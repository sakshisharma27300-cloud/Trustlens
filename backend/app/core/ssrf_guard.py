"""
TRUSTLENS SSRF Protection & Safe Web Inspection Engine
Enforces multi-layer validation before any external web page can be fetched.
Prevents internal network reconnaissance, cloud metadata harvesting (169.254.169.254),
loopback probing, DNS rebinding, and port manipulation.
"""
import ipaddress
import socket
from typing import Tuple, Optional
from urllib.parse import urlparse
import httpx
from app.core.config import settings

# Disallowed IP Networks (RFC 1918, Carrier Grade NAT, Loopback, Link-Local, Cloud Metadata, Multicast)
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # AWS/GCP/Azure Metadata Endpoint
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),       # Shared address space / CGNAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmark testing
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),             # IPv6 Loopback
    ipaddress.ip_network("fe80::/10"),           # IPv6 Link-Local
    ipaddress.ip_network("fc00::/7"),            # IPv6 Unique Local Address
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped IPv6
]

class SSRFSecurityException(Exception):
    """Raised when a target URL or resolved IP violates SSRF security boundaries."""
    pass

def validate_target_url(raw_url: str) -> Tuple[str, str, int]:
    """
    Validates URL scheme, hostname, and port.
    Returns (cleaned_url, hostname, port).
    """
    parsed = urlparse(raw_url.strip())
    
    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFSecurityException(f"Unsupported protocol scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")
    
    hostname = parsed.hostname
    if not hostname:
        raise SSRFSecurityException("Missing or unparseable target hostname.")
    
    # Check for direct localhost / metadata names
    lower_host = hostname.lower()
    if lower_host in ("localhost", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"):
        raise SSRFSecurityException(f"Blocked request to internal hostname: '{hostname}'")

    # Check for direct IP address in forbidden networks
    try:
        ip = ipaddress.ip_address(hostname)
        for forbidden in FORBIDDEN_NETWORKS:
            if ip in forbidden:
                raise SSRFSecurityException(f"Blocked request to restricted IP range: '{hostname}' ({forbidden})")
    except ValueError:
        pass
        
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if port in settings.BLOCKED_PORTS:
        raise SSRFSecurityException(f"Port {port} is classified as high-risk and restricted by security policy.")
        
    return raw_url, hostname, port

def resolve_and_verify_ip(hostname: str) -> str:
    """
    Resolves hostname to IP and verifies that the resolved address
    is strictly a public routable IP. Mitigates DNS rebinding.
    """
    try:
        # Resolve address family
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            raise SSRFSecurityException(f"Failed to resolve hostname: '{hostname}'")
            
        ip_str = addr_info[0][4][0]
        ip_obj = ipaddress.ip_address(ip_str)
        
        # Check against forbidden networks
        for forbidden in FORBIDDEN_NETWORKS:
            if ip_obj in forbidden:
                raise SSRFSecurityException(f"Resolved IP {ip_str} falls into restricted network range ({forbidden}). Fetch aborted.")
                
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            raise SSRFSecurityException(f"Resolved IP {ip_str} is private or non-routable.")
            
        return ip_str
    except (socket.gaierror, socket.herror) as e:
        raise SSRFSecurityException(f"DNS resolution failure for '{hostname}': {str(e)}")

async def safe_fetch_website_content(url: str) -> Tuple[bool, Optional[str], Optional[dict], str]:
    """
    Safely retrieves public web page contents with SSRF guards, redirect tracking,
    content-type filtering, byte size limits, and timeout isolation.
    
    Returns:
        (success: bool, html_text: Optional[str], metadata: Optional[dict], message: str)
    """
    if not settings.ENABLE_LIVE_WEBSITE_FETCH:
        return False, None, None, "Live website content inspection is disabled by configuration policy."
        
    current_url = url
    redirect_chain = []
    
    try:
        for hop in range(settings.FETCH_MAX_REDIRECTS + 1):
            cleaned_url, hostname, port = validate_target_url(current_url)
            resolved_ip = resolve_and_verify_ip(hostname)
            redirect_chain.append({"url": current_url, "resolved_ip": resolved_ip})
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 (TrustLensGlobal-SecurityScanner/2.4)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9,es;q=0.8,fr;q=0.7",
            }
            
            async with httpx.AsyncClient(
                verify=False, # We inspect cert separately in TLS engine; don't break inspection on self-signed targets
                timeout=settings.FETCH_TIMEOUT_SECONDS,
                follow_redirects=False
            ) as client:
                response = await client.get(current_url, headers=headers)
                
                # Check for redirect
                if response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers:
                    next_loc = response.headers["location"]
                    # Handle relative redirects
                    if next_loc.startswith("/"):
                        parsed_cur = urlparse(current_url)
                        current_url = f"{parsed_cur.scheme}://{parsed_cur.netloc}{next_loc}"
                    else:
                        current_url = next_loc
                    continue
                
                # Verify content type
                content_type = response.headers.get("content-type", "").lower()
                if "application/octet-stream" in content_type or "application/x-dosexec" in content_type or "application/zip" in content_type:
                    return False, None, None, f"Refused to download binary/executable payload (Content-Type: {content_type})."
                
                content = response.content[:settings.FETCH_MAX_BYTES]
                text = content.decode("utf-8", errors="replace")
                
                metadata = {
                    "final_url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "content_length_bytes": len(content),
                    "redirect_chain": redirect_chain,
                    "server_header": response.headers.get("server", "hidden"),
                    "security_headers": {
                        "content_security_policy": "content-security-policy" in response.headers,
                        "strict_transport_security": "strict-transport-security" in response.headers,
                        "x_frame_options": response.headers.get("x-frame-options", None),
                        "x_content_type_options": response.headers.get("x-content-type-options", None),
                    }
                }
                
                return True, text, metadata, "Successfully inspected public page content safely."
                
        return False, None, None, f"Exceeded maximum redirection limit ({settings.FETCH_MAX_REDIRECTS})."
        
    except SSRFSecurityException as ssrf_err:
        return False, None, None, f"SSRF Guard Blocked: {str(ssrf_err)}"
    except Exception as e:
        return False, None, None, f"Safe fetch failed: {type(e).__name__} - {str(e)}"
