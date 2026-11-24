"""
Certificate Transparency (crt.sh) Provider
Inspects public CT logs to detect historical certificate issuance, lookalike SANs,
and issuance dates.
"""
import time
import httpx
from typing import Dict, Any, List

async def query_crt_sh(domain: str) -> Dict[str, Any]:
    """Queries crt.sh certificate transparency logs for a domain."""
    start_t = time.time()
    url = f"https://crt.sh/?q={domain.strip().lower()}&output=json"
    
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url)
            latency = round((time.time() - start_t) * 1000, 1)
            
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    issuers = set()
                    common_names = set()
                    first_seen = None
                    
                    # Sort certificates by entry date if possible
                    for cert in data[:15]: # Take top 15
                        issuer = cert.get("issuer_name", "")
                        if "O=" in issuer:
                            # Extract Organization
                            parts = [p for p in issuer.split(",") if "O=" in p]
                            if parts:
                                issuers.add(parts[0].replace("O=", "").strip())
                        common_names.add(cert.get("common_name", ""))
                        
                    first_seen = data[-1].get("entry_timestamp", None)
                    latest_seen = data[0].get("entry_timestamp", None)
                    
                    return {
                        "available": True,
                        "total_certificates_found": len(data),
                        "issuers": list(issuers)[:5],
                        "first_seen": first_seen,
                        "latest_seen": latest_seen,
                        "sample_sans": list(common_names)[:8],
                        "latency_ms": latency
                    }
                else:
                    return {
                        "available": True,
                        "total_certificates_found": 0,
                        "message": "No certificate transparency logs found for this domain",
                        "latency_ms": latency
                    }
            else:
                return {
                    "available": False,
                    "message": f"CT log query returned HTTP {resp.status_code}",
                    "latency_ms": latency
                }
    except Exception as e:
        return {
            "available": False,
            "message": f"Certificate transparency service error: {str(e)}",
            "latency_ms": round((time.time() - start_t) * 1000, 1)
        }
