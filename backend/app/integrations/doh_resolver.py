"""
DNS-over-HTTPS (DoH) Live Resolver
Queries Cloudflare and Google DoH endpoints for A, AAAA, MX, NS, and TXT records.
Bypasses local port 53 blocking and corporate firewall DNS tampering.
"""
import time
import httpx
from typing import Dict, List, Any
from app.core.config import settings

RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28
}

async def query_doh_record(domain: str, record_type: str = "A") -> List[str]:
    """Queries Cloudflare DoH (with Google DoH fallback) for a specific record type."""
    headers = {"Accept": "application/dns-json"}
    
    # Try Cloudflare DoH first
    try:
        async with httpx.AsyncClient(timeout=3.5) as client:
            resp = await client.get(
                settings.CLOUDFLARE_DOH_URL,
                params={"name": domain, "type": record_type},
                headers=headers
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                return [ans["data"] for ans in answers if "data" in ans]
    except Exception:
        pass

    # Fallback to Google DoH
    try:
        async with httpx.AsyncClient(timeout=3.5) as client:
            resp = await client.get(
                settings.GOOGLE_DOH_URL,
                params={"name": domain, "type": record_type},
                headers=headers
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                return [ans["data"] for ans in answers if "data" in ans]
    except Exception:
        pass

    return []

async def get_full_dns_profile(domain: str) -> Dict[str, Any]:
    """Gathers complete DNS intelligence for a domain."""
    start_t = time.time()
    
    # Parallel gather simulated or sequential clean execution
    a_records = await query_doh_record(domain, "A")
    aaaa_records = await query_doh_record(domain, "AAAA")
    mx_records = await query_doh_record(domain, "MX")
    ns_records = await query_doh_record(domain, "NS")
    txt_records = await query_doh_record(domain, "TXT")
    cname_records = await query_doh_record(domain, "CNAME")
    
    elapsed = round((time.time() - start_t) * 1000, 1)
    
    has_records = bool(a_records or aaaa_records or mx_records or ns_records or txt_records)
    
    return {
        "domain": domain,
        "resolved": has_records,
        "latency_ms": elapsed,
        "records": {
            "A": a_records,
            "AAAA": aaaa_records,
            "MX": mx_records,
            "NS": ns_records,
            "TXT": txt_records,
            "CNAME": cname_records
        },
        "flags": {
            "has_mx": len(mx_records) > 0,
            "has_spf": any("v=spf1" in txt.lower() for txt in txt_records),
            "has_dmarc_indicator": any("v=dmarc" in txt.lower() for txt in txt_records),
            "ip_count": len(a_records) + len(aaaa_records)
        }
    }
