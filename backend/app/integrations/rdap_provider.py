"""
RDAP (Registration Data Access Protocol) Client
Queries ICANN RDAP endpoints to discover domain creation dates, registrars, and domain age.
"""
import time
from datetime import datetime
import httpx
from typing import Dict, Any, Optional

async def query_rdap(domain: str) -> Dict[str, Any]:
    """Queries ICANN public RDAP service for authoritative registration data."""
    start_t = time.time()
    url = f"https://rdap.org/domain/{domain.strip().lower()}"
    
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.get(url, headers={"Accept": "application/rdap+json"})
            latency = round((time.time() - start_t) * 1000, 1)
            
            if resp.status_code == 200:
                data = resp.json()
                
                # Extract events (registration, expiration, last changed)
                events = data.get("events", [])
                created_date = None
                expires_date = None
                
                for ev in events:
                    action = ev.get("eventAction", "").lower()
                    date_str = ev.get("eventDate", "")
                    if action in ("registration", "created"):
                        created_date = date_str
                    elif action in ("expiration", "expired"):
                        expires_date = date_str
                
                # Calculate domain age in days if created_date is available
                age_days = None
                if created_date:
                    try:
                        clean_date = created_date.split("T")[0]
                        dt = datetime.strptime(clean_date, "%Y-%m-%d")
                        age_days = (datetime.utcnow() - dt).days
                    except Exception:
                        pass
                        
                # Extract registrar
                registrar = "Unknown / Privacy Protected"
                entities = data.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    if "registrar" in roles:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break
                                    
                return {
                    "status": "success",
                    "available": True,
                    "domain": domain,
                    "created_date": created_date,
                    "expires_date": expires_date,
                    "domain_age_days": age_days,
                    "is_young_domain": age_days is not None and age_days < 90,
                    "registrar": registrar,
                    "privacy_protected": True if "privacy" in str(data).lower() or "withheld" in str(data).lower() else False,
                    "latency_ms": latency
                }
            elif resp.status_code == 404:
                return {
                    "status": "not_found",
                    "available": False,
                    "domain": domain,
                    "message": "Domain not registered or RDAP data unavailable in registry",
                    "latency_ms": latency
                }
            else:
                return {
                    "status": "error",
                    "available": False,
                    "domain": domain,
                    "message": f"RDAP service returned HTTP {resp.status_code}",
                    "latency_ms": latency
                }
    except Exception as e:
        return {
            "status": "unavailable",
            "available": False,
            "domain": domain,
            "message": f"RDAP lookup failed: {str(e)}",
            "latency_ms": round((time.time() - start_t) * 1000, 1)
        }
