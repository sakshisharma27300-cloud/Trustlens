"""
URLhaus Threat Intelligence Provider (Abuse.ch)
Performs real-time lookups against abuse.ch URLhaus malware and phishing repository.
Requires no API key for standard operational queries.
"""
import time
import httpx
from app.integrations.base_provider import BaseThreatProvider
from app.schemas.threat_intel import ThreatIntelResult, ProviderStatus

class URLhausProvider(BaseThreatProvider):
    def __init__(self):
        super().__init__(
            name="URLhaus (Abuse.ch)",
            source_reference="https://urlhaus.abuse.ch/api/"
        )

    async def query_target(self, target: str, query_type: str = "url") -> ThreatIntelResult:
        start_t = time.time()
        try:
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/" if query_type == "url" else "https://urlhaus-api.abuse.ch/v1/host/"
            data = {"url": target} if query_type == "url" else {"host": target}
            
            async with httpx.AsyncClient(timeout=4.5) as client:
                res = await client.post(endpoint, data=data)
                latency = round((time.time() - start_t) * 1000, 1)
                
                if res.status_code == 200:
                    json_data = res.json()
                    query_status = json_data.get("query_status")
                    
                    if query_status in ("ok", "found"):
                        tags = json_data.get("tags") or []
                        threat_type = json_data.get("threat") or "malware_url"
                        status_str = json_data.get("url_status", "active")
                        findings = [
                            f"Listed on URLhaus database as: {threat_type} (Status: {status_str})",
                            f"Threat tags: {', '.join(tags) if tags else 'none'}",
                            f"Reporter: {json_data.get('reporter', 'community')}"
                        ]
                        return self.build_result(
                            target=target,
                            query_type=query_type,
                            status=ProviderStatus.MALICIOUS,
                            match=True,
                            findings=findings,
                            confidence=0.95,
                            latency_ms=latency,
                            raw_summary={"threat": threat_type, "tags": tags, "status": status_str}
                        )
                    elif query_status == "no_results":
                        return self.build_result(
                            target=target,
                            query_type=query_type,
                            status=ProviderStatus.NO_MATCH,
                            match=False,
                            findings=["No malicious entries found on URLhaus repository."],
                            latency_ms=latency
                        )
                    else:
                        return self.build_result(
                            target=target,
                            query_type=query_type,
                            status=ProviderStatus.NO_MATCH,
                            match=False,
                            findings=[f"URLhaus status: {query_status}"],
                            latency_ms=latency
                        )
                else:
                    return self.build_result(
                        target=target,
                        query_type=query_type,
                        status=ProviderStatus.UNAVAILABLE,
                        error_message=f"HTTP Error {res.status_code}",
                        latency_ms=latency
                    )
        except httpx.TimeoutException:
            return self.build_result(
                target=target,
                query_type=query_type,
                status=ProviderStatus.UNAVAILABLE,
                error_message="Connection timed out while contacting URLhaus API",
                latency_ms=round((time.time() - start_t) * 1000, 1)
            )
        except Exception as e:
            return self.build_result(
                target=target,
                query_type=query_type,
                status=ProviderStatus.UNAVAILABLE,
                error_message=f"URLhaus query error: {str(e)}",
                latency_ms=round((time.time() - start_t) * 1000, 1)
            )
