"""
Base Threat Intelligence Provider Abstract Class
Ensures consistent interface, rate-limit tolerance, timeout isolation,
and standardized attribution reporting.
"""
from abc import ABC, abstractmethod
import time
from typing import Optional
from app.schemas.threat_intel import ThreatIntelResult, ProviderStatus

class BaseThreatProvider(ABC):
    def __init__(self, name: str, source_reference: str):
        self.name = name
        self.source_reference = source_reference

    @abstractmethod
    async def query_target(self, target: str, query_type: str = "url") -> ThreatIntelResult:
        """Query the intelligence provider for a target URL, domain, or IP."""
        pass

    def build_result(
        self,
        target: str,
        query_type: str,
        status: ProviderStatus,
        match: bool = False,
        findings: Optional[list] = None,
        confidence: Optional[float] = None,
        latency_ms: Optional[float] = None,
        error_message: Optional[str] = None,
        raw_summary: Optional[dict] = None
    ) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider_name=self.name,
            provider_status=status,
            query_type=query_type,
            target=target,
            match_status=match,
            findings=findings or [],
            confidence=confidence,
            source_reference=self.source_reference,
            latency_ms=latency_ms,
            error_message=error_message,
            raw_summary=raw_summary
        )
