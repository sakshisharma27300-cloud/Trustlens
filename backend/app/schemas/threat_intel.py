"""
Threat Intelligence Provider Schemas
Normalizes outputs from all external threat feeds and API clients.
"""
from typing import Optional, Any, Dict, List
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class ProviderStatus(str, Enum):
    MALICIOUS = "Confirmed malicious indicator"
    SUSPICIOUS = "Suspicious indicator"
    NO_MATCH = "No match found"
    NOT_CHECKED = "Not checked"
    UNAVAILABLE = "Provider unavailable"
    RATE_LIMITED = "Rate limited"
    AUTH_REQUIRED = "Authentication required"

class ThreatIntelResult(BaseModel):
    provider_name: str
    provider_status: ProviderStatus
    query_timestamp: datetime = Field(default_factory=datetime.utcnow)
    query_type: str  # url, domain, ip, hash
    target: str
    match_status: bool = False
    findings: List[str] = Field(default_factory=list)
    confidence: Optional[float] = None # 0.0 - 1.0
    source_reference: Optional[str] = None
    latency_ms: Optional[float] = None
    raw_summary: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
