"""
Engine Results and Detection Schemas
Encapsulates outputs from the 16 independent detection engines.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum

class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EvidenceItem(BaseModel):
    id: str
    engine_name: str
    severity: SeverityLevel
    title: str
    description: str
    raw_indicator: Optional[str] = None
    confidence: float = 0.8  # 0.0 - 1.0
    source_layer: str  # url, dns, tls, content, identity, linguistic, reputation
    category: str  # phishing, malware, advance_fee, impersonation, structural_anomaly

class EngineExecutionResult(BaseModel):
    engine_name: str
    executed: bool = True
    execution_time_ms: float = 0.0
    status: str = "success"  # success, partial, failed, skipped
    summary: str
    risk_contribution: float = 0.0 # 0.0 - 100.0
    findings: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
