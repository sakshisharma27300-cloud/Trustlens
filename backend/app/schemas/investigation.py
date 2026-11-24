"""
Core Investigation Schemas & Contracts
Covers Website, URL, Email, Message, and Job/Recruitment verification pipelines.
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from app.schemas.threat_intel import ThreatIntelResult
from app.schemas.engines import EngineExecutionResult, EvidenceItem
from app.schemas.graph import IntelligenceGraph

class InvestigationType(str, Enum):
    WEBSITE = "website"
    URL = "url"
    EMAIL = "email"
    MESSAGE = "message"
    JOB_OFFER = "job_offer"

class VerdictCategory(str, Enum):
    MINIMAL_RISK = "No Significant Risk Detected"
    LOW_RISK = "Low Risk"
    MODERATE_RISK = "Suspicious"
    HIGH_RISK = "High Risk / Likely Malicious"
    CRITICAL_RISK = "Confirmed Malicious"
    INCONCLUSIVE = "Inconclusive / Insufficient Information"

# Input Schemas
class WebsiteInvestigateRequest(BaseModel):
    url: str
    deep_inspection: bool = True
    context: Optional[str] = None

class URLInvestigateRequest(BaseModel):
    url: str
    check_redirects: bool = True

class EmailInvestigateRequest(BaseModel):
    email_address: Optional[str] = None
    sender_name: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    raw_headers: Optional[str] = None
    attachment_metadata: Optional[List[Dict[str, Any]]] = None

class MessageInvestigateRequest(BaseModel):
    content: str
    channel: str = "general" # whatsapp, sms, telegram, linkedin, email, instagram
    language_hint: Optional[str] = None

class JobOfferInvestigateRequest(BaseModel):
    company_name: str
    recruiter_name: Optional[str] = None
    recruiter_email: Optional[str] = None
    job_title: Optional[str] = None
    website_url: Optional[str] = None
    offer_text: Optional[str] = None
    payment_requested: Optional[bool] = False
    payment_amount: Optional[str] = None
    interview_platform: Optional[str] = None

# Counterfactual Scenario Exploration
class CounterfactualQuery(BaseModel):
    investigation_id: str
    modified_parameters: Dict[str, Any]

class CounterfactualVerdictResult(BaseModel):
    original_risk_score: float
    simulated_risk_score: float
    original_verdict: VerdictCategory
    simulated_verdict: VerdictCategory
    delta_explanation: str
    divergent_factors: List[str]

# Full 22-Section Investigation Report Schema
class InvestigationReport(BaseModel):
    investigation_id: str
    submitted_entity: str
    investigation_type: InvestigationType
    overall_verdict: VerdictCategory
    
    # Independent Tri-Axis Metrics
    risk_score: float = Field(ge=0.0, le=100.0, description="0-100 estimate based on observed malicious/suspicious indicators")
    assessment_confidence: float = Field(ge=0.0, le=100.0, description="Confidence in the interpretation of available evidence")
    analysis_coverage: float = Field(ge=0.0, le=100.0, description="Proportion of applicable intelligence checks successfully completed")
    
    # 22 Mandated Report Sections
    executive_summary: str
    detection_engine_results: List[EngineExecutionResult] = Field(default_factory=list)
    threat_intelligence_sources: List[ThreatIntelResult] = Field(default_factory=list)
    domain_information: Dict[str, Any] = Field(default_factory=dict)
    technical_indicators: Dict[str, Any] = Field(default_factory=dict)
    website_identity_findings: Dict[str, Any] = Field(default_factory=dict)
    email_authentication_findings: Optional[Dict[str, Any]] = None
    evidence_excerpts: List[EvidenceItem] = Field(default_factory=list)
    correlated_findings: List[str] = Field(default_factory=list)
    contradictory_signals: List[str] = Field(default_factory=list)
    safe_or_reassuring_observations: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    recommended_action_plan: List[str] = Field(default_factory=list)
    investigation_timestamp: datetime = Field(default_factory=datetime.utcnow)
    algorithm_version: str = "TRUSTLENS-CORE-2.4.0"
    
    # Major Innovation Features
    intelligence_graph: IntelligenceGraph = Field(default_factory=IntelligenceGraph)
    counterfactual_insights: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
