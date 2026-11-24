"""
Investigation Intelligence Graph Schema
Supports interactive node-link relationships linking Domain, Subdomain, IP, Certificate,
Email Domain, Organization, URLs, Threat Indicators, and Evidence Sources.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str  # domain, subdomain, ip, certificate, email_domain, organization, url, indicator, provider
    risk_level: str = "neutral" # neutral, safe, suspicious, malicious
    details: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    source: str
    target: str
    label: str
    relationship_type: str # direct, inferred, corroborates, resolves_to, issued_to, impersonates
    is_inferred: bool = False
    weight: float = 1.0

class IntelligenceGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
