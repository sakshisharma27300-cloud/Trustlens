"""
Investigation Intelligence Graph Builder & Counterfactual Simulation Engine
Constructs multi-node correlation networks and simulates 'What would change the verdict?'
"""
from typing import List, Dict, Any, Tuple
from app.schemas.graph import IntelligenceGraph, GraphNode, GraphEdge
from app.schemas.engines import EvidenceItem, SeverityLevel
from app.schemas.threat_intel import ThreatIntelResult, ProviderStatus
from app.schemas.investigation import VerdictCategory, CounterfactualVerdictResult

def build_intelligence_graph(
    entity: str,
    investigation_type: str,
    domain: str,
    dns_profile: Dict[str, Any],
    cert_data: Dict[str, Any],
    evidence: List[EvidenceItem],
    providers: List[ThreatIntelResult]
) -> IntelligenceGraph:
    """Builds node-link relationship graph connecting all inspected digital artifacts."""
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    node_ids = set()

    def add_node(nid: str, label: str, ntype: str, risk: str = "neutral", details: dict = None):
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append(GraphNode(id=nid, label=label, node_type=ntype, risk_level=risk, details=details or {}))

    def add_edge(src: str, tgt: str, label: str, rel: str = "direct", inferred: bool = False):
        if src in node_ids and tgt in node_ids:
            edges.append(GraphEdge(source=src, target=tgt, label=label, relationship_type=rel, is_inferred=inferred))

    # Root Entity Node
    root_risk = "suspicious" if any(e.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL) for e in evidence) else "neutral"
    add_node("root_target", entity[:35], investigation_type, root_risk, {"full_entity": entity})

    # Domain Node
    if domain:
        add_node(f"dom_{domain}", domain, "domain", "neutral")
        add_edge("root_target", f"dom_{domain}", "belongs to domain")

    # IP Nodes from DNS
    ips = dns_profile.get("records", {}).get("A", [])
    for idx, ip in enumerate(ips[:4]):
        ip_id = f"ip_{ip.replace('.', '_')}"
        add_node(ip_id, ip, "ip", "neutral", {"record": "A"})
        add_edge(f"dom_{domain}", ip_id, "resolves to", "resolves_to")

    # TLS / Certificate Node
    if cert_data.get("is_valid_https"):
        issuer = cert_data.get("issuer", "TLS CA")
        cert_id = f"cert_{abs(hash(issuer)) % 10000}"
        add_node(cert_id, f"TLS: {issuer[:20]}", "certificate", "neutral", cert_data)
        add_edge(f"dom_{domain}", cert_id, "secures", "issued_to")

    # Threat Intelligence Providers & Matches
    for p in providers:
        if p.provider_status in (ProviderStatus.MALICIOUS, ProviderStatus.SUSPICIOUS):
            p_id = f"prov_{p.provider_name.replace(' ', '_').lower()}"
            add_node(p_id, p.provider_name, "provider", "malicious", {"status": p.provider_status})
            add_edge(p_id, "root_target", "flags as malicious", "corroborates")

    # Key Evidence / Anomaly Nodes
    for idx, ev in enumerate(evidence[:6]):
        ev_id = f"ev_{ev.id}_{idx}"
        ev_risk = "malicious" if ev.severity == SeverityLevel.CRITICAL else "suspicious"
        add_node(ev_id, ev.title[:25], "indicator", ev_risk, {"description": ev.description})
        add_edge("root_target", ev_id, "exhibits", "direct")

    return IntelligenceGraph(nodes=nodes, edges=edges)

def simulate_counterfactual_verdict(
    original_risk_score: float,
    original_verdict: VerdictCategory,
    modified_parameters: Dict[str, Any]
) -> CounterfactualVerdictResult:
    """
    Evaluates 'What would change the verdict?':
    Simulates impact of modifying observed parameters (e.g., domain age, recruiter email alignment, payment removal).
    """
    simulated_score = original_risk_score
    divergent_factors = []
    
    # Factor 1: Domain Age
    if modified_parameters.get("domain_age_years", 0) >= 3:
        simulated_score = max(0.0, simulated_score - 35.0)
        divergent_factors.append("Domain established for > 3 years (removes new registration penalty: -35 pts)")
        
    # Factor 2: Recruiter email domain matching official domain
    if modified_parameters.get("recruiter_domain_matched", False):
        simulated_score = max(0.0, simulated_score - 40.0)
        divergent_factors.append("Recruiter uses official enterprise email rather than free webmail (-40 pts)")

    # Factor 3: Payment demand removed
    if modified_parameters.get("remove_payment_demand", False):
        simulated_score = max(0.0, simulated_score - 50.0)
        divergent_factors.append("Upfront employment fee demand eliminated (-50 pts)")

    # Factor 4: Listed on Threat Intelligence Feed
    if modified_parameters.get("simulate_reputation_hit", False):
        simulated_score = min(100.0, simulated_score + 60.0)
        divergent_factors.append("Corroborated hit on global malware/phishing repository (+60 pts)")

    # Factor 5: Valid EV Certificate
    if modified_parameters.get("has_ev_cert", False):
        simulated_score = max(0.0, simulated_score - 15.0)
        divergent_factors.append("Organization-Validated (OV/EV) certificate established (-15 pts)")

    simulated_score = round(simulated_score, 1)
    
    # Determine simulated verdict
    if simulated_score >= 85.0:
        sim_verdict = VerdictCategory.CRITICAL_RISK
    elif simulated_score >= 60.0:
        sim_verdict = VerdictCategory.HIGH_RISK
    elif simulated_score >= 35.0:
        sim_verdict = VerdictCategory.MODERATE_RISK
    elif simulated_score > 15.0:
        sim_verdict = VerdictCategory.LOW_RISK
    else:
        sim_verdict = VerdictCategory.MINIMAL_RISK

    delta = simulated_score - original_risk_score
    orig_v_str = original_verdict.value if hasattr(original_verdict, "value") else str(original_verdict)
    sim_v_str = sim_verdict.value if hasattr(sim_verdict, "value") else str(sim_verdict)
    explanation = f"Simulated parameters altered risk score by {delta:+.1f} points (from {original_risk_score} to {simulated_score}), shifting verdict from '{orig_v_str}' to '{sim_v_str}'."

    return CounterfactualVerdictResult(
        original_risk_score=original_risk_score,
        simulated_risk_score=simulated_score,
        original_verdict=orig_v_str,
        simulated_verdict=sim_v_str,
        delta_explanation=explanation,
        divergent_factors=divergent_factors
    )
