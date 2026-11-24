"""
Engines 12, 13, 14, 15, 16:
- Engine 12: Threat Reputation Engine
- Engine 13: Evidence Extraction Engine
- Engine 14: Cross-Layer Threat Correlation Engine
- Engine 15: Advanced Risk Fusion Engine
- Engine 16: Actionable Recommendation Engine
"""
import time
from typing import List, Dict, Any, Tuple
from app.schemas.engines import EngineExecutionResult, EvidenceItem, SeverityLevel
from app.schemas.threat_intel import ThreatIntelResult, ProviderStatus
from app.schemas.investigation import VerdictCategory

class ThreatReputationEngine:
    name = "Threat Reputation Engine"

    def run(self, provider_results: List[ThreatIntelResult]) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        malicious_hits = 0
        suspicious_hits = 0
        total_checked = 0
        
        for prov in provider_results:
            if prov.provider_status in (ProviderStatus.MALICIOUS, ProviderStatus.SUSPICIOUS, ProviderStatus.NO_MATCH):
                total_checked += 1
                
            if prov.provider_status == ProviderStatus.MALICIOUS:
                malicious_hits += 1
                risk += 65.0
                findings.append(f"Confirmed match on {prov.provider_name}: {', '.join(prov.findings)}")
                evidence.append(EvidenceItem(
                    id=f"REP-{prov.provider_name[:4].upper()}-01",
                    engine_name=self.name,
                    severity=SeverityLevel.CRITICAL,
                    title=f"Flagged by {prov.provider_name}",
                    description=f"Entity listed as malicious by reputable security provider {prov.provider_name}.",
                    raw_indicator=prov.target,
                    confidence=prov.confidence or 0.95,
                    source_layer="reputation",
                    category="phishing"
                ))
            elif prov.provider_status == ProviderStatus.SUSPICIOUS:
                suspicious_hits += 1
                risk += 35.0
                findings.append(f"Suspicious flag on {prov.provider_name}: {', '.join(prov.findings)}")
            elif prov.provider_status == ProviderStatus.AUTH_REQUIRED:
                findings.append(f"{prov.provider_name}: Degraded (API key unconfigured).")
            elif prov.provider_status == ProviderStatus.UNAVAILABLE:
                findings.append(f"{prov.provider_name}: Unavailable ({prov.error_message or 'timeout'}).")

        if malicious_hits == 0 and suspicious_hits == 0:
            findings.append("No active malicious indicators found in checked global threat feeds. Note: Zero database hits does NOT certify target as safe.")

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Synthesized {len(provider_results)} threat feeds. Malicious: {malicious_hits}, Suspicious: {suspicious_hits}, Checked: {total_checked}",
            risk_contribution=min(risk, 95.0),
            findings=findings,
            evidence=evidence,
            metadata={"malicious_hits": malicious_hits, "suspicious_hits": suspicious_hits}
        )

class EvidenceExtractionEngine:
    name = "Evidence Extraction Engine"

    def run(self, all_engine_results: List[EngineExecutionResult]) -> List[EvidenceItem]:
        """Collects, deduplicates, and ranks evidence by severity and confidence."""
        aggregated: List[EvidenceItem] = []
        seen_keys = set()
        
        for eng in all_engine_results:
            for item in eng.evidence:
                key = f"{item.source_layer}_{item.title}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    aggregated.append(item)
                    
        # Sort evidence: CRITICAL > HIGH > MEDIUM > LOW > INFO
        order = {SeverityLevel.CRITICAL: 0, SeverityLevel.HIGH: 1, SeverityLevel.MEDIUM: 2, SeverityLevel.LOW: 3, SeverityLevel.INFO: 4}
        aggregated.sort(key=lambda x: (order.get(x.severity, 5), -x.confidence))
        return aggregated

class CorrelationEngine:
    name = "Cross-Layer Correlation Engine"

    def run(self, evidence: List[EvidenceItem], metadata_pool: Dict[str, Any]) -> List[str]:
        """
        Cross-correlates disparate layer signals to reconstruct end-to-end threat campaign narratives.
        Avoids double-counting while connecting technical indicators with fraud patterns.
        """
        narratives = []
        categories = {e.category for e in evidence}
        layers = {e.source_layer for e in evidence}
        
        # Narrative 1: Brand Impersonation on Ephemeral Infrastructure
        has_brand = any(e.source_layer == "identity" and "Brand" in e.title for e in evidence)
        has_young_reg = any("Young" in e.title or "Age" in e.description for e in evidence)
        has_credential_form = any("Credential" in e.title or "Password" in e.description for e in evidence)
        
        if has_brand and has_young_reg:
            narratives.append("Campaign Pattern Identified: Targeted Brand Spoofing via Ephemeral Infrastructure. Newly registered domain mimicing a protected corporate identity.")
            
        if has_brand and has_credential_form:
            narratives.append("Credential Harvesting Attack Pattern: Unauthorized login/password portal branded under a trusted trademark.")

        # Narrative 2: Advance-Fee Recruitment Impersonation
        has_rec_pay = any("Employment Fee" in e.title or "advance_fee" in e.category for e in evidence)
        has_free_email = any("Free Webmail" in e.title for e in evidence)
        if has_rec_pay and has_free_email:
            narratives.append("Coordinated Advance-Fee Recruitment Scam: Impersonation of hiring entity coupled with upfront financial demands via unverified webmail communications.")

        # Narrative 3: Digital Arrest Extortion Chain
        has_dig_arrest = any("Digital Arrest" in e.title for e in evidence)
        if has_dig_arrest:
            narratives.append("Law Enforcement Video-Extortion / Digital Arrest Scheme: Fabricated criminal allegations paired with forced isolation to extract emergency wire transfers.")

        # Narrative 4: Malicious Threat Feed Corroboration
        has_rep = any(e.source_layer == "reputation" for e in evidence)
        if has_rep and (has_brand or has_credential_form or has_young_reg):
            narratives.append("Multi-Source Corroboration: Independent threat repository listings corroborate locally discovered structural and identity anomalies.")

        if not narratives and evidence:
            narratives.append("Isolated suspicious indicators observed across independent layers without unified multi-stage campaign signatures.")
        elif not narratives:
            narratives.append("No correlated cross-layer attack chains observed.")

        return narratives

class RiskFusionEngine:
    name = "Risk Fusion Engine"

    def run(
        self,
        engine_results: List[EngineExecutionResult],
        provider_results: List[ThreatIntelResult],
        evidence: List[EvidenceItem],
        investigation_type: str
    ) -> Tuple[float, float, float, VerdictCategory, str, List[str], List[str], List[str]]:
        """
        Calculates 3 independent orthogonal dimensions:
        1. Risk Score (0 - 100): Weighted severity of confirmed risk indicators.
        2. Assessment Confidence (0 - 100%): Confidence in interpretation given evidence density.
        3. Analysis Coverage (0 - 100%): Proportion of applicable engines successfully executed.
        
        CRITICAL RULE: Absence of threat intelligence match MUST NEVER yield a 'Safe' verdict.
        """
        # 1. Coverage Calculation
        executed_count = sum(1 for e in engine_results if e.executed and e.status in ("success", "partial"))
        total_engines = max(len(engine_results), 1)
        coverage = round((executed_count / total_engines) * 100.0, 1)

        # 2. Risk Score Synthesis with non-linear saturation
        max_engine_risk = max((e.risk_contribution for e in engine_results), default=0.0)
        reputation_malicious = any(p.provider_status == ProviderStatus.MALICIOUS for p in provider_results)
        
        # Base accumulator
        critical_count = sum(1 for ev in evidence if ev.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for ev in evidence if ev.severity == SeverityLevel.HIGH)
        medium_count = sum(1 for ev in evidence if ev.severity == SeverityLevel.MEDIUM)
        
        score = 0.0
        if reputation_malicious:
            score = max(80.0, max_engine_risk)
        else:
            score = max_engine_risk * 0.6 + (critical_count * 30.0) + (high_count * 15.0) + (medium_count * 8.0)
            
        score = min(max(round(score, 1), 0.0), 99.0) if not reputation_malicious else min(max(round(score, 1), 85.0), 100.0)

        # 3. Assessment Confidence
        confidence_base = 50.0
        if coverage > 75:
            confidence_base += 20.0
        if len(evidence) >= 2:
            confidence_base += 15.0
        if reputation_malicious:
            confidence_base += 15.0
        confidence = min(round(confidence_base, 1), 98.0)

        # 4. Truthful Verdict Categorization
        missing_info = []
        contradictory = []
        reassuring = []
        
        # Identify missing or degraded checks
        for p in provider_results:
            if p.provider_status == ProviderStatus.AUTH_REQUIRED:
                missing_info.append(f"Live telemetry from {p.provider_name} unavailable (API key required).")
            elif p.provider_status == ProviderStatus.UNAVAILABLE:
                missing_info.append(f"{p.provider_name} service timed out or was unreachable.")

        if score >= 85.0:
            verdict = VerdictCategory.CRITICAL_RISK
            exec_summary = f"CRITICAL THREAT: Entity exhibits verified malicious indicators ({critical_count} critical, {high_count} high-severity findings). High probability of active fraud or credential theft."
        elif score >= 60.0:
            verdict = VerdictCategory.HIGH_RISK
            exec_summary = f"HIGH RISK: Significant fraudulent, deceptive, or structural anomalies identified across multiple analytical layers."
        elif score >= 35.0:
            verdict = VerdictCategory.MODERATE_RISK
            exec_summary = f"SUSPICIOUS: Moderate irregularities observed. Caution is advised as entity displays atypical or impersonation characteristics."
        elif score > 15.0:
            verdict = VerdictCategory.LOW_RISK
            exec_summary = f"LOW RISK DETECTED: Minor technical notes observed. Standard operational caution recommended."
        else:
            if coverage < 50.0:
                verdict = VerdictCategory.INCONCLUSIVE
                exec_summary = "INCONCLUSIVE: Insufficient telemetry gathered to formulate an evidence-backed security determination."
            else:
                verdict = VerdictCategory.MINIMAL_RISK
                exec_summary = "NO SIGNIFICANT RISK DETECTED: Analyzed parameters conform to standard legitimate operational norms. (Zero negative threat-feed hits does not guarantee absolute safety)."

        # Contradictions and Reassuring signals
        for e in engine_results:
            if "Established domain age" in str(e.findings):
                reassuring.append("Domain possesses established multi-year operational registration.")
            if "TLS Active" in str(e.findings) and score > 50:
                contradictory.append("Entity employs valid TLS transport encryption despite hosting deceptive or suspicious credential/brand elements.")

        return score, confidence, coverage, verdict, exec_summary, contradictory, reassuring, missing_info

class RecommendationEngine:
    name = "Recommendation Engine"

    def run(self, verdict: VerdictCategory, evidence: List[EvidenceItem]) -> List[str]:
        plans = []
        if verdict in (VerdictCategory.CRITICAL_RISK, VerdictCategory.HIGH_RISK):
            plans.append("DO NOT enter login credentials, passwords, or personal identity numbers on this resource.")
            plans.append("DO NOT execute monetary transfers, cryptocurrency payments, or upfront fee deposits.")
            plans.append("Block the domain/URL on perimeter firewalls and endpoint DNS filtering.")
            plans.append("If credentials were already submitted, immediately rotate passwords and invalidate active authentication sessions.")
            plans.append("Report the incident to relevant national cybercrime reporting portals or domain registrars.")
        elif verdict == VerdictCategory.MODERATE_RISK:
            plans.append("Verify the organization through an independently established contact method (do not use phone numbers or links provided in the message/website).")
            plans.append("Check official careers or press portals for corroboration of claims or offers.")
            plans.append("Avoid clicking embedded links; navigate directly to official root domains.")
        else:
            plans.append("Continue to practice routine digital vigilance.")
            plans.append("Verify HTTPS certificates and sender addresses prior to entering sensitive personal information.")
            plans.append("Remember that presence of SSL padlock (HTTPS) only encrypts transit, and does not certify organizational integrity.")

        return plans
