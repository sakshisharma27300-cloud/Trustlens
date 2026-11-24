"""
Engine 3: Domain Registration Intelligence Engine
Engine 4: DNS Intelligence Engine
Engine 5: TLS & Certificate Intelligence Engine
"""
import time
import ssl
import socket
from urllib.parse import urlparse
from typing import Dict, Any, List
from app.integrations.rdap_provider import query_rdap
from app.integrations.doh_resolver import get_full_dns_profile
from app.schemas.engines import EngineExecutionResult, EvidenceItem, SeverityLevel

class DomainRegistrationEngine:
    name = "Domain Registration Intelligence Engine"

    async def run(self, domain: str) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        rdap_data = await query_rdap(domain)
        
        if rdap_data.get("available"):
            age_days = rdap_data.get("domain_age_days")
            created = rdap_data.get("created_date")
            registrar = rdap_data.get("registrar")
            
            if age_days is not None:
                if age_days < 14:
                    risk += 50.0
                    findings.append(f"CRITICAL: Brand new domain registered only {age_days} days ago ({created}). High correlation with ephemeral scam/phishing campaigns.")
                    evidence.append(EvidenceItem(
                        id="REG-AGE-01",
                        engine_name=self.name,
                        severity=SeverityLevel.HIGH,
                        title="Ultra-Young Domain Registration",
                        description=f"Domain registered within the last 14 days ({age_days} days old). Legitimate enterprise operations rarely deploy brand new domains for financial/login transactions.",
                        raw_indicator=f"Age: {age_days} days, Created: {created}",
                        confidence=0.9,
                        source_layer="domain",
                        category="phishing"
                    ))
                elif age_days < 60:
                    risk += 25.0
                    findings.append(f"Domain is relatively new ({age_days} days old, registered {created}).")
                elif age_days > 730:
                    findings.append(f"Established domain age: {round(age_days / 365.0, 1)} years ({age_days} days).")
            else:
                findings.append("Registration timestamp withheld by registry or unavailable.")
                
            if rdap_data.get("privacy_protected"):
                findings.append("Registrant contact details are privacy-protected (Standard neutral privacy practice).")
                
            findings.append(f"Sponsoring Registrar: {registrar}")
        else:
            findings.append("RDAP registration record unavailable from top-level registry. Proceeding with passive telemetry.")

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success" if rdap_data.get("available") else "partial",
            summary=f"Evaluated domain lifecycle and registry status for {domain}.",
            risk_contribution=min(risk, 70.0),
            findings=findings,
            evidence=evidence,
            metadata=rdap_data
        )

class DNSIntelligenceEngine:
    name = "DNS Intelligence Engine"

    async def run(self, domain: str) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        dns_profile = await get_full_dns_profile(domain)
        records = dns_profile.get("records", {})
        
        a_records = records.get("A", [])
        mx_records = records.get("MX", [])
        txt_records = records.get("TXT", [])
        ns_records = records.get("NS", [])
        
        if not dns_profile.get("resolved"):
            risk += 30.0
            findings.append("Domain failed to resolve standard DNS A/AAAA records (NXDOMAIN or inactive).")
            evidence.append(EvidenceItem(
                id="DNS-NX-01",
                engine_name=self.name,
                severity=SeverityLevel.MEDIUM,
                title="Unresolved DNS Records",
                description="The target domain does not resolve to active IP addresses via public DoH resolvers.",
                raw_indicator=domain,
                confidence=0.75,
                source_layer="dns",
                category="structural_anomaly"
            ))
        else:
            findings.append(f"Resolved to {len(a_records)} IPv4 address(es): {', '.join(a_records[:3])}")
            
            # MX record inspection
            if not mx_records:
                findings.append("No MX (Mail Exchange) records configured. Domain cannot receive official email.")
            else:
                findings.append(f"Configured MX: {', '.join(mx_records[:2])}")
                
            # SPF record check
            has_spf = any("v=spf1" in txt.lower() for txt in txt_records)
            if has_spf:
                findings.append("Configured SPF policy in TXT records.")
            else:
                findings.append("No SPF authentication record found in TXT records.")
                
            # Fast-flux or excessive IP churn warning
            if len(a_records) > 6:
                findings.append(f"Large pool of resolved IPs ({len(a_records)}), consistent with CDN or distributed hosting.")

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success" if dns_profile.get("resolved") else "partial",
            summary=f"Queried DNS over HTTPS. A: {len(a_records)}, MX: {len(mx_records)}, NS: {len(ns_records)}",
            risk_contribution=min(risk, 40.0),
            findings=findings,
            evidence=evidence,
            metadata=dns_profile
        )

class TLSIntelligenceEngine:
    name = "TLS & Certificate Intelligence Engine"

    def run(self, hostname: str, port: int = 443) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        cert_data = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Safe inspection of raw cert
            
            with socket.create_connection((hostname, port), timeout=3.5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Also extract raw cert if available
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    sans = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]
                    not_after = cert.get("notAfter", "")
                    
                    issuer_org = issuer.get("organizationName", "Unknown Issuer")
                    common_name = subject.get("commonName", "")
                    
                    cert_data = {
                        "common_name": common_name,
                        "issuer": issuer_org,
                        "sans": sans[:10],
                        "not_after": not_after,
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else None,
                        "is_valid_https": True
                    }
                    
                    findings.append(f"TLS Active ({version}, Cipher: {cipher[0] if cipher else 'N/A'})")
                    findings.append(f"Certificate Authority: {issuer_org}")
                    
                    # Note on DV vs EV and free CAs
                    if "Let's Encrypt" in issuer_org or "cPanel" in issuer_org or "ZeroSSL" in issuer_org:
                        findings.append(f"Domain-Validated (DV) automated certificate from '{issuer_org}'. Note: Over 80% of modern phishing pages utilize automated DV certificates; presence of HTTPS does NOT indicate legitimacy.")
                    else:
                        findings.append(f"Organization-Validated or Commercial Certificate: {issuer_org}")
                        
                    # Check domain match in SANs
                    if sans and hostname.lower() not in [s.lower() for s in sans] and not any(s.startswith("*.") and hostname.lower().endswith(s[2:].lower()) for s in sans):
                        risk += 40.0
                        findings.append(f"Certificate SAN mismatch: Host '{hostname}' not found in SAN list: {sans[:3]}")
                        evidence.append(EvidenceItem(
                            id="TLS-MISMATCH-01",
                            engine_name=self.name,
                            severity=SeverityLevel.HIGH,
                            title="TLS Hostname / Certificate SAN Mismatch",
                            description="The server returned a certificate that does not explicitly cover the visited domain name, indicating misconfiguration, shared phishing cluster, or proxy interception.",
                            raw_indicator=f"Target: {hostname}, SANs: {', '.join(sans[:3])}",
                            confidence=0.88,
                            source_layer="tls",
                            category="structural_anomaly"
                        ))
                        
        except Exception as e:
            findings.append(f"TLS handshake was unresolvable or rejected: {str(e)}")
            cert_data = {"is_valid_https": False, "error": str(e)}
            # Non-TLS is common on HTTP or plain services, small risk bump
            risk += 15.0

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success" if cert_data.get("is_valid_https") else "partial",
            summary=f"TLS Inspection. Issuer: {cert_data.get('issuer', 'None')}, Valid: {cert_data.get('is_valid_https', False)}",
            risk_contribution=min(risk, 50.0),
            findings=findings,
            evidence=evidence,
            metadata=cert_data
        )
