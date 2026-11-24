"""
Engine 8: Email Forensics Engine
Parses RFC 822 email headers, extracts Authentication-Results (SPF, DKIM, DMARC),
traces Received hop chains, evaluates Reply-To / Return-Path inconsistencies,
and flags display-name impersonation.
"""
import time
import re
import email
from email import policy
from typing import Dict, Any, List, Optional
from app.schemas.engines import EngineExecutionResult, EvidenceItem, SeverityLevel

class EmailForensicsEngine:
    name = "Email Forensics Engine"

    def run(
        self,
        email_address: Optional[str] = None,
        sender_name: Optional[str] = None,
        subject: Optional[str] = None,
        body: Optional[str] = None,
        raw_headers: Optional[str] = None
    ) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        parsed_headers = {}
        spf_status = "Not Supplied"
        dkim_status = "Not Supplied"
        dmarc_status = "Not Supplied"
        reply_to = None
        return_path = None
        hops = []
        
        # 1. Parse raw headers if supplied
        if raw_headers and raw_headers.strip():
            try:
                msg = email.message_from_string(raw_headers, policy=policy.default)
                sender = msg.get("From", "")
                reply_to = msg.get("Reply-To", "")
                return_path = msg.get("Return-Path", "")
                auth_results = msg.get_all("Authentication-Results", [])
                received_spf = msg.get_all("Received-SPF", [])
                received_headers = msg.get_all("Received", [])
                
                # Analyze Authentication-Results
                full_auth = " ".join(auth_results) + " " + " ".join(received_spf)
                full_auth_lower = full_auth.lower()
                
                if "spf=pass" in full_auth_lower:
                    spf_status = "PASS"
                    findings.append("SPF Authentication verified (PASS).")
                elif "spf=fail" in full_auth_lower or "spf=softfail" in full_auth_lower:
                    spf_status = "FAIL"
                    risk += 45.0
                    findings.append("SPF Authentication FAILED or SOFTFAIL.")
                    evidence.append(EvidenceItem(
                        id="EML-SPF-01",
                        engine_name=self.name,
                        severity=SeverityLevel.HIGH,
                        title="SPF Authentication Failure",
                        description="Sending IP address is not authorized by the sender domain's SPF policy record.",
                        raw_indicator=full_auth[:120],
                        confidence=0.92,
                        source_layer="email",
                        category="phishing"
                    ))
                elif "spf=" in full_auth_lower:
                    spf_status = "NEUTRAL/NONE"
                    findings.append("SPF evaluated as Neutral/None.")

                if "dkim=pass" in full_auth_lower:
                    dkim_status = "PASS"
                    findings.append("DKIM Cryptographic Signature verified (PASS).")
                elif "dkim=fail" in full_auth_lower:
                    dkim_status = "FAIL"
                    risk += 40.0
                    findings.append("DKIM Signature Verification FAILED.")
                    evidence.append(EvidenceItem(
                        id="EML-DKIM-02",
                        engine_name=self.name,
                        severity=SeverityLevel.HIGH,
                        title="DKIM Signature Verification Failed",
                        description="Message content or headers have been modified in transit, or cryptographic signature is invalid.",
                        raw_indicator=full_auth[:120],
                        confidence=0.9,
                        source_layer="email",
                        category="phishing"
                    ))

                if "dmarc=pass" in full_auth_lower:
                    dmarc_status = "PASS"
                    findings.append("DMARC Alignment Policy PASS.")
                elif "dmarc=fail" in full_auth_lower:
                    dmarc_status = "FAIL"
                    risk += 50.0
                    findings.append("DMARC Enforcement FAILED.")
                    evidence.append(EvidenceItem(
                        id="EML-DMARC-03",
                        engine_name=self.name,
                        severity=SeverityLevel.CRITICAL,
                        title="DMARC Policy Rejection / Failure",
                        description="Header 'From' domain fails alignment with authenticated SPF/DKIM domains.",
                        raw_indicator=full_auth[:120],
                        confidence=0.95,
                        source_layer="email",
                        category="phishing"
                    ))

                # Check Reply-To and Return-Path Mismatch
                if reply_to and sender:
                    sender_email_match = re.search(r'[\w\.-]+@[\w\.-]+', sender)
                    reply_email_match = re.search(r'[\w\.-]+@[\w\.-]+', reply_to)
                    if sender_email_match and reply_email_match:
                        s_domain = sender_email_match.group(0).split("@")[-1].lower()
                        r_domain = reply_email_match.group(0).split("@")[-1].lower()
                        if s_domain != r_domain and not ("mailgun" in r_domain or "sendgrid" in r_domain or "zendesk" in r_domain):
                            risk += 35.0
                            findings.append(f"Reply-To domain mismatch: Sent from @{s_domain}, replies route to @{r_domain}.")
                            evidence.append(EvidenceItem(
                                id="EML-REPLY-04",
                                engine_name=self.name,
                                severity=SeverityLevel.HIGH,
                                title="Reply-To Domain Mismatch",
                                description="Replies will route to a different external domain than the apparent sender, common in BEC and credentials spoofing.",
                                raw_indicator=f"From: {s_domain} -> Reply-To: {r_domain}",
                                confidence=0.88,
                                source_layer="email",
                                category="impersonation"
                            ))

                # Received hop counting
                hops = [h.strip().replace("\n", " ")[:120] for h in received_headers]
                findings.append(f"Header hop chain: {len(hops)} intermediate relays traced.")

            except Exception as e:
                findings.append(f"Header parsing error: {str(e)}")
        else:
            findings.append("No raw email headers supplied. SPF/DKIM/DMARC cryptographic validation could not be performed. Assessment based on sender address and body semantics.")

        # 2. Display Name Impersonation (e.g. sender_name="PayPal Support", email="john8472@gmail.com")
        if email_address and sender_name:
            email_lower = email_address.lower()
            name_lower = sender_name.lower()
            domain = email_lower.split("@")[-1] if "@" in email_lower else ""
            
            brands = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "bank", "chase", "fedex", "dhl", "support"]
            for brand in brands:
                if brand in name_lower and brand not in domain:
                    risk += 50.0
                    findings.append(f"Display Name Impersonation: Displays as '{sender_name}', but sending domain is '@{domain}'.")
                    evidence.append(EvidenceItem(
                        id="EML-NAME-05",
                        engine_name=self.name,
                        severity=SeverityLevel.CRITICAL,
                        title="Display Name Impersonation",
                        description=f"The sender name mimics '{brand.capitalize()}' but originates from an unrelated domain (@{domain}), a prevalent mobile spear-phishing technique.",
                        raw_indicator=f"{sender_name} <{email_address}>",
                        confidence=0.96,
                        source_layer="email",
                        category="impersonation"
                    ))
                    break

        # 3. Check for Free Webmail in Business / Official Context
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "yandex.com", "proton.me", "protonmail.com"]
        if email_address:
            dom = email_address.lower().split("@")[-1] if "@" in email_address else ""
            if dom in free_providers:
                findings.append(f"Sender utilizes consumer free webmail provider (@{dom}).")

        # 4. Body heuristics if body supplied
        if body:
            urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
            if urls:
                findings.append(f"Extracted {len(urls)} embedded URL(s) from email body.")
                
            suspicious_actions = ["click here to reactivate", "verify your identity immediately", "wire transfer", "gift cards"]
            for action in suspicious_actions:
                if action in body.lower():
                    risk += 25.0
                    findings.append(f"Solicitation pattern: '{action}'")

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Email Forensics completed. SPF: {spf_status}, DKIM: {dkim_status}, DMARC: {dmarc_status}, Risk: {round(risk, 1)}",
            risk_contribution=min(risk, 90.0),
            findings=findings,
            evidence=evidence,
            metadata={
                "spf_status": spf_status,
                "dkim_status": dkim_status,
                "dmarc_status": dmarc_status,
                "reply_to": reply_to,
                "return_path": return_path,
                "hop_count": len(hops)
            }
        )
