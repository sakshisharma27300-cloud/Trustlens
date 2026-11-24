"""
Engine 1: Input Normalization Engine
Engine 2: URL Structural Analysis Engine

Normalizes internationalized domain names (IDN/Punycode), removes deceptive encoding,
extracts TLDs, subdomains, embedded credentials, IP-based URLs, and calculates entropy.
"""
import time
import math
import re
from urllib.parse import urlparse, unquote
from typing import Dict, Any, Tuple, List
from app.schemas.engines import EngineExecutionResult, EvidenceItem, SeverityLevel

def normalize_input_url(raw_input: str) -> str:
    """Normalizes input string into a standard verifiable URL format."""
    trimmed = raw_input.strip()
    # Strip enclosing quotes, brackets, or markdown links
    trimmed = re.sub(r'^[<"\'\[(]+|[>"\'\])]+$', '', trimmed)
    if not trimmed.startswith(("http://", "https://")):
        trimmed = "https://" + trimmed
    return trimmed

def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect DGA or obfuscated random paths."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy, 2)

class NormalizationEngine:
    name = "Input Normalization Engine"

    def run(self, raw_input: str) -> Tuple[EngineExecutionResult, str, Dict[str, Any]]:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        normalized_url = normalize_input_url(raw_input)
        
        # Check for Unicode homoglyphs / Punycode
        is_punycode = "xn--" in normalized_url
        if is_punycode:
            findings.append("Detected Punycode encoded domain (potential internationalized homoglyph disguise).")
            risk += 25.0
            evidence.append(EvidenceItem(
                id="NORM-01",
                engine_name=self.name,
                severity=SeverityLevel.HIGH,
                title="Punycode Homoglyph Detected",
                description="Target uses 'xn--' prefix representing internationalized characters often used to spoof authentic ASCII domains.",
                raw_indicator=normalized_url,
                confidence=0.9,
                source_layer="url",
                category="structural_anomaly"
            ))
            
        # Check for URL encoding obfuscation
        unquoted = unquote(normalized_url)
        if unquoted != normalized_url:
            findings.append("Target contains percent-encoded characters.")
            if "%00" in normalized_url or "%2e%2e" in normalized_url.lower():
                risk += 35.0
                evidence.append(EvidenceItem(
                    id="NORM-02",
                    engine_name=self.name,
                    severity=SeverityLevel.HIGH,
                    title="Path Traversal / Null Byte in URL",
                    description="Detected encoded path traversal or null byte pattern.",
                    raw_indicator=normalized_url,
                    confidence=0.95,
                    source_layer="url",
                    category="structural_anomaly"
                ))

        elapsed = round((time.time() - start_t) * 1000, 2)
        result = EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Input normalized. Evaluated encoding, Punycode, and sanitization.",
            risk_contribution=min(risk, 40.0),
            findings=findings,
            evidence=evidence,
            metadata={"normalized_url": normalized_url, "is_punycode": is_punycode}
        )
        return result, normalized_url, {"normalized_url": normalized_url, "is_punycode": is_punycode}

class URLStructuralEngine:
    name = "URL Structural Analysis Engine"

    # Known shorteners
    SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rb.gy", "cutt.ly"}
    SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".work", ".click", ".link", ".sbs", ".monster", ".cfd", ".icu", ".rest"}

    def run(self, url: str) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        parsed = urlparse(url)
        netloc = parsed.netloc.split(":")[0]  # hostname without port
        path = parsed.path
        query = parsed.query
        
        # 1. IP-address based URL
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', netloc))
        if is_ip:
            risk += 45.0
            findings.append("Host is a bare IPv4 address rather than a registered domain name.")
            evidence.append(EvidenceItem(
                id="URL-IP-01",
                engine_name=self.name,
                severity=SeverityLevel.HIGH,
                title="Direct IP-Based Host",
                description="Legitimate consumer portals use registered domain names. Direct IP addresses are frequently deployed in temporary phishing hosting.",
                raw_indicator=netloc,
                confidence=0.88,
                source_layer="url",
                category="phishing"
            ))

        # 2. Embedded credentials (e.g., http://google.com@phishingsite.com)
        if "@" in parsed.netloc:
            risk += 60.0
            findings.append("Host contains embedded '@' credential separator, a classic deceptive URL spoofing technique.")
            evidence.append(EvidenceItem(
                id="URL-CRED-02",
                engine_name=self.name,
                severity=SeverityLevel.CRITICAL,
                title="Credential Masking '@' in URL",
                description="Attackers prepend trusted domain names before '@' to mislead victims about the true destination host.",
                raw_indicator=parsed.netloc,
                confidence=0.98,
                source_layer="url",
                category="phishing"
            ))

        # 3. URL Shortener detection
        if netloc.lower() in self.SHORTENERS:
            risk += 20.0
            findings.append(f"Domain '{netloc}' is a known public URL shortening service that conceals destination endpoints.")
            evidence.append(EvidenceItem(
                id="URL-SHORT-03",
                engine_name=self.name,
                severity=SeverityLevel.MEDIUM,
                title="URL Shortener Concealment",
                description="URL shorteners mask actual destination domains, often used to bypass initial visual inspection.",
                raw_indicator=netloc,
                confidence=0.85,
                source_layer="url",
                category="structural_anomaly"
            ))

        # 4. Excessive Subdomains (Domain stacking)
        parts = netloc.split(".")
        if len(parts) > 4:
            risk += 25.0
            findings.append(f"Excessive subdomain depth detected ({len(parts)} levels), frequently observed in multi-tenant phishing kits.")
            evidence.append(EvidenceItem(
                id="URL-SUB-04",
                engine_name=self.name,
                severity=SeverityLevel.MEDIUM,
                title="Deep Subdomain Nesting",
                description="Phishing kits frequently generate deep subdomain chains (e.g., paypal.com.verification.attacker.com) to deceive mobile users.",
                raw_indicator=netloc,
                confidence=0.8,
                source_layer="url",
                category="impersonation"
            ))

        # 5. Suspicious TLD check
        for tld in self.SUSPICIOUS_TLDS:
            if netloc.endswith(tld):
                risk += 15.0
                findings.append(f"Domain uses high-abuse discount TLD '{tld}'.")
                break

        # 6. Path and Query Entropy / Phishing keywords
        path_entropy = calculate_shannon_entropy(path)
        if path_entropy > 4.5 and len(path) > 30:
            findings.append(f"High path entropy ({path_entropy}), indicative of randomized automated payload naming.")
            
        phish_keywords = ["login", "signin", "verify", "account", "update", "banking", "secure", "wallet", "recover", "kyc"]
        matched_keywords = [kw for kw in phish_keywords if kw in path.lower() or kw in query.lower()]
        if matched_keywords and (is_ip or len(parts) > 3):
            risk += 30.0
            findings.append(f"Security-sensitive keywords in path: {', '.join(matched_keywords)}")

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Parsed URL structure. Host: {netloc}, Path depth: {len(path.split('/')) - 1}, Risk contribution: {round(risk, 1)}",
            risk_contribution=min(risk, 85.0),
            findings=findings if findings else ["URL structure conforms to standard web conventions."],
            evidence=evidence,
            metadata={
                "hostname": netloc,
                "scheme": parsed.scheme,
                "path_entropy": path_entropy,
                "is_ip": is_ip,
                "subdomain_count": len(parts) - 2 if len(parts) >= 2 else 0
            }
        )
