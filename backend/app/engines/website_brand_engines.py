"""
Engine 6: Website Content Analysis Engine
Engine 7: Brand Impersonation Engine

Inspects public page content in safe isolated sandbox.
Extracts login forms, fake trust seals, credential collection fields,
crypto payment demands, and detects typo-squatting / homoglyph brand impersonation.
"""
import time
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
from app.core.ssrf_guard import safe_fetch_website_content
from app.schemas.engines import EngineExecutionResult, EvidenceItem, SeverityLevel

# Authoritative Top Global Brands & Targets of Phishing Impersonation
TARGET_BRANDS = {
    "google": ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "login.microsoftonline.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"]
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class WebsiteContentEngine:
    name = "Website Content Analysis Engine"

    async def run(self, url: str) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        success, html_text, meta, msg = await safe_fetch_website_content(url)
        
        if not success:
            findings.append(f"Content fetch restricted or unavailable: {msg}")
            elapsed = round((time.time() - start_t) * 1000, 2)
            return EngineExecutionResult(
                engine_name=self.name,
                executed=True,
                execution_time_ms=elapsed,
                status="partial",
                summary=f"Safe content fetch bypassed: {msg}",
                risk_contribution=0.0,
                findings=findings,
                evidence=[],
                metadata={"fetch_status": msg}
            )

        soup = BeautifulSoup(html_text, "html.parser")
        
        # 1. Extract Page Title
        title = soup.title.string.strip() if soup.title and soup.title.string else "Untitled"
        findings.append(f"Page Title: '{title[:80]}'")
        
        # 2. Check for Password Fields & Credential Harvesting
        password_inputs = soup.find_all("input", {"type": "password"})
        has_password = len(password_inputs) > 0
        if has_password:
            findings.append(f"Detected {len(password_inputs)} credential / password input field(s).")
            # If site is not HTTPS, huge violation
            if not url.startswith("https://"):
                risk += 60.0
                evidence.append(EvidenceItem(
                    id="CONT-CRED-01",
                    engine_name=self.name,
                    severity=SeverityLevel.CRITICAL,
                    title="Unencrypted Credential Form",
                    description="The page solicits passwords over unencrypted HTTP protocol, violating basic security standards and exposing credentials in cleartext.",
                    raw_indicator=f"Form in {url}",
                    confidence=0.98,
                    source_layer="content",
                    category="phishing"
                ))
            else:
                risk += 15.0

        # 3. Check for Suspicious Financial Demands / Cryptocurrency Addresses
        btc_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        eth_pattern = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
        text_content = soup.get_text()
        
        btc_matches = btc_pattern.findall(text_content)
        eth_matches = eth_pattern.findall(text_content)
        
        if btc_matches or eth_matches:
            risk += 35.0
            findings.append(f"Detected direct cryptocurrency wallet addresses in page text ({len(btc_matches)} BTC, {len(eth_matches)} ETH).")
            evidence.append(EvidenceItem(
                id="CONT-CRYPTO-02",
                engine_name=self.name,
                severity=SeverityLevel.HIGH,
                title="Cryptocurrency Payment Request",
                description="Direct wallet address embedding without official gateway integration is a frequent pattern in extortion and fraudulent investment schemes.",
                raw_indicator=f"Wallets: {btc_matches[:2] or eth_matches[:2]}",
                confidence=0.85,
                source_layer="content",
                category="advance_fee"
            ))

        # 4. Check for Fake Trust Badges
        trust_badge_keywords = ["norton secured", "mcafee secure", "verified by visa", "bbb accredited"]
        for badge in trust_badge_keywords:
            if badge in text_content.lower():
                findings.append(f"References trust badge: '{badge}'. Verified static image or text claim.")

        # 5. Check for Emergency or Social Engineering Keywords
        urgency_terms = ["act immediately", "account suspended within 24 hours", "unauthorized transaction detected", "call police", "arrest warrant"]
        found_urgency = [term for term in urgency_terms if term in text_content.lower()]
        if found_urgency:
            risk += 30.0
            findings.append(f"High-urgency coercive language found: {', '.join(found_urgency)}")
            evidence.append(EvidenceItem(
                id="CONT-URG-03",
                engine_name=self.name,
                severity=SeverityLevel.HIGH,
                title="Coercive Urgency Trigger",
                description="Detected threatening or artificial countdown language designed to force immediate compliance.",
                raw_indicator=", ".join(found_urgency),
                confidence=0.88,
                source_layer="content",
                category="phishing"
            ))

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Inspected public HTML structure. Password fields: {len(password_inputs)}, Page title: '{title[:40]}'",
            risk_contribution=min(risk, 75.0),
            findings=findings,
            evidence=evidence,
            metadata={
                "title": title,
                "has_password_field": has_password,
                "server_header": meta.get("server_header") if meta else "unknown"
            }
        )

class BrandImpersonationEngine:
    name = "Brand Impersonation Engine"

    def run(self, domain: str, page_title: Optional[str] = None) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        domain_lower = domain.lower()
        parts = domain_lower.split(".")
        main_label = parts[-2] if len(parts) >= 2 else parts[0]
        
        for brand, official_domains in TARGET_BRANDS.items():
            # If domain IS the official domain, it's legitimate for this brand
            is_official = any(domain_lower == off or domain_lower.endswith("." + off) for off in official_domains)
            if is_official:
                findings.append(f"Domain aligns directly with official reference registry for brand '{brand}'.")
                break
                
            # Check 1: Brand name embedded in unrelated domain (e.g. paypal-security-update.com)
            if brand in domain_lower:
                risk += 60.0
                findings.append(f"CRITICAL: Brand '{brand}' is embedded within an unofficial domain name ('{domain}').")
                evidence.append(EvidenceItem(
                    id="BRAND-EMBED-01",
                    engine_name=self.name,
                    severity=SeverityLevel.CRITICAL,
                    title=f"Brand Squatting ({brand.capitalize()})",
                    description=f"Domain contains the protected brand keyword '{brand}' but does not belong to authorized brand nameservers or root domains.",
                    raw_indicator=f"Target: {domain}, Official: {official_domains[0]}",
                    confidence=0.96,
                    source_layer="identity",
                    category="impersonation"
                ))
                break
                
            # Check 2: Levenshtein Typo-Squatting (e.g. g00gle, paypai, micr0soft)
            dist = levenshtein_distance(main_label, brand)
            if 0 < dist <= 2 and len(brand) >= 5:
                risk += 50.0
                findings.append(f"Typo-squatting indicator: Domain label '{main_label}' is {dist} edit(s) away from global brand '{brand}'.")
                evidence.append(EvidenceItem(
                    id="BRAND-TYPO-02",
                    engine_name=self.name,
                    severity=SeverityLevel.HIGH,
                    title=f"Typo-Squatting / Lookalike ({brand.capitalize()})",
                    description=f"Domain closely mimics '{brand}' with minor typographical substitution to deceive rushed users.",
                    raw_indicator=f"Target label: {main_label}, Target brand: {brand}",
                    confidence=0.91,
                    source_layer="identity",
                    category="impersonation"
                ))
                break

        # Check page title for brand impersonation if title exists
        if page_title and risk < 30:
            title_lower = page_title.lower()
            for brand, official_domains in TARGET_BRANDS.items():
                if brand in title_lower and not any(off in domain_lower for off in official_domains):
                    risk += 35.0
                    findings.append(f"Page title references brand '{brand}', yet host domain '{domain}' has no authoritative link.")
                    evidence.append(EvidenceItem(
                        id="BRAND-TITLE-03",
                        engine_name=self.name,
                        severity=SeverityLevel.HIGH,
                        title=f"Title / Domain Identity Contradiction",
                        description=f"Website claims brand identity '{brand}' in header titles while hosted on unrelated third-party infrastructure.",
                        raw_indicator=f"Title: {page_title}, Domain: {domain}",
                        confidence=0.87,
                        source_layer="identity",
                        category="impersonation"
                    ))
                    break

        if not findings:
            findings.append("No direct brand keyword squatting or typo-squatting detected against monitored global brand registry.")

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Compared host against {len(TARGET_BRANDS)} high-profile financial, tech, and logistics brands.",
            risk_contribution=min(risk, 85.0),
            findings=findings,
            evidence=evidence,
            metadata={"evaluated_label": main_label}
        )
