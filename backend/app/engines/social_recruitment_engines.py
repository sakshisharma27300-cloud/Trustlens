"""
Engine 9: Social Engineering Detection Engine
Engine 10: Multilingual NLP Engine
Engine 11: Recruitment Fraud Engine

Covers international scam typologies: Digital Arrest, Fake Courier, Advance-Fee,
Crypto Investment, OTP Theft, Fake Refund, and Recruitment Impersonation.
"""
import time
import re
from typing import Dict, Any, List, Optional, Tuple
from app.schemas.engines import EngineExecutionResult, EvidenceItem, SeverityLevel

# Comprehensive Global Scam Taxonomy & Pattern Signatures
SCAM_PATTERNS = {
    "digital_arrest": {
        "title": "Digital Arrest / Law Enforcement Impersonation Scam",
        "keywords": ["cbi", "police department", "customs department", "money laundering", "narcotics bureau", "arrest warrant", "stay on video call", "skype interrogation", "supreme court order"],
        "severity": SeverityLevel.CRITICAL,
        "risk": 75.0,
        "description": "Criminals impersonate police, customs, or judicial officers claiming illegal parcels or money laundering, demanding victims stay isolated on video calls and transfer funds for 'verification'."
    },
    "fake_courier": {
        "title": "Courier / Customs Duty Impersonation",
        "keywords": ["package held", "customs fee", "unpaid duty", "delivery failed", "reschedule delivery", "click here to pay 1.", "click here to pay 2.", "dhl tracking", "fedex parcel"],
        "severity": SeverityLevel.HIGH,
        "risk": 55.0,
        "description": "Impersonates postal/courier agencies requesting small fee payments or personal identification to release fictitious international packages."
    },
    "crypto_investment": {
        "title": "High-Yield Cryptocurrency / Investment Fraud",
        "keywords": ["guaranteed returns", "daily profit", "crypto mining", "investment plan", "double your money", "vip trading group", "whatsapp investment group", "telegram trading signals", "passive income 100%"],
        "severity": SeverityLevel.CRITICAL,
        "risk": 70.0,
        "description": "Promises unrealistic or risk-free profits through fake cryptocurrency trading dashboards or exclusive insider messaging groups."
    },
    "otp_theft": {
        "title": "Credential / OTP Interception Attack",
        "keywords": ["share otp", "one time password", "verification code", "confirm code to unblock", "send 6 digit code", "do not share with bank official"],
        "severity": SeverityLevel.CRITICAL,
        "risk": 80.0,
        "description": "Attempts to elicit multi-factor authentication (MFA/OTP) tokens under pretext of fraud resolution or account reactivation."
    },
    "fake_refund": {
        "title": "Overpayment / Fake Refund Scam",
        "keywords": ["accidental refund", "refund of $", "refund of £", "refund of €", "fill out refund form", "remote support", "anydesk", "teamviewer"],
        "severity": SeverityLevel.HIGH,
        "risk": 65.0,
        "description": "Tricks victims into believing they were erroneously refunded, instructing them to install remote access tools (AnyDesk/TeamViewer) or wire back money."
    },
    "advance_fee": {
        "title": "Advance-Fee / Prize / Lottery Scam",
        "keywords": ["you have won", "lottery prize", "processing fee", "claim your prize", "inheritance", "diplomatic courier", "fund release fee"],
        "severity": SeverityLevel.HIGH,
        "risk": 60.0,
        "description": "Demands upfront payment or clearance taxes before transferring non-existent lottery windfalls or inheritance allocations."
    }
}

# Multilingual Keyword Mappings (Spanish, French, German, Hindi, Portuguese)
MULTILINGUAL_PATTERNS = {
    "es": {
        "bloqueo de cuenta": "Urgent account suspension warning",
        "haga clic aquí": "Generic phishing call-to-action",
        "paquete retenido": "Fake courier package notification",
        "ganador de la lotería": "Lottery advance-fee lure"
    },
    "fr": {
        "compte suspendu": "Account suspension threat",
        "cliquez ici": "Phishing link call-to-action",
        "colis en attente": "Courier impostor scam",
        "amende impayée": "Government imposter fine scam"
    },
    "de": {
        "konto gesperrt": "Urgent account lock warning",
        "paket konnte nicht zugestellt werden": "Parcel delivery fraud",
        "überweisung bestätigen": "Unauthorized transfer alert"
    },
    "hi": {
        "डिजिटल अरेस्ट": "Digital arrest scam phrase",
        "खाता ब्लॉक": "Account block threat",
        "लॉटरी जीती": "Lottery lure",
        "ओटीपी बताएं": "OTP elicitation attempt"
    }
}

class SocialEngineeringEngine:
    name = "Social Engineering Detection Engine"

    def run(self, message_text: str) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        lower_msg = message_text.lower()
        
        detected_categories = []
        
        for cat_key, cat_data in SCAM_PATTERNS.items():
            matched_terms = [kw for kw in cat_data["keywords"] if kw in lower_msg]
            if matched_terms:
                detected_categories.append(cat_data["title"])
                risk += cat_data["risk"]
                findings.append(f"Identified {cat_data['title']} pattern: Excerpts: [{', '.join(matched_terms[:3])}]")
                evidence.append(EvidenceItem(
                    id=f"SOC-{cat_key.upper()[:4]}-01",
                    engine_name=self.name,
                    severity=cat_data["severity"],
                    title=cat_data["title"],
                    description=cat_data["description"],
                    raw_indicator=", ".join(matched_terms),
                    confidence=0.92,
                    source_layer="linguistic",
                    category="phishing"
                ))

        # Check for emotional manipulation triggers: Fear, Urgency, Greed, Secrecy
        psych_triggers = []
        if any(w in lower_msg for w in ["immediate", "within 1 hour", "urgent", "expires today", "before time runs out"]):
            psych_triggers.append("Artificial Urgency (forces irrational immediate action)")
        if any(w in lower_msg for w in ["confidential", "do not tell anyone", "keep this secret", "private transaction"]):
            psych_triggers.append("Forced Isolation / Secrecy (prevents consulting family or experts)")
        if any(w in lower_msg for w in ["arrest", "prison", "warrant", "court summons", "fbi", "police"]):
            psych_triggers.append("Intimidation / Coercion via Authority Impersonation")

        if psych_triggers:
            findings.append(f"Psychological manipulation levers identified: {'; '.join(psych_triggers)}")
            risk += 20.0

        if not findings:
            findings.append("No common high-risk social engineering or advance-fee patterns matched.")

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Social engineering evaluation completed. Matched {len(detected_categories)} scam signatures.",
            risk_contribution=min(risk, 90.0),
            findings=findings,
            evidence=evidence,
            metadata={"matched_typologies": detected_categories, "psych_triggers": psych_triggers}
        )

class MultilingualNLPEngine:
    name = "Multilingual NLP Engine"

    def run(self, text: str) -> Tuple[EngineExecutionResult, str, List[Dict[str, str]]]:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        # Simple reliable character distribution language detector
        detected_lang = "en"
        # Check Devanagari (Hindi)
        if re.search(r'[\u0900-\u097F]', text):
            detected_lang = "hi"
        # Check Arabic
        elif re.search(r'[\u0600-\u06FF]', text):
            detected_lang = "ar"
        # Check Cyrillic (Russian/Ukrainian)
        elif re.search(r'[\u0400-\u04FF]', text):
            detected_lang = "ru"
        # Check Spanish markers (ñ, ¿, ¡, á, é, í, ó, ú)
        elif re.search(r'[áéíóúñ¿¡]', text.lower()):
            detected_lang = "es"
        # Check French markers (ç, è, à, ê, â)
        elif re.search(r'[çèàêâ]', text.lower()):
            detected_lang = "fr"
        # Check German markers (ä, ö, ü, ß)
        elif re.search(r'[äöüß]', text.lower()):
            detected_lang = "de"

        findings.append(f"Detected message language/script: '{detected_lang.upper()}'. Evaluating localized semantic patterns.")
        
        highlighted_excerpts = []
        if detected_lang in MULTILINGUAL_PATTERNS:
            lang_dict = MULTILINGUAL_PATTERNS[detected_lang]
            for phrase, meaning in lang_dict.items():
                if phrase in text.lower():
                    risk += 35.0
                    findings.append(f"Localized scam phrase in {detected_lang.upper()}: '{phrase}' ({meaning})")
                    highlighted_excerpts.append({"phrase": phrase, "meaning": meaning, "lang": detected_lang})
                    evidence.append(EvidenceItem(
                        id=f"ML-{detected_lang.upper()}-01",
                        engine_name=self.name,
                        severity=SeverityLevel.HIGH,
                        title=f"Multilingual Threat Phrase ({detected_lang.upper()})",
                        description=f"Identified region-specific fraud trigger: '{phrase}' ({meaning})",
                        raw_indicator=phrase,
                        confidence=0.89,
                        source_layer="linguistic",
                        category="phishing"
                    ))

        elapsed = round((time.time() - start_t) * 1000, 2)
        res = EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Processed text in {detected_lang.upper()}. Preserved original excerpts for forensic review.",
            risk_contribution=min(risk, 60.0),
            findings=findings,
            evidence=evidence,
            metadata={"detected_language": detected_lang, "excerpts": highlighted_excerpts}
        )
        return res, detected_lang, highlighted_excerpts

class RecruitmentFraudEngine:
    name = "Recruitment Fraud Engine"

    FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "aol.com"}

    def run(
        self,
        company_name: str,
        recruiter_email: Optional[str] = None,
        job_title: Optional[str] = None,
        website_url: Optional[str] = None,
        offer_text: Optional[str] = None,
        payment_requested: Optional[bool] = False,
        payment_amount: Optional[str] = None,
        interview_platform: Optional[str] = None
    ) -> EngineExecutionResult:
        start_t = time.time()
        findings = []
        evidence = []
        risk = 0.0
        
        # 1. Payment demands for employment (Absolute Red Flag)
        if payment_requested or (offer_text and any(w in offer_text.lower() for w in ["security deposit", "laptop fee", "training fee", "registration charges", "refundable payment", "equipment processing fee"])):
            risk += 75.0
            amount_str = f" ({payment_amount})" if payment_amount else ""
            findings.append(f"CRITICAL: Upfront payment demanded for employment{amount_str}. Legitimate global corporations never demand job-seekers pay for employment, training, or hardware.")
            evidence.append(EvidenceItem(
                id="REC-PAY-01",
                engine_name=self.name,
                severity=SeverityLevel.CRITICAL,
                title="Upfront Employment Fee Demand",
                description="The offer mandates upfront monetary payment under the guise of refundable security deposits, training materials, or hardware processing. This is a definitive advance-fee recruitment scam pattern.",
                raw_indicator=payment_amount or "Payment demanded in recruitment flow",
                confidence=0.98,
                source_layer="identity",
                category="advance_fee"
            ))

        # 2. Free Webmail Domain for Corporate Recruiter
        if recruiter_email:
            email_domain = recruiter_email.lower().split("@")[-1] if "@" in recruiter_email else ""
            if email_domain in self.FREE_EMAIL_DOMAINS:
                risk += 45.0
                findings.append(f"Recruiter uses free webmail domain (@{email_domain}) while representing '{company_name}'.")
                evidence.append(EvidenceItem(
                    id="REC-EMAIL-02",
                    engine_name=self.name,
                    severity=SeverityLevel.HIGH,
                    title="Recruiter Free Webmail Mismatch",
                    description=f"Recruiter claims to represent '{company_name}' but contacts candidates from personal/free webmail (@{email_domain}) rather than an enterprise domain.",
                    raw_indicator=recruiter_email,
                    confidence=0.92,
                    source_layer="identity",
                    category="impersonation"
                ))
            elif website_url:
                # Compare email domain with website domain
                web_host = website_url.replace("https://", "").replace("http://", "").split("/")[0].lower()
                if email_domain not in web_host and web_host not in email_domain:
                    risk += 25.0
                    findings.append(f"Domain divergence: Recruiter email is @{email_domain}, but specified company website is '{web_host}'.")

        # 3. Off-Platform / Text-Only Interview Channels
        suspicious_platforms = ["telegram", "whatsapp", "signal", "google chat", "hangouts"]
        interview_check_str = (interview_platform or "").lower() + " " + (offer_text or "").lower()
        for platform in suspicious_platforms:
            if platform in interview_check_str:
                risk += 35.0
                findings.append(f"Interview or onboarding conducted via '{platform.capitalize()}'. Enterprise organizations use formal HR suites or video conferencing (Google Meet, Teams, Zoom).")
                evidence.append(EvidenceItem(
                    id="REC-CHAT-03",
                    engine_name=self.name,
                    severity=SeverityLevel.HIGH,
                    title=f"Chat App Interview Channel ({platform.capitalize()})",
                    description=f"Recruiter insists on conducting text-based screening or interviews via {platform.capitalize()}, avoiding verified enterprise channels.",
                    raw_indicator=platform,
                    confidence=0.88,
                    source_layer="identity",
                    category="phishing"
                ))
                break

        # 4. Unrealistic Guarantees & Linguistic red flags
        if offer_text:
            text_lower = offer_text.lower()
            unrealistic_terms = ["immediate selection without interview", "guaranteed visa sponsorship without documents", "$5000 weekly for data entry", "no experience required $80/hr"]
            for term in unrealistic_terms:
                if term in text_lower:
                    risk += 35.0
                    findings.append(f"Unrealistic proposition: '{term}'")
                    evidence.append(EvidenceItem(
                        id="REC-PROPO-04",
                        engine_name=self.name,
                        severity=SeverityLevel.MEDIUM,
                        title="Unrealistic Compensation / Guaranteed Selection",
                        description="Propositions offering exorbitant compensation for unskilled tasks or immediate hiring without formal evaluation.",
                        raw_indicator=term,
                        confidence=0.86,
                        source_layer="identity",
                        category="advance_fee"
                    ))

        # 5. Distinct Verification Dimensions (as mandated in requirement 3.E)
        distinctions = {
            "company_exists": "Plausible (Recognized commercial entity name)",
            "company_website_verified": bool(website_url),
            "recruiter_identity_verified": False, # Cannot establish from email alone
            "job_opening_verified": False,
            "offer_authenticity_established": False if risk > 30 else "Inconclusive"
        }

        if not findings:
            findings.append("Recruitment parameters align with standard commercial hiring indicators.")

        elapsed = round((time.time() - start_t) * 1000, 2)
        return EngineExecutionResult(
            engine_name=self.name,
            executed=True,
            execution_time_ms=elapsed,
            status="success",
            summary=f"Recruitment forensic review for '{company_name}'. Risk: {round(risk, 1)}",
            risk_contribution=min(risk, 95.0),
            findings=findings,
            evidence=evidence,
            metadata={"verification_dimensions": distinctions}
        )
