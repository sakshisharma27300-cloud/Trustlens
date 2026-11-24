"""
Detection Engine Unit Tests
Tests URL structural analysis, brand impersonation, email forensics,
social engineering, recruitment fraud, and risk fusion.
"""
import pytest
from app.engines.url_structure_engine import NormalizationEngine, URLStructuralEngine
from app.engines.website_brand_engines import BrandImpersonationEngine
from app.engines.email_forensics_engine import EmailForensicsEngine
from app.engines.social_recruitment_engines import SocialEngineeringEngine, RecruitmentFraudEngine
from app.schemas.engines import SeverityLevel
from app.schemas.investigation import VerdictCategory
from app.orchestrator.graph_counterfactual import simulate_counterfactual_verdict

def test_normalization_punycode():
    engine = NormalizationEngine()
    res, norm_url, meta = engine.run("http://xn--pypal-4ve.com/login")
    assert meta["is_punycode"] is True
    assert any("Punycode" in f for f in res.findings)

def test_url_structural_credentials_and_ip():
    engine = URLStructuralEngine()
    res = engine.run("http://google.com@attacker-portal.net/login")
    assert res.risk_contribution > 50.0
    assert any("embedded '@'" in f for f in res.findings)

def test_brand_impersonation_detection():
    engine = BrandImpersonationEngine()
    # Brand embedded in unrelated domain
    res = engine.run("paypal-account-security-update.com")
    assert res.risk_contribution > 50.0
    assert any(e.severity == SeverityLevel.CRITICAL for e in res.evidence)

def test_email_forensics_spf_dkim_failure():
    engine = EmailForensicsEngine()
    raw_headers = (
        "From: Security Team <service@bank.com>\n"
        "Reply-To: phisher99@yandex.com\n"
        "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
    )
    res = engine.run(
        email_address="service@bank.com",
        sender_name="Security Team",
        raw_headers=raw_headers
    )
    assert res.risk_contribution > 50.0
    assert res.metadata["spf_status"] == "FAIL"
    assert res.metadata["dkim_status"] == "FAIL"

def test_social_engineering_digital_arrest():
    engine = SocialEngineeringEngine()
    msg = "Police department notice: You are under digital arrest warrant for money laundering. Stay on video call."
    res = engine.run(msg)
    assert res.risk_contribution > 60.0
    assert any("Digital Arrest" in f for f in res.findings)

def test_recruitment_fraud_upfront_fee():
    engine = RecruitmentFraudEngine()
    res = engine.run(
        company_name="Apex Logistics",
        recruiter_email="hiring.apex@gmail.com",
        payment_requested=True,
        payment_amount="$200 Equipment Deposit",
        interview_platform="Telegram"
    )
    assert res.risk_contribution > 70.0
    assert any(e.severity == SeverityLevel.CRITICAL for e in res.evidence)

def test_counterfactual_simulation():
    res = simulate_counterfactual_verdict(
        original_risk_score=85.0,
        original_verdict=VerdictCategory.CRITICAL_RISK,
        modified_parameters={"remove_payment_demand": True}
    )
    assert res.simulated_risk_score < 85.0
    assert len(res.divergent_factors) > 0
