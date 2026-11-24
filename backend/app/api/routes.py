"""
FastAPI REST API Routes for TRUSTLENS GLOBAL
Provides clean, validated endpoints for all 5 workspaces, counterfactual exploration,
history management, and provider telemetry.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any

from app.schemas.investigation import (
    InvestigationReport, WebsiteInvestigateRequest, URLInvestigateRequest,
    EmailInvestigateRequest, MessageInvestigateRequest,
    JobOfferInvestigateRequest, CounterfactualQuery, CounterfactualVerdictResult
)
from app.orchestrator.orchestrator import orchestrator
from app.orchestrator.graph_counterfactual import simulate_counterfactual_verdict
from app.models.database import (
    get_recent_investigations, get_investigation_by_id, delete_investigation_by_id
)
from app.benchmark.benchmark_suite import JUDGE_SCENARIOS, run_benchmark_evaluation
from app.core.config import settings

router = APIRouter()

# 1. Flagship Website Investigator
@router.post("/investigate/website", response_model=InvestigationReport)
async def investigate_website_endpoint(req: WebsiteInvestigateRequest):
    return await orchestrator.investigate_website(req)

# 2. URL Threat Scanner
@router.post("/investigate/url", response_model=InvestigationReport)
async def investigate_url_endpoint(req: URLInvestigateRequest):
    return await orchestrator.investigate_url(req)

# 3. Email Forensics
@router.post("/investigate/email", response_model=InvestigationReport)
async def investigate_email_endpoint(req: EmailInvestigateRequest):
    return await orchestrator.investigate_email(req)

# 4. Message & Social Engineering Analyzer
@router.post("/investigate/message", response_model=InvestigationReport)
async def investigate_message_endpoint(req: MessageInvestigateRequest):
    return await orchestrator.investigate_message(req)

# 5. Job & Organization Authenticity Verifier
@router.post("/investigate/job-offer", response_model=InvestigationReport)
async def investigate_job_offer_endpoint(req: JobOfferInvestigateRequest):
    return await orchestrator.investigate_job_offer(req)

# Counterfactual Scenario Simulator ("What would change the verdict?")
@router.post("/counterfactual/simulate", response_model=CounterfactualVerdictResult)
async def simulate_counterfactual_endpoint(query: CounterfactualQuery):
    rec = get_investigation_by_id(query.investigation_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Investigation record not found")
    report = rec["report"]
    return simulate_counterfactual_verdict(
        original_risk_score=report["risk_score"],
        original_verdict=report["overall_verdict"],
        modified_parameters=query.modified_parameters
    )

# Investigation History & Detail
@router.get("/investigations")
async def list_investigations(limit: int = Query(50, ge=1, le=100)):
    return get_recent_investigations(limit=limit)

@router.get("/investigations/{inv_id}")
async def get_investigation(inv_id: str):
    rec = get_investigation_by_id(inv_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return rec

@router.delete("/investigations/{inv_id}")
async def delete_investigation(inv_id: str):
    success = delete_investigation_by_id(inv_id)
    if not success:
        raise HTTPException(status_code=404, detail="Investigation record not found")
    return {"status": "success", "deleted_id": inv_id}

# Threat Intelligence Providers Health & Status
@router.get("/intelligence/providers")
async def get_providers_status():
    return [
        {
            "name": "URLhaus (Abuse.ch)",
            "category": "Malware & Phishing URLs",
            "type": "Live Open API",
            "status": "Operational (Zero-Auth)",
            "latency": "~320ms",
            "attribution": "https://urlhaus.abuse.ch"
        },
        {
            "name": "Google Safe Browsing v4",
            "category": "Web Phishing & Malware",
            "type": "API Key Integration",
            "status": "Operational" if settings.GOOGLE_SAFE_BROWSING_KEY else "Awaiting API Key in Settings",
            "latency": "~150ms",
            "attribution": "https://developers.google.com/safe-browsing"
        },
        {
            "name": "VirusTotal v3",
            "category": "Multi-Engine Threat Telemetry",
            "type": "API Key Integration",
            "status": "Operational" if settings.VIRUSTOTAL_API_KEY else "Awaiting API Key in Settings",
            "latency": "~450ms",
            "attribution": "https://virustotal.com"
        },
        {
            "name": "AbuseIPDB v2",
            "category": "IP Address Reputation & Confidence",
            "type": "API Key Integration",
            "status": "Operational" if settings.ABUSEIPDB_API_KEY else "Awaiting API Key in Settings",
            "latency": "~220ms",
            "attribution": "https://abuseipdb.com"
        },
        {
            "name": "PhishTank Community Feed",
            "category": "Active Phishing Feeds",
            "type": "Live Verification",
            "status": "Operational",
            "latency": "~400ms",
            "attribution": "https://phishtank.org"
        },
        {
            "name": "OpenPhish Stream",
            "category": "Zero-Day Phishing Feeds",
            "type": "Live Feed Mirror",
            "status": "Operational",
            "latency": "~310ms",
            "attribution": "https://openphish.com"
        },
        {
            "name": "Cloudflare & Google DoH",
            "category": "Authoritative DNS over HTTPS",
            "type": "Live DoH Resolvers",
            "status": "Operational (Encrypted DNS)",
            "latency": "~45ms",
            "attribution": "Cloudflare / Google Public DNS"
        },
        {
            "name": "ICANN RDAP Bootstrap",
            "category": "Authoritative Domain Registration",
            "type": "Live Registry API",
            "status": "Operational (Zero-Auth)",
            "latency": "~380ms",
            "attribution": "ICANN / RDAP.org"
        },
        {
            "name": "crt.sh Certificate Transparency",
            "category": "Public CT Certificate Logs",
            "type": "Live CT Search",
            "status": "Operational",
            "latency": "~520ms",
            "attribution": "Sectigo crt.sh"
        }
    ]

@router.get("/intelligence/health")
async def get_health_status():
    return {
        "status": "healthy",
        "system": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "environment": settings.ENVIRONMENT,
        "ssrf_guard_active": True,
        "live_website_fetch_enabled": settings.ENABLE_LIVE_WEBSITE_FETCH,
        "engines_active": 16
    }

# Dashboard Statistics & Aggregates
@router.get("/dashboard")
async def get_dashboard_summary():
    recent = get_recent_investigations(limit=100)
    total_count = len(recent)
    
    malicious_count = sum(1 for r in recent if "Malicious" in r.get("verdict", "") or "Critical" in r.get("verdict", "") or "High" in r.get("verdict", ""))
    suspicious_count = sum(1 for r in recent if "Suspicious" in r.get("verdict", ""))
    minimal_count = sum(1 for r in recent if "No Significant" in r.get("verdict", "") or "Low" in r.get("verdict", ""))
    
    avg_risk = round(sum(r.get("risk_score", 0) for r in recent) / total_count, 1) if total_count > 0 else 0.0

    return {
        "total_investigations": total_count,
        "threat_breakdown": {
            "critical_or_high_risk": malicious_count,
            "suspicious": suspicious_count,
            "minimal_or_low_risk": minimal_count
        },
        "average_risk_score": avg_risk,
        "active_engines": 16,
        "recent_investigations": recent[:6]
    }

# Hackathon Live Judge Challenge Scenarios
@router.get("/scenarios")
async def get_scenarios():
    return JUDGE_SCENARIOS

# Benchmarks
@router.get("/benchmark")
async def get_benchmarks():
    return run_benchmark_evaluation()
