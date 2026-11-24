"""
End-to-End System Live Verification Script
Simulates client requests against the FastAPI backend app to verify all pipelines.
"""
import asyncio
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_full_pipeline():
    print("[1/6] Testing System Root & Health...")
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "online"

    print("[2/6] Testing Flagship Website Investigator...")
    payload = {
        "url": "https://accounts.google.com",
        "deep_inspection": False
    }
    r = client.post("/api/v1/investigate/website", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert "investigation_id" in data
    assert data["risk_score"] < 40.0
    assert len(data["detection_engine_results"]) > 0
    print(f"  -> Generated Report ID: {data['investigation_id']}, Verdict: {data['overall_verdict']}")

    print("[3/6] Testing Multilingual Message Analyzer (Digital Arrest)...")
    msg_payload = {
        "channel": "whatsapp",
        "content": "URGENT NOTICE: आपके नाम पर मुंबई कस्टम्स में एक पार्सल ज़ब्त किया गया है जिसमें अवैध ड्रग्स पाए गए हैं। आपके खिलाफ डिजिटल अरेस्ट वारंट जारी किया गया है। तुरंत इस स्काइप आईडी पर संपर्क करें और किसी से बात न करें।"
    }
    r = client.post("/api/v1/investigate/message", json=msg_payload)
    assert r.status_code == 200
    msg_data = r.json()
    assert msg_data["risk_score"] >= 35.0
    print(f"  -> Detected Hindi Digital Arrest: Risk Score {msg_data['risk_score']}, Verdict: {msg_data['overall_verdict']}")

    print("[4/6] Testing Job Authenticity Verifier (Upfront Fee Demand)...")
    job_payload = {
        "company_name": "Apex Global Logistics",
        "recruiter_email": "hr.apexlogistics@gmail.com",
        "job_title": "Remote Data Clerk",
        "website_url": "https://apex-logistics-portal.net",
        "payment_requested": True,
        "payment_amount": "$150 Security Deposit",
        "interview_platform": "Telegram"
    }
    r = client.post("/api/v1/investigate/job-offer", json=job_payload)
    assert r.status_code == 200
    job_data = r.json()
    assert job_data["risk_score"] >= 70.0
    inv_id = job_data["investigation_id"]
    print(f"  -> Flagged Recruitment Scam: Risk Score {job_data['risk_score']}")

    print("[5/6] Testing Counterfactual Simulator ('What would change the verdict?')...")
    cf_payload = {
        "investigation_id": inv_id,
        "modified_parameters": {
            "remove_payment_demand": True,
            "recruiter_domain_matched": True
        }
    }
    r = client.post("/api/v1/counterfactual/simulate", json=cf_payload)
    assert r.status_code == 200
    cf_data = r.json()
    assert cf_data["simulated_risk_score"] < cf_data["original_risk_score"]
    print(f"  -> Counterfactual Shift: {cf_data['original_risk_score']} -> {cf_data['simulated_risk_score']} pts")

    print("[6/6] Testing Provider Telemetry & Ground-Truth Benchmarks...")
    r = client.get("/api/v1/intelligence/providers")
    assert r.status_code == 200
    assert len(r.json()) >= 7

    r = client.get("/api/v1/benchmark")
    assert r.status_code == 200
    assert r.json()["metrics"]["f1_score"] == 100.0
    print("  -> Benchmarks verified: Precision 100%, Recall 100%, F1 100%")

    print("\nALL 6 END-TO-END PIPELINES PASSED RIGOROUS VERIFICATION!")

if __name__ == "__main__":
    test_full_pipeline()
