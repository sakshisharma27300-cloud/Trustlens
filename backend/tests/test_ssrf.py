"""
SSRF Protection Unit Tests
Verifies that forbidden IP ranges, metadata endpoints, loopback,
and restricted ports are reliably rejected.
"""
import pytest
from app.core.ssrf_guard import validate_target_url, resolve_and_verify_ip, SSRFSecurityException

def test_ssrf_rejects_localhost():
    with pytest.raises(SSRFSecurityException):
        validate_target_url("http://localhost:8000/internal")

def test_ssrf_rejects_cloud_metadata():
    with pytest.raises(SSRFSecurityException):
        validate_target_url("http://169.254.169.254/latest/meta-data/")

def test_ssrf_rejects_restricted_ports():
    with pytest.raises(SSRFSecurityException):
        validate_target_url("http://example.com:22/ssh")
    with pytest.raises(SSRFSecurityException):
        validate_target_url("http://example.com:3306/db")

def test_ssrf_permits_standard_public_urls():
    url, host, port = validate_target_url("https://www.example.com/login")
    assert host == "www.example.com"
    assert port == 443
