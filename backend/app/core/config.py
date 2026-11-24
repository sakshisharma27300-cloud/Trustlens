"""
TRUSTLENS GLOBAL Configuration & Settings
Manages live threat intelligence API credentials, safe fetch controls, timeouts,
and system parameters with graceful fallbacks when keys are not configured.
"""
from typing import Optional, List
from pydantic import BaseModel
import os

class Settings(BaseModel):
    PROJECT_NAME: str = "TRUSTLENS GLOBAL"
    PROJECT_VERSION: str = "2.4.0-enterprise"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    API_PREFIX: str = "/api/v1"
    
    # Storage
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./trustlens.db")
    
    # Safe Website Content Fetching & SSRF Protection
    ENABLE_LIVE_WEBSITE_FETCH: bool = os.getenv("ENABLE_LIVE_WEBSITE_FETCH", "true").lower() in ("true", "1")
    FETCH_TIMEOUT_SECONDS: float = 6.0
    FETCH_MAX_BYTES: int = 1024 * 1024  # 1MB limit to avoid DoS
    FETCH_MAX_REDIRECTS: int = 4
    BLOCKED_PORTS: List[int] = [22, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 6379, 8080, 9200, 27017]
    
    # Threat Intelligence Providers (Optional API Keys with truthful degraded mode)
    GOOGLE_SAFE_BROWSING_KEY: Optional[str] = os.getenv("GOOGLE_SAFE_BROWSING_KEY", None)
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY", None)
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY", None)
    URLSCAN_API_KEY: Optional[str] = os.getenv("URLSCAN_API_KEY", None)
    
    # Public & Open Intelligence endpoints (Zero-auth default live lookups)
    URLHAUS_API_URL: str = "https://urlhaus-api.abuse.ch/v1/url/"
    PHISHTANK_ONLINE_FEED_URL: str = "https://data.phishtank.com/data/online-valid.json"
    OPENPHISH_COMMUNITY_FEED: str = "https://openphish.com/feed.txt"
    RDAP_BOOTSTRAP_URL: str = "https://rdap.org/domain/"
    CLOUDFLARE_DOH_URL: str = "https://cloudflare-dns.com/dns-query"
    GOOGLE_DOH_URL: str = "https://dns.google/resolve"
    CRT_SH_URL: str = "https://crt.sh/"

settings = Settings()
