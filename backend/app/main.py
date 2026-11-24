"""
TRUSTLENS GLOBAL - Main FastAPI Application
Enterprise Threat Intelligence Platform Backend
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.models.database import init_db
from app.api.routes import router

# Initialize SQLite database schema
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Global AI-Powered Cybersecurity, Scam Detection & Digital Trust Intelligence Platform",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration for local development and production frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix=settings.API_PREFIX)

@app.get("/")
async def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "tagline": "One Platform. Global Threat Intelligence. Informed Decisions.",
        "status": "online",
        "docs": "/docs",
        "api_prefix": settings.API_PREFIX
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
