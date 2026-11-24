@echo off
echo ==========================================================
echo   Starting TRUSTLENS GLOBAL Threat Intelligence Platform
echo ==========================================================

start "TrustLens Backend" cmd /k "cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
start "TrustLens Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo Services launched!
echo Frontend: http://localhost:5173
echo Backend API: http://localhost:8000
echo Swagger Docs: http://localhost:8000/docs
echo.
pause
