# TRUSTLENS GLOBAL - Run Script for Windows PowerShell
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Starting TRUSTLENS GLOBAL Threat Intelligence Platform  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Start FastAPI Backend in background job
Write-Host "`n[1/2] Launching Backend on http://localhost:8000..." -ForegroundColor Green
$BackendProcess = Start-Process -FilePath "python" -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000" -WorkingDirectory "$PSScriptRoot\backend" -PassThru

# 2. Start Vite Frontend
Write-Host "[2/2] Launching Frontend on http://localhost:5173..." -ForegroundColor Green
Start-Process -FilePath "npm" -ArgumentList "run dev" -WorkingDirectory "$PSScriptRoot\frontend"

Write-Host "`nServices Started!" -ForegroundColor Yellow
Write-Host "  Frontend: http://localhost:5173" -ForegroundColor White
Write-Host "  Backend API: http://localhost:8000" -ForegroundColor White
Write-Host "  API Docs (Swagger): http://localhost:8000/docs" -ForegroundColor White
Write-Host "`nPress Ctrl+C or close windows to terminate." -ForegroundColor Gray
