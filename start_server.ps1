# PhishGuard — Quick Start Scripts
# Copy the correct block for your OS into a terminal

# ══════════════════════════════════════════════
# Windows (PowerShell) — run.bat equivalent
# ══════════════════════════════════════════════
# start_server.ps1

Write-Host "🛡️  Starting PhishGuard..." -ForegroundColor Cyan

# Check if server is already running
$existing = Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -eq "" }

Set-Location backend
Start-Process python -ArgumentList "server.py" -WindowStyle Normal
Start-Sleep -Seconds 2

Write-Host "✅ Backend running at http://127.0.0.1:5000" -ForegroundColor Green
Write-Host ""
Write-Host "📂 Open frontend in browser:" -ForegroundColor Yellow
Write-Host "   Start-Process 'http://localhost:3000'" -ForegroundColor White
Write-Host ""
Write-Host "Or serve frontend with:" -ForegroundColor Yellow
Write-Host "   cd ..\frontend && python -m http.server 3000" -ForegroundColor White
