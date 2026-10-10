@echo off
echo ===================================================
echo   LOGSHIELD — AI Security Platform (v0.5)
echo ===================================================
echo Starting FastAPI Backend Server and Simulator...
echo.

cd /d "%~dp0"

start "LogShield Backend Server" cmd /k "python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"
timeout /t 2 >nul
start "LogShield Simulator GUI" cmd /k "python simulator/simulator.py"

echo.
echo LogShield Backend available at: http://127.0.0.1:8000
echo.
