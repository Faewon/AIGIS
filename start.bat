@echo off
cd /d "%~dp0"
title AIGIS — Adversarial Intelligence for Generative Immunity ^& Security
echo =====================================================================
echo  AIGIS: Dual-Agent Adversarial Wargame Engine
echo  Adversarial Intelligence for Generative Immunity ^& Security
echo =====================================================================
echo.
echo [1/2] Dang kiem tra moi truong Python...
python -c "import fastapi, uvicorn, multipart, httpx" 2>nul
if %errorlevel% neq 0 (
    echo [!] Dang cai dat thu vien phu thuoc...
    pip install -r requirements.txt
)

echo.
echo [2/2] Khoi dong Server tai http://127.0.0.1:8000 ...
python run_server.py
pause
