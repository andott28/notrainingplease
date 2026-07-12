@echo off
cd /d "%~dp0"
echo [LLM Shield] Starting proxy...

docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [LLM Shield] Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

python start.py %*
