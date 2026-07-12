@echo off
cd /d "%~dp0"
echo [LLM Shield] Stopping proxy...

python toggle_proxy.py off

docker compose down 2>nul
if %errorlevel% neq 0 (
    docker-compose down 2>nul
)
docker stop llm-shield 2>nul
docker rm llm-shield 2>nul

echo [LLM Shield] Proxy stopped. System proxy cleared. CA removed.
pause
