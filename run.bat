@echo off
cd /d "%~dp0"

>nul 2>&1 fsutil dirty query %systemdrive%
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
)

.venv\Scripts\python.exe run.py
if %errorlevel% neq 0 pause
