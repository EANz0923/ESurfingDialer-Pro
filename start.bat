@echo off
title ESurfingDialer-Pro

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo Python not found. Please install from https://www.python.org/downloads/
    pause
    exit /b 1
)

python -c "import requests" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing dependencies...
    pip install -r "%~dp0requirements.txt"
)

cd /d "%~dp0"
python -m esurfing_pro.main daemon --mode net --tray
pause
