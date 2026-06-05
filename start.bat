@echo off
title ESurfingDialer-Pro

:: Check Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Install from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Starting ESurfingDialer-Pro in system tray...
echo Check the notification area (bottom-right) for the icon.
echo.
echo Green  = online
echo Yellow = authenticating
echo Red    = offline
echo.
echo Right-click the icon to see status or exit.
echo.

cd /d "%~dp0"
python -m esurfing_pro.main daemon --mode net --tray

pause
