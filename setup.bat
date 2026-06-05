@echo off
title ESurfingDialer-Pro Setup

echo.
echo    ======================================
echo      ESurfingDialer-Pro  Setup
echo    ======================================
echo.

echo    [1/2] Installing Python dependencies...
echo.
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo    [FAIL] Dependency install failed!
    echo    Make sure Python and pip are installed:
    echo      https://www.python.org/downloads/
    echo    Check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)
echo.
echo    [OK] Dependencies ready
echo.

echo    [2/2] Starting setup wizard...
echo.

python -m esurfing_pro.main setup
if %errorlevel% neq 0 (
    echo.
    echo    [FAIL] Setup failed. See error above.
    pause
    exit /b 1
)

pause
