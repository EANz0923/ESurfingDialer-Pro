@echo off
title ESurfingDialer-Pro Setup

echo.
echo    ======================================
echo      ESurfingDialer-Pro  Setup
echo    ======================================
echo.

:: --- Check Python ---
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo    [ERROR] Python is not installed!
    echo.
    echo    Please install Python first:
    echo      1. Open https://www.python.org/downloads/
    echo      2. Download the latest version
    echo      3. Run the installer
    echo      4. CHECK "Add Python to PATH" !!!
    echo      5. Re-run this setup.bat
    echo.
    pause
    exit /b 1
)
echo    [OK] Python found
echo.

:: --- Install dependencies ---
echo    [1/2] Installing dependencies...
pip install -r "%~dp0requirements.txt"
if %errorlevel% neq 0 (
    echo.
    echo    [FAIL] Dependency install failed.
    echo    Try running: pip install -r requirements.txt
    pause
    exit /b 1
)
echo    [OK] Dependencies ready
echo.

:: --- Run setup wizard ---
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
