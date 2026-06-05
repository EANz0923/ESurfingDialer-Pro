@echo off
title ESurfingDialer-Pro Setup

echo.
echo    ======================================
echo      ESurfingDialer-Pro  Setup
echo    ======================================
echo.

:: --- Check Python, auto-install if missing ---
where python >nul 2>&1
if %errorlevel% equ 0 goto :python_ok

echo    Python not found. Trying to install automatically...
echo.

:: Method 1: winget (Windows 10/11 built-in)
where winget >nul 2>&1
if %errorlevel% equ 0 (
    echo    Installing Python via winget (may take a few minutes)...
    winget install Python.Python.3.12 --silent --accept-package-agreements
    if %errorlevel% equ 0 (
        echo    [OK] Python installed!
        echo    Please RESTART this setup.bat after the terminal refreshes.
        pause
        exit /b 0
    )
)

:: Method 2: download installer
echo    winget not available, downloading Python installer...
curl -L -o "%TEMP%\python-installer.exe" "https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe" 2>nul
if exist "%TEMP%\python-installer.exe" (
    echo    Running Python installer...
    echo    Please follow the installer window.
    echo    IMPORTANT: Check "Add Python to PATH" !!!
    start /wait "" "%TEMP%\python-installer.exe"
    del "%TEMP%\python-installer.exe"
    echo.
    echo    After install completes, RESTART this setup.bat.
    pause
    exit /b 0
)

:: Method 3: give up
echo    [FAIL] Could not install Python automatically.
echo.
echo    Please install manually:
echo      1. https://www.python.org/downloads/
echo      2. Download + run installer
echo      3. CHECK "Add Python to PATH" !!!
echo      4. Re-run this setup.bat
echo.
pause
exit /b 1

:python_ok
echo    [OK] Python found
python --version
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
