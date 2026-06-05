@echo off
chcp 65001 >nul
title ESurfingDialer-Pro Setup

echo.
echo    ======================================
echo      ESurfingDialer-Pro  Setup
echo    ======================================
echo.

:: --- Check Python ---
where python >nul 2>&1
if %errorlevel% equ 0 goto :python_ok

echo    [ERROR] Python is not installed!
echo.
echo    A step-by-step guide will open now.
echo    Follow it to install Python, then re-run this setup.bat.
echo.
start "" "%~dp0安装Python指南.txt"
pause
exit /b 1

:python_ok
echo    [OK] Python found
echo.

:: --- Install dependencies (using Tsinghua mirror for speed) ---
echo    [1/2] Installing dependencies (Tsinghua mirror)...
pip install -r "%~dp0requirements.txt" -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn
if %errorlevel% neq 0 (
    echo.
    echo    [FAIL] Dependency install failed.
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
