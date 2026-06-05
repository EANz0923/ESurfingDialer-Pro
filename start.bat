@echo off
chcp 65001 >nul
title ESurfingDialer-Pro

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo Python not found. Please install from https://mirrors.tuna.tsinghua.edu.cn/python/3.13.3/python-3.13.3-amd64.exe
    pause
    exit /b 1
)

python -c "import requests" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing dependencies...
    pip install -r "%~dp0requirements.txt" -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn
)

cd /d "%~dp0"
python -m esurfing_pro.main daemon --mode net --tray
pause
