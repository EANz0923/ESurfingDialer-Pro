@echo off
chcp 65001 >nul
title ESurfingDialer-Pro 首次配置

echo.
echo    ======================================
echo      ESurfingDialer-Pro  首次配置
echo    ======================================
echo.
echo    [1/2] 检查 Python 依赖...
pip install -r requirements.txt -q 2>nul
echo    [OK] 依赖就绪
echo.
echo    [2/2] 启动配置向导...
echo.

python -m esurfing_pro.main setup

pause
