@echo off
chcp 65001 >nul
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "BAT=%STARTUP%\ESurfingDialer-Pro.bat"
set "VBS=%STARTUP%\ESurfingDialer-Pro.vbs"

set "DELETED=0"
if exist "%BAT%" (
    del /Q "%BAT%"
    echo [OK] Removed: ESurfingDialer-Pro.bat
    set "DELETED=1"
)
if exist "%VBS%" (
    del /Q "%VBS%"
    echo [OK] Removed: ESurfingDialer-Pro.vbs
    set "DELETED=1"
)
if "%DELETED%"=="0" (
    echo [INFO] No autostart entry found. Already clean.
)
pause
