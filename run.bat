@echo off
chcp 65001 >nul 2>&1
echo ========================================
echo   MC Scanner - Server Scanner and Warning Bot
echo ========================================
echo.
echo Usage:
echo   run.bat scan TARGET      Scan + SLP probe
echo   run.bat warn TARGET      Scan + send warnings
echo   run.bat portscan TARGET  Port scan only
echo   run.bat web              Start web panel
echo.
echo Examples:
echo   run.bat warn 1.2.3.0/24
echo   run.bat warn -f targets.txt
echo   run.bat scan 1.2.3.4
echo   run.bat web
echo.
if "%~1"=="" (
    echo No arguments. Example: run.bat warn 1.2.3.0/24
    pause
    exit /b
)
if "%~1"=="web" (
    python web.py
    pause
    exit /b
)
python main.py %*
echo.
pause
