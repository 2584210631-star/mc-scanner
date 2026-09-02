@echo off
chcp 65001 >nul 2>&1
title MC Scanner v3
echo ========================================
echo   MC Scanner v3 - Web Control Panel
echo ========================================
echo.
echo Starting web panel at http://127.0.0.1:8080
echo.
python web.py 8080
if errorlevel 1 (
    echo.
    echo Python not found. Please install Python 3.8+ first.
    echo Download: https://www.python.org/downloads/
    echo.
)
pause
