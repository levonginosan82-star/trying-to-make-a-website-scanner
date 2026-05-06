@echo off
title Web Vulnerability Scanner
color 0a
cls

echo ============================================
echo    Web Vulnerability Scanner
echo ============================================
echo.

cd /d "%~dp0"

echo [1/3] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo [2/3] Checking dependencies...
pip show streamlit >nul 2>&1
if errorlevel 1 (
    echo [!] Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [!] Failed to install dependencies
        pause
        exit /b 1
    )
)

echo [3/3] Starting Scanner...
echo.
echo The application will open in your browser.
echo Press Ctrl+C in this window to stop the server.
echo.
python -m streamlit run main.py --server.port 8501 --server.headless true