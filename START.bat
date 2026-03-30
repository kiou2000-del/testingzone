@echo off
setlocal
cd /d "%~dp0"
title SBOM Generator - Dashboard

:: Add tools to PATH for the session
set "PATH=%~dp0tools;%PATH%"

echo.
echo Starting SBOM Generator Dashboard...
echo Please wait while Streamit initializes.
echo.

:: Check for streamlit
where streamlit >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Streamlit not found.
    echo Running "INSTALL.bat" first is recommended.
    echo Trying to run via python module...
    python -m streamlit run app.py
) else (
    streamlit run app.py
)

if errorlevel 1 (
    echo.
    echo [CRITICAL] Failed to start. 
    echo Check if Python and streamlit are installed correctly.
    pause
)
