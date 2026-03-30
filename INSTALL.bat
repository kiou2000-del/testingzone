@echo off
setlocal
cd /d "%~dp0"
title SBOM Generator - Install

echo.
echo ============================================================
echo   SBOM Generator - Installation Script
echo ============================================================
echo.

:: 1. Check Python
echo [1/5] Checking Python...
where python >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python not found.
    echo Please install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)
python --version
echo [OK] Python is ready.
echo.

:: 2. Install Python packages
echo [2/5] Installing Python packages (streamlit, openpyxl)...
python -m pip install --upgrade pip --quiet
python -m pip install streamlit openpyxl --quiet
if errorlevel 1 (
    echo [WARN] Fast install failed, retrying with verbose...
    python -m pip install streamlit openpyxl
)
echo [OK] Python packages installed.
echo.

:: 3. Check Node.js (Optional but recommended)
echo [3/5] Checking Node.js for cdxgen...
where node >nul 2>&1
if errorlevel 1 (
    echo [INFO] Node.js not found. Will use standalone cdxgen binary.
    goto skip_npm
)
node --version
echo Installing cdxgen via npm...
call npm install -g @cyclonedx/cdxgen --silent 2>nul
if errorlevel 1 (
    echo [WARN] npm install failed. Standalone binary will be used.
) else (
    echo [OK] cdxgen installed via npm.
)
:skip_npm
echo.

:: 4. Download Security Tools
echo [4/5] Downloading security tools (syft, grype, osv-scanner)...
python install_tools.py
echo.

:: 5. Setup Folders
echo [5/5] Creating folders...
if not exist "tools" mkdir tools
if not exist "output" mkdir output
if not exist "saves" mkdir saves
echo [OK] Folders created.
echo.

:: Final Check
echo ============================================================
echo   Installation Results
echo ============================================================
echo.
if exist "tools\syft" (echo   [OK] syft) else (if exist "tools\syft.exe" (echo   [OK] syft) else (echo   [X] syft missing))
if exist "tools\grype" (echo   [OK] grype) else (if exist "tools\grype.exe" (echo   [OK] grype) else (echo   [X] grype missing))
if exist "tools\osv-scanner" (echo   [OK] osv-scanner) else (if exist "tools\osv-scanner.exe" (echo   [OK] osv-scanner) else (echo   [X] osv-scanner missing))
echo.
echo ============================================================
echo   Installation Finished!
echo   Run START.bat to begin scanning.
echo ============================================================
echo.
pause
