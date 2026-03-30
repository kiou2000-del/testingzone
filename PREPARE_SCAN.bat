@echo off
setlocal
cd /d "%~dp0"
title SBOM Generator - Prepare Scan

echo.
echo ============================================================
echo   SBOM Generator - Prepare Project Dependencies
echo ============================================================
echo.

if "%~1"=="" (
    echo [USAGE] PREPARE_SCAN.bat <target_project_path>
    echo.
    set /p "target=Enter target project path: "
) else (
    set "target=%~1"
)

if not exist "%target%" (
    echo [ERROR] Target path not found: %target%
    pause
    exit /b 1
)

echo Target: %target%
echo.
echo [1/1] Running preparation script...
python prepare_scan.py "%target%"

echo.
echo ============================================================
echo   Preparation finished.
echo ============================================================
echo.
pause
