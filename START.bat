@echo off
cd /d "%~dp0"
chcp 65001 >nul 2>&1
title SBOM Generator

:: Add local tools to PATH
set "PATH=%~dp0tools;%PATH%"

echo.
echo ============================================================
echo   SBOM Generator - Starting
echo ============================================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python not found. Run INSTALL.bat first.
    pause
    exit /b 1
)

where streamlit >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Streamlit not found. Run INSTALL.bat first.
    pause
    exit /b 1
)

echo   Tool Status:
where syft >nul 2>&1
if not errorlevel 1 (echo     [OK] Syft) else (echo     [X] Syft)
where cdxgen >nul 2>&1
if not errorlevel 1 (echo     [OK] cdxgen) else (echo     [X] cdxgen)
where osv-scanner >nul 2>&1
if not errorlevel 1 (echo     [OK] osv-scanner) else (echo     [X] osv-scanner)
where depscan >nul 2>&1
if not errorlevel 1 (echo     [OK] dep-scan) else (echo     [X] dep-scan)
echo.
echo   Browser will open automatically.
echo   Stop: Ctrl+C
echo ============================================================
echo.

streamlit run app.py --server.port 8501 --browser.gatherUsageStats false

echo.
echo   Stopped.
pause
