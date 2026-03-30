@echo off
cd /d "%~dp0"
chcp 65001 >nul 2>&1
title SBOM Generator - Install

echo.
echo ============================================================
echo   SBOM Generator v2.2.0 - One-Click Install
echo ============================================================
echo.

:: ──────────────────────────────────────────
:: 1. Python 확인
:: ──────────────────────────────────────────
echo [1/5] Python 확인 중...
where python >nul 2>&1
if errorlevel 1 (
    echo.
    echo   [FAIL] Python이 설치되어 있지 않습니다.
    echo.
    echo   설치 방법:
    echo     1. https://www.python.org/downloads/ 접속
    echo     2. Python 3.10 이상 다운로드
    echo     3. 설치 시 "Add Python to PATH" 반드시 체크
    echo     4. 설치 완료 후 이 스크립트 다시 실행
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo   %%i
echo   [OK] Python 확인 완료
echo.

:: ──────────────────────────────────────────
:: 2. pip 패키지 설치
:: ──────────────────────────────────────────
echo [2/5] Python 패키지 설치 중...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install streamlit openpyxl --quiet
if errorlevel 1 (
    echo   [WARN] 일부 패키지 설치 실패 - 다시 시도합니다...
    python -m pip install streamlit openpyxl
)
echo   [OK] streamlit, openpyxl 설치 완료
echo.

:: ──────────────────────────────────────────
:: 3. Node.js + cdxgen (npm)
:: ──────────────────────────────────────────
echo [3/5] Node.js / cdxgen 확인 중...
where node >nul 2>&1
if errorlevel 1 (
    echo   [INFO] Node.js 미설치 - cdxgen은 독립 exe로 설치됩니다
    echo   [TIP]  더 안정적인 cdxgen 사용을 위해 Node.js LTS 설치를 권장합니다
    echo          https://nodejs.org/
    goto skip_npm
)
for /f "tokens=*" %%i in ('node --version 2^>^&1') do echo   Node.js %%i
echo   cdxgen npm 설치/업데이트 중...
call npm install -g @cyclonedx/cdxgen --silent 2>nul
if errorlevel 1 (
    echo   [WARN] npm 설치 실패 - 독립 exe로 대체됩니다
) else (
    echo   [OK] cdxgen npm 설치 완료
)
:skip_npm
echo.

:: ──────────────────────────────────────────
:: 4. 분석 도구 자동 다운로드 (GitHub)
:: ──────────────────────────────────────────
echo [4/5] 분석 도구 다운로드 중 (GitHub Releases)...
echo   - syft.exe       (SBOM 생성)
echo   - grype.exe      (CVE 스캔 - 권장)
echo   - osv-scanner.exe (CVE 스캔 - 보조)
echo   - cdxgen.exe     (SBOM 생성 - Node.js 없을 때)
echo.
python install_tools.py
echo.

:: ──────────────────────────────────────────
:: 5. 폴더 생성 + PATH 설정
:: ──────────────────────────────────────────
echo [5/5] 환경 설정 중...
if not exist "tools" mkdir tools
if not exist "output" mkdir output
if not exist "saves" mkdir saves

:: tools 폴더를 PATH에 추가 (현재 세션)
set "PATH=%~dp0tools;%PATH%"

echo   [OK] 폴더 생성 완료
echo.

:: ──────────────────────────────────────────
:: 설치 결과 확인
:: ──────────────────────────────────────────
echo ============================================================
echo   설치 결과
echo ============================================================
echo.
echo   [SBOM 생성 도구]
where syft >nul 2>&1
if not errorlevel 1 (echo     [OK] syft) else (echo     [X] syft - 수동 설치 필요)
where cdxgen >nul 2>&1
if not errorlevel 1 (echo     [OK] cdxgen) else (
    if exist "%~dp0tools\cdxgen.exe" (echo     [OK] cdxgen ^(독립 exe^)) else (echo     [X] cdxgen - 수동 설치 필요)
)
echo.
echo   [CVE 스캔 도구]
where grype >nul 2>&1
if not errorlevel 1 (echo     [OK] grype) else (
    if exist "%~dp0tools\grype.exe" (echo     [OK] grype ^(tools 폴더^)) else (echo     [X] grype - 수동 설치 필요)
)
where osv-scanner >nul 2>&1
if not errorlevel 1 (echo     [OK] osv-scanner) else (
    if exist "%~dp0tools\osv-scanner.exe" (echo     [OK] osv-scanner ^(tools 폴더^)) else (echo     [X] osv-scanner - 수동 설치 필요)
)
echo.
echo ============================================================
echo   설치 완료!
echo.
echo   사용 방법:
echo     1. START.bat 더블클릭 (대시보드 실행)
echo     2. 프로젝트 경로 입력 후 "분석" 클릭
echo.
echo   첫 실행 시 grype 취약점 DB 다운로드에 1~2분 소요됩니다.
echo ============================================================
echo.
pause
