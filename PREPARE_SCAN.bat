@echo off
chcp 65001 > nul
title SBOM 사전 준비 도구 (취약점 보존 모드)

echo ===================================================
echo  🛡️ 스캔 대상 프로젝트 사전 패키지 설치 스크립트
echo  [특수 모드] NPM 자동 패치 차단 / 원본 버전 보존
echo  [모노레포] 하위 디렉토리 자동 탐색
echo ===================================================
echo.

:: 드래그 앤 드롭으로 받은 경로
set TARGET_DIR=%~1

if "%TARGET_DIR%" == "" goto INPUT_DIR
goto CHECK_DIR

:INPUT_DIR
set /p TARGET_DIR="👉 타겟 폴더 경로를 끌어다 놓거나 붙여넣으세요: "
set TARGET_DIR=%TARGET_DIR:"=%

:CHECK_DIR
if "%TARGET_DIR%" == "" (
    echo ❌ 경로가 입력되지 않았습니다.
    pause
    exit /b
)

if not exist "%TARGET_DIR%" (
    echo ❌ 해당 경로를 찾을 수 없습니다: "%TARGET_DIR%"
    pause
    exit /b
)

echo 📂 분석 대상: "%TARGET_DIR%"
echo.

:: Python prepare_scan 모듈 호출 (하위 디렉토리 재귀 탐색 포함)
python -c "import sys; sys.path.insert(0, r'%~dp0'); from prepare_scan import prepare_scan; r = prepare_scan(r'%TARGET_DIR%', line_callback=print); print(); print(r.message)"

echo.
echo ===================================================
echo 🎉 작업 완료! 이제 대시보드에서 분석을 돌려 진짜 취약점을 확인하세요.
echo ===================================================
pause
