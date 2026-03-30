#!/bin/zsh

# 현재 스크립트 위치로 이동
cd "$(dirname "$0")"

echo "🔧 Installing SBOM Generator Dependencies for macOS..."
echo "----------------------------------------------------"

# 1. Python 패키지 설치
echo "[1/3] Installing Python packages (streamlit, openpyxl, etc.)..."
python3 -m pip install streamlit openpyxl --quiet

# 2. 분석 도구 자동 다운로드
echo "[2/3] Downloading security tools (Syft, Grype, etc.)..."
python3 install_tools.py

# 3. 폴더 생성
echo "[3/3] Setting up folders..."
mkdir -p tools output saves

# 스크립트 실행 권한 부여
chmod +x START.sh

echo "----------------------------------------------------"
echo "✅ Installation Finished!"
echo "Use './START.sh' to run the dashboard."
