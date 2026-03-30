#!/bin/zsh

# 현재 스크립트 위치로 이동
cd "$(dirname "$0")"

# 프로젝트 로컬 tools 폴더를 PATH에 추가
export PATH="$PWD/tools:$PATH"

echo "🛡️ Starting SBOM Generator Dashboard on Mac Mini..."
echo "----------------------------------------------------"

# Streamlit 실행 (요청하신 옵션 적용)
streamlit run app.py --server.port 8501 --browser.gatherUsageStats false

if [ $? -ne 0 ]; then
    echo "❌ Failed to start Streamlit."
    echo "Please check if 'streamlit' is installed: pip install streamlit"
fi
