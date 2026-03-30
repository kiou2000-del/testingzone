"""
외부 도구 관리자
Syft, cdxgen, osv-scanner, dep-scan 설치 상태 확인 및 설치 가이드 제공
"""
import shutil
import subprocess
import platform
from dataclasses import dataclass
from typing import Optional


@dataclass
class ToolStatus:
    name: str
    command: str
    installed: bool = False
    version: str = ""
    path: str = ""
    install_guide: str = ""
    purpose: str = ""


# 도구 정의
TOOLS = {
    "syft": {
        "command": "syft",
        "purpose": "바이너리 SBOM 생성",
        "install_steps": [
            "1. GitHub Releases 에서 다운로드:",
            "   syft_*_windows_amd64.zip",
            "2. 압축 해제 후 syft.exe를 PATH에 추가",
        ],
        "install_cmd": "scoop install syft",
        "url": "https://github.com/anchore/syft/releases",
    },
    "cdxgen": {
        "command": "cdxgen",
        "purpose": "소스코드 SBOM 생성",
        "install_steps": [
            "Node.js 설치 후:",
        ],
        "install_cmd": "npm install -g @cyclonedx/cdxgen",
        "url": "https://github.com/CycloneDX/cdxgen",
    },
    "osv-scanner": {
        "command": "osv-scanner",
        "purpose": "CVE 매핑 (Google)",
        "install_steps": [
            "1. GitHub Releases 에서 다운로드:",
            "   osv-scanner_*_windows_amd64.exe",
            "2. exe 파일을 PATH에 추가",
            "",
            "또는 Go 설치 후:",
        ],
        "install_cmd": "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
        "url": "https://github.com/google/osv-scanner/releases",
    },
    "depscan": {
        "command": "depscan",
        "purpose": "CVE 매핑 (OWASP)",
        "install_steps": [],
        "install_cmd": "pip install owasp-depscan",
        "url": "https://github.com/owasp-dep-scan/dep-scan",
    },
    "grype": {
        "command": "grype",
        "purpose": "CVE 매핑 (Anchore, SBOM 네이티브)",
        "install_steps": [
            "1. GitHub Releases 에서 다운로드:",
            "   grype_*_windows_amd64.zip",
            "2. 압축 해제 후 grype.exe를 PATH에 추가",
        ],
        "install_cmd": "scoop install grype",
        "url": "https://github.com/anchore/grype/releases",
    },
}


def check_tool(name: str) -> ToolStatus:
    """단일 도구 상태 확인"""
    info = TOOLS.get(name, {})
    cmd = info.get("command", name)
    system = platform.system()

    status = ToolStatus(
        name=name,
        command=cmd,
        purpose=info.get("purpose", ""),
        install_guide=info.get("install_cmd", ""),
    )

    # Windows에서 .cmd/.bat 확장자 포함 검색
    path = shutil.which(cmd)
    if not path and platform.system() == "Windows":
        for ext in [".cmd", ".exe", ".bat"]:
            path = shutil.which(cmd + ext)
            if path:
                break

    if path:
        status.installed = True
        status.path = path
        try:
            ver_arg = "version" if name != "depscan" else "--version"
            result = subprocess.run(
                [cmd, ver_arg],
                capture_output=True, text=True, timeout=10,
                shell=(platform.system() == "Windows"),
                encoding="utf-8", errors="replace",
            )
            out = (result.stdout + result.stderr).strip()
            for line in out.split("\n"):
                line = line.strip()
                if line:
                    status.version = line[:80]
                    break
        except Exception:
            status.version = "(installed)"

    return status


def check_all_tools() -> dict:
    """모든 도구 상태 확인"""
    return {name: check_tool(name) for name in TOOLS}


def get_available_sbom_tools() -> list:
    """사용 가능한 SBOM 생성 도구 목록"""
    available = []
    for name in ["syft", "cdxgen"]:
        s = check_tool(name)
        if s.installed:
            available.append(name)
    return available


def get_available_cve_tools() -> list:
    """사용 가능한 CVE 매핑 도구 목록"""
    available = []
    for name in ["grype", "osv-scanner", "depscan"]:
        s = check_tool(name)
        if s.installed:
            available.append(name)
    return available
