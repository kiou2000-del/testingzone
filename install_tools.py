"""
🔧 도구 자동 다운로드 & 업데이트 관리자
GitHub Releases에서 최신 바이너리를 자동 다운로드합니다.

관리 도구:
  - syft.exe          (anchore/syft)           — 바이너리 SBOM 생성
  - cdxgen.exe        (CycloneDX/cdxgen)       — 소스코드 SBOM 생성
  - osv-scanner.exe   (google/osv-scanner)     — CVE 매핑 (Google OSV)

워크플로:
  1. tools/versions.json 에서 현재 설치된 버전 확인
  2. GitHub API로 최신 릴리즈 태그 조회
  3. 버전 비교 → 미설치 or 구버전이면 다운로드
  4. 다운로드 완료 후 versions.json 갱신
"""
import os
import sys
import json
import zipfile
import shutil
import urllib.request
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, List

# ─────────────────────────────────────────
# 설정
# ─────────────────────────────────────────
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(_APP_DIR, "tools")
VERSIONS_FILE = os.path.join(TOOLS_DIR, "versions.json")

USER_AGENT = "SBOM-Generator/2.1"

# 도구 정의: GitHub 저장소, 에셋 패턴, 로컬 파일명
TOOL_DEFS = {
    "syft": {
        "owner": "anchore",
        "repo": "syft",
        "local_exe": "syft.exe",
        "purpose": "바이너리 SBOM 생성",
        "asset_type": "zip",
        "asset_pattern": "syft_{ver}_windows_amd64.zip",
        "version_cmd": ["syft", "version"],
        "install_mode": "github",        # github 에서 바이너리 다운로드
    },
    "cdxgen": {
        "owner": "cdxgen",
        "repo": "cdxgen",
        "local_exe": "cdxgen.exe",
        "purpose": "소스코드 SBOM 생성",
        "asset_type": "exe",
        "asset_pattern": "cdxgen-windows-amd64",
        "version_cmd": ["cdxgen", "--version"],
        "install_mode": "npm_or_github",  # Node.js 있으면 npm, 없으면 github exe
        "npm_package": "@cyclonedx/cdxgen",
    },
    "osv-scanner": {
        "owner": "google",
        "repo": "osv-scanner",
        "local_exe": "osv-scanner.exe",
        "purpose": "CVE 매핑 (Google OSV)",
        "asset_type": "exe",
        "asset_pattern": "osv-scanner_windows_amd64.exe",
        "version_cmd": ["osv-scanner", "version"],
        "install_mode": "github",
    },
    "grype": {
        "owner": "anchore",
        "repo": "grype",
        "local_exe": "grype.exe",
        "purpose": "CVE 매핑 (Anchore, SBOM 네이티브)",
        "asset_type": "zip",
        "asset_pattern": "grype_{ver}_windows_amd64.zip",
        "version_cmd": ["grype", "version"],
        "install_mode": "github",
    },
}


# ─────────────────────────────────────────
# 데이터 클래스
# ─────────────────────────────────────────
@dataclass
class ToolUpdateInfo:
    name: str
    purpose: str = ""
    installed: bool = False
    local_version: str = ""
    latest_version: str = ""
    needs_update: bool = False
    downloaded: bool = False
    skipped: bool = False
    error: str = ""


@dataclass
class UpdateResult:
    tools: List[ToolUpdateInfo] = field(default_factory=list)
    all_ok: bool = False
    duration: float = 0.0


# ─────────────────────────────────────────
# 버전 파일 관리
# ─────────────────────────────────────────
def _load_versions() -> dict:
    """tools/versions.json 로드"""
    if os.path.isfile(VERSIONS_FILE):
        try:
            with open(VERSIONS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_versions(data: dict):
    """tools/versions.json 저장"""
    os.makedirs(TOOLS_DIR, exist_ok=True)
    with open(VERSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ─────────────────────────────────────────
# GitHub API
# ─────────────────────────────────────────
def _make_ssl_context():
    ctx = ssl.create_default_context()
    return ctx


def _github_latest_release(owner: str, repo: str) -> dict:
    """
    GitHub API에서 최신 릴리즈 정보를 가져옵니다.
    반환: {"tag_name": "v1.2.3", "assets": [{"name": "...", "browser_download_url": "..."}]}
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = _make_ssl_context()
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _find_asset_url(release: dict, pattern: str, tag: str) -> str:
    """릴리즈 에셋 목록에서 패턴에 맞는 다운로드 URL 찾기"""
    ver = tag.lstrip("v")
    target = pattern.replace("{ver}", ver)

    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name == target or target in name:
            return asset.get("browser_download_url", "")

    # 정확한 매칭 실패 시 부분 매칭
    for asset in release.get("assets", []):
        name = asset.get("name", "").lower()
        if "windows" in name and "amd64" in name:
            # exe 혹은 zip 매칭
            if pattern.endswith(".zip") and name.endswith(".zip"):
                return asset.get("browser_download_url", "")
            if pattern.endswith(".exe") and name.endswith(".exe"):
                return asset.get("browser_download_url", "")
            # cdxgen은 확장자 없이 배포될 수 있음
            if "cdxgen" in name and "windows" in name and "amd64" in name:
                return asset.get("browser_download_url", "")

    return ""


# ─────────────────────────────────────────
# 다운로드
# ─────────────────────────────────────────
def _download_file(url: str, dest: str, desc: str = "",
                   line_cb: Optional[Callable] = None) -> bool:
    """URL에서 파일 다운로드 (진행 표시)"""
    msg = f"⬇️  다운로드 중: {desc or url}"
    if line_cb:
        line_cb(msg)

    try:
        ctx = _make_ssl_context()
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
            total = resp.headers.get("Content-Length")
            total = int(total) if total else 0
            data = bytearray()
            downloaded = 0
            block = 1024 * 64  # 64KB

            while True:
                chunk = resp.read(block)
                if not chunk:
                    break
                data.extend(chunk)
                downloaded += len(chunk)
                if total and line_cb:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    total_mb = total / (1024 * 1024)
                    line_cb(f"  📥 {mb:.1f} / {total_mb:.1f} MB ({pct}%)")

        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)

        size_mb = len(data) / (1024 * 1024)
        if line_cb:
            line_cb(f"  ✅ 완료: {size_mb:.1f} MB → {os.path.basename(dest)}")
        return True

    except Exception as e:
        if line_cb:
            line_cb(f"  ❌ 다운로드 실패: {e}")
        return False


def _download_and_extract_zip(url: str, dest_exe: str, desc: str = "",
                              line_cb: Optional[Callable] = None) -> bool:
    """ZIP 다운로드 후 exe 추출"""
    zip_path = dest_exe + ".tmp.zip"
    if not _download_file(url, zip_path, desc, line_cb):
        return False

    try:
        if line_cb:
            line_cb(f"  📦 압축 해제 중...")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(os.path.dirname(dest_exe))
        os.remove(zip_path)

        if os.path.isfile(dest_exe):
            if line_cb:
                line_cb(f"  ✅ {os.path.basename(dest_exe)} 추출 완료")
            return True
        else:
            # ZIP 안에 이름이 다를 수 있음 — exe 찾기
            parent = os.path.dirname(dest_exe)
            for f in os.listdir(parent):
                if f.endswith(".exe") and f != os.path.basename(dest_exe):
                    src = os.path.join(parent, f)
                    if os.path.basename(dest_exe).split(".")[0].lower() in f.lower():
                        shutil.move(src, dest_exe)
                        if line_cb:
                            line_cb(f"  ✅ {f} → {os.path.basename(dest_exe)}")
                        return True
            if line_cb:
                line_cb(f"  ❌ ZIP에서 exe를 찾을 수 없음")
            return False

    except Exception as e:
        if line_cb:
            line_cb(f"  ❌ 압축 해제 실패: {e}")
        if os.path.isfile(zip_path):
            os.remove(zip_path)
        return False


def _download_exe(url: str, dest_exe: str, desc: str = "",
                  line_cb: Optional[Callable] = None) -> bool:
    """EXE 직접 다운로드"""
    return _download_file(url, dest_exe, desc, line_cb)


# ─────────────────────────────────────────
# npm 기반 설치 (cdxgen 전용)
# ─────────────────────────────────────────
def _check_node_available() -> bool:
    """Node.js / npm이 설치되어 있는지 확인"""
    return shutil.which("npm") is not None


def _get_npm_global_version(package_name: str) -> str:
    """npm global 패키지의 설치된 버전 확인"""
    import subprocess, platform
    try:
        result = subprocess.run(
            ["npm", "list", "-g", package_name, "--depth=0", "--json"],
            capture_output=True, text=True, timeout=15,
            shell=(platform.system() == "Windows"),
            encoding="utf-8", errors="replace",
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            deps = data.get("dependencies", {})
            # package_name은 @cyclonedx/cdxgen 같은 형태
            short = package_name.split("/")[-1] if "/" in package_name else package_name
            for key, val in deps.items():
                if short in key or package_name in key:
                    return val.get("version", "")
        return ""
    except Exception:
        return ""


def _install_via_npm(
    package_name: str,
    line_cb: Optional[Callable] = None,
) -> tuple:
    """
    npm install -g 로 패키지 설치/업데이트.
    반환: (성공여부, 설치된 버전 문자열)
    """
    import subprocess, platform
    _win = platform.system() == "Windows"

    cmd = ["npm", "install", "-g", package_name]
    if line_cb:
        line_cb(f"$ {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, shell=_win,
            encoding="utf-8", errors="replace",
        )
        for raw_line in proc.stdout:
            raw_line = raw_line.rstrip("\n\r")
            if raw_line and line_cb:
                line_cb(raw_line)
        proc.wait(timeout=300)

        if proc.returncode == 0:
            ver = _get_npm_global_version(package_name)
            return True, ver
        return False, ""
    except Exception as e:
        if line_cb:
            line_cb(f"  ❌ npm 설치 실패: {e}")
        return False, ""


# ─────────────────────────────────────────
# 메인: 도구 업데이트 확인 & 다운로드
# ─────────────────────────────────────────
def check_and_update_tools(
    line_callback: Optional[Callable[[str], None]] = None,
    force_download: bool = False,
) -> UpdateResult:
    """
    모든 도구의 최신 버전을 확인하고 필요 시 다운로드합니다.

    Args:
        line_callback: 실시간 로그 콜백
        force_download: True면 버전 무관하게 재다운로드

    Returns:
        UpdateResult
    """
    result = UpdateResult()
    t0 = time.time()

    os.makedirs(TOOLS_DIR, exist_ok=True)
    versions = _load_versions()

    def cb(msg):
        if line_callback:
            line_callback(msg)

    cb("── 도구 업데이트 확인 ────────────────────")
    cb(f"  📂 도구 폴더: {TOOLS_DIR}")
    cb("")

    for tool_name, tdef in TOOL_DEFS.items():
        info = ToolUpdateInfo(name=tool_name, purpose=tdef["purpose"])
        local_exe = os.path.join(TOOLS_DIR, tdef["local_exe"])
        install_mode = tdef.get("install_mode", "github")

        cb(f"🔧 [{tool_name}] {tdef['purpose']}")

        # ─── npm_or_github 모드: cdxgen 전용 ───
        if install_mode == "npm_or_github":
            npm_pkg = tdef.get("npm_package", "")
            has_npm = _check_node_available()

            # npm으로 이미 설치되어 있는지 확인 (PATH에 cdxgen 존재)
            npm_cmd_path = shutil.which(tool_name) or shutil.which(tool_name + ".cmd")

            if npm_cmd_path:
                # npm global로 이미 설치됨
                npm_ver = _get_npm_global_version(npm_pkg)
                cb(f"  📌 npm global 설치 감지: {npm_ver or '버전 미확인'}")
                cb(f"     경로: {npm_cmd_path}")
                info.installed = True
                info.local_version = npm_ver

                # 최신 버전 확인
                try:
                    cb(f"  🌐 GitHub 최신 버전 조회 중...")
                    release = _github_latest_release(tdef["owner"], tdef["repo"])
                    info.latest_version = release.get("tag_name", "").lstrip("v")
                    cb(f"  🏷️  최신: {info.latest_version}")
                except Exception as e:
                    cb(f"  ⚠️  GitHub 조회 실패: {e} — 기존 버전 유지")
                    info.skipped = True
                    result.tools.append(info)
                    cb("")
                    continue

                if info.local_version == info.latest_version or (
                    not force_download and info.local_version and info.latest_version in info.local_version
                ):
                    cb(f"  ✅ 최신 버전입니다")
                    info.skipped = True
                    result.tools.append(info)
                    cb("")
                    continue

                # 업데이트 필요
                if has_npm:
                    cb(f"  🔄 npm 업데이트: {info.local_version} → {info.latest_version}")
                    ok, ver = _install_via_npm(npm_pkg, line_cb=cb)
                    if ok:
                        info.downloaded = True
                        info.latest_version = ver or info.latest_version
                        versions[tool_name] = {
                            "version": info.latest_version,
                            "method": "npm",
                            "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        _save_versions(versions)
                        cb(f"  ✅ cdxgen {info.latest_version} npm 업데이트 완료!")
                    else:
                        cb(f"  ⚠️  npm 업데이트 실패 — 기존 버전 유지")
                else:
                    cb(f"  ⚠️  npm 없음 — 기존 버전 유지")

                result.tools.append(info)
                cb("")
                continue

            # npm으로 설치되어 있지 않음 → 신규 설치
            if has_npm:
                cb(f"  📦 Node.js 감지 → npm install -g {npm_pkg}")
                ok, ver = _install_via_npm(npm_pkg, line_cb=cb)
                if ok:
                    info.downloaded = True
                    info.installed = True
                    info.latest_version = ver or "installed"
                    versions[tool_name] = {
                        "version": info.latest_version,
                        "method": "npm",
                        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    _save_versions(versions)
                    cb(f"  ✅ cdxgen npm 설치 완료! ({ver})")
                    result.tools.append(info)
                    cb("")
                    continue
                else:
                    cb(f"  ⚠️  npm 설치 실패 — GitHub exe 다운로드로 전환")
                    # npm 실패 시 아래 github 다운로드로 fallthrough

            elif not has_npm:
                cb(f"  ⚠️  Node.js/npm 미설치 — GitHub exe 다운로드로 전환")

            # npm 불가 → github exe 다운로드 (fallback)
            # 아래 github 공통 로직으로 진행

        # ─── github 모드 (syft, osv-scanner, cdxgen fallback) ───

        # 1. 로컬 상태 확인
        if not info.installed:
            info.installed = os.path.isfile(local_exe)
        if not info.local_version:
            info.local_version = versions.get(tool_name, {}).get("version", "")

        if info.installed and info.local_version:
            cb(f"  📌 현재: {info.local_version} ({tdef['local_exe']})")
        elif info.installed:
            cb(f"  📌 파일 존재하나 버전 미확인 ({tdef['local_exe']})")
        elif install_mode == "github":
            cb(f"  ⚠️  미설치")

        # 2. GitHub 최신 버전 조회
        if not info.latest_version:
            try:
                cb(f"  🌐 GitHub 최신 버전 조회 중... ({tdef['owner']}/{tdef['repo']})")
                release = _github_latest_release(tdef["owner"], tdef["repo"])
                info.latest_version = release.get("tag_name", "")
                cb(f"  🏷️  최신: {info.latest_version}")
            except Exception as e:
                info.error = f"GitHub API 오류: {e}"
                cb(f"  ❌ GitHub 조회 실패: {e}")
                if info.installed:
                    cb(f"  ⏭️  기존 버전 유지 (오프라인)")
                    info.skipped = True
                else:
                    cb(f"  ❌ 설치 불가")
                result.tools.append(info)
                cb("")
                continue
        else:
            # npm_or_github fallback에서 이미 release 조회 시도가 필요함
            try:
                release = _github_latest_release(tdef["owner"], tdef["repo"])
                info.latest_version = release.get("tag_name", "")
                cb(f"  🏷️  최신: {info.latest_version}")
            except Exception:
                info.error = "GitHub 조회 실패"
                cb(f"  ❌ GitHub에서 다운로드 불가")
                result.tools.append(info)
                cb("")
                continue

        # 3. 업데이트 필요 여부 판단
        if force_download:
            info.needs_update = True
            cb(f"  🔄 강제 다운로드 모드")
        elif not info.installed:
            info.needs_update = True
            cb(f"  📦 신규 설치 필요")
        elif info.local_version != info.latest_version:
            info.needs_update = True
            cb(f"  🔄 업데이트 필요: {info.local_version} → {info.latest_version}")
        else:
            info.needs_update = False
            info.skipped = True
            cb(f"  ✅ 최신 버전입니다")
            result.tools.append(info)
            cb("")
            continue

        # 4. GitHub에서 다운로드
        asset_url = _find_asset_url(
            release, tdef["asset_pattern"], info.latest_version
        )
        if not asset_url:
            info.error = f"다운로드 에셋을 찾을 수 없음: {tdef['asset_pattern']}"
            cb(f"  ❌ {info.error}")
            result.tools.append(info)
            cb("")
            continue

        cb(f"  📡 URL: {asset_url}")

        # 기존 파일 백업
        backup_path = local_exe + ".bak"
        if info.installed:
            try:
                shutil.copy2(local_exe, backup_path)
            except Exception:
                pass

        # 다운로드 실행
        if tdef["asset_type"] == "zip":
            ok = _download_and_extract_zip(
                asset_url, local_exe,
                f"{tool_name} {info.latest_version}",
                line_cb=cb,
            )
        else:
            ok = _download_exe(
                asset_url, local_exe,
                f"{tool_name} {info.latest_version}",
                line_cb=cb,
            )

        if ok:
            info.downloaded = True
            info.installed = True
            # 버전 정보 갱신
            versions[tool_name] = {
                "version": info.latest_version,
                "exe": tdef["local_exe"],
                "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            _save_versions(versions)
            cb(f"  ✅ {tool_name} {info.latest_version} 설치 완료!")
            # 백업 삭제
            if os.path.isfile(backup_path):
                os.remove(backup_path)
        else:
            info.error = "다운로드 실패"
            # 백업 복원
            if os.path.isfile(backup_path):
                shutil.move(backup_path, local_exe)
                cb(f"  ⚠️  기존 버전 복원됨")

        result.tools.append(info)
        cb("")

    # 결과 요약
    result.duration = time.time() - t0
    result.all_ok = all(
        (t.installed and not t.error) or t.skipped
        for t in result.tools
    )

    cb("── 업데이트 결과 ─────────────────────────")
    for t in result.tools:
        if t.downloaded:
            cb(f"  🆕 {t.name}: {t.latest_version} (신규 다운로드)")
        elif t.skipped and t.installed:
            ver = t.local_version or t.latest_version
            cb(f"  ✅ {t.name}: {ver} (최신)")
        elif t.error:
            cb(f"  ❌ {t.name}: {t.error}")
        else:
            cb(f"  ⚠️  {t.name}: 상태 불명")
    cb(f"  ⏱️  소요 시간: {result.duration:.1f}초")
    cb("")

    return result


# ─────────────────────────────────────────
# CLI 실행
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  SBOM Generator — 도구 자동 다운로드 & 업데이트")
    print("=" * 60)
    print()

    force = "--force" in sys.argv

    def print_line(msg):
        print(msg)

    result = check_and_update_tools(
        line_callback=print_line,
        force_download=force,
    )

    print()
    if result.all_ok:
        print("✅ 모든 도구 준비 완료!")
    else:
        print("⚠️  일부 도구에 문제가 있습니다.")
        for t in result.tools:
            if t.error:
                print(f"   {t.name}: {t.error}")

    sys.exit(0 if result.all_ok else 1)
