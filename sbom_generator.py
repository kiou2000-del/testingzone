"""
2차: SBOM 생성
  - 바이너리 → Syft
  - 소스코드 → cdxgen
CycloneDX JSON 포맷으로 출력합니다.

Windows 호환:
  - npm global 패키지(.cmd)는 shell=True 필요
  - FileNotFoundError([WinError 2]) 방어
"""
import subprocess
import json
import os
import sys
import tempfile
import shutil
import platform
from typing import Optional, Callable
from dataclasses import dataclass, field

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class SBOMResult:
    success: bool = False
    tool_used: str = ""
    format: str = "cyclonedx"
    sbom_json: dict = field(default_factory=dict)
    sbom_path: str = ""
    components_count: int = 0
    error: str = ""
    duration: float = 0.0
    raw_output: str = ""


def _run_cmd(cmd: list, timeout=600, cwd=None, line_callback=None) -> subprocess.CompletedProcess:
    """
    Windows/Linux 호환 subprocess 실행.
    로컬 tools 폴더를 PATH에 추가하여 실행합니다.
    """
    # 환경변수 보강: 로컬 tools 폴더 추가
    env = os.environ.copy()
    app_dir = os.path.dirname(os.path.abspath(__file__))
    local_tools_dir = os.path.join(app_dir, "tools")
    if os.path.isdir(local_tools_dir):
        sep = ";" if IS_WINDOWS else ":"
        env["PATH"] = local_tools_dir + sep + env.get("PATH", "")

    if line_callback:
        # 실시간 스트리밍 모드
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=cwd, shell=IS_WINDOWS,
                env=env, encoding="utf-8", errors="replace",
            )
            out_lines = []
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n\r")
                if line:
                    out_lines.append(line)
                    line_callback(line)
            proc.wait(timeout=timeout)
            stdout = "\n".join(out_lines)
            return subprocess.CompletedProcess(cmd, proc.returncode, stdout, "")
        except FileNotFoundError:
            cmd_name = cmd[0] if cmd else "unknown"
            raise FileNotFoundError(
                f"'{cmd_name}' 명령을 찾을 수 없습니다.\n"
                f"설치 확인: where {cmd_name} (Windows) 또는 which {cmd_name} (Linux)\n"
                f"PATH 환경변수에 {cmd_name}이 포함되어 있는지 확인하세요."
            )

    # 기존 일괄 실행 모드
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            shell=IS_WINDOWS,
            encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        cmd_name = cmd[0] if cmd else "unknown"
        raise FileNotFoundError(
            f"'{cmd_name}' 명령을 찾을 수 없습니다.\n"
            f"설치 확인: where {cmd_name} (Windows) 또는 which {cmd_name} (Linux)\n"
            f"PATH 환경변수에 {cmd_name}이 포함되어 있는지 확인하세요."
        )


def _find_tool(name: str) -> Optional[str]:
    """도구 실행 경로 찾기 (시스템 PATH + 로컬 tools/ 폴더)"""
    # 1. 시스템 PATH 확인
    path = shutil.which(name)
    if path:
        return path
    
    # 2. 로컬 tools/ 폴더 확인
    app_dir = os.path.dirname(os.path.abspath(__file__))
    local_tools_dir = os.path.join(app_dir, "tools")
    
    if os.path.isdir(local_tools_dir):
        # 가능한 확장자 목록
        exts = [""]
        if IS_WINDOWS:
            exts = [".exe", ".cmd", ".bat"]
        
        for ext in exts:
            target = os.path.join(local_tools_dir, name + ext)
            if os.path.isfile(target):
                return target

    # 3. Windows 추가 확장자 시도 (시스템 PATH용)
    if IS_WINDOWS:
        for ext in [".cmd", ".exe", ".bat"]:
            path = shutil.which(name + ext)
            if path:
                return path
    return None


def generate_sbom_syft(
    target_path: str,
    output_dir: str = "",
    output_format: str = "cyclonedx-json",
    progress: Optional[Callable] = None,
    line_callback: Optional[Callable] = None,
) -> SBOMResult:
    """Syft로 바이너리 기반 SBOM 생성"""
    result = SBOMResult(tool_used="syft")

    if not _find_tool("syft"):
        result.error = (
            "Syft가 설치되어 있지 않습니다.\n"
            "다운로드: https://github.com/anchore/syft/releases\n"
            "syft.exe를 다운로드하여 PATH에 추가하세요."
        )
        return result

    def log(msg):
        if progress:
            progress(msg)

    log(f"🔧 Syft SBOM 생성 시작: {os.path.basename(target_path)}")

    if not output_dir:
        output_dir = tempfile.mkdtemp(prefix="sbom_out_")

    if os.path.isdir(target_path):
        scan_target = f"dir:{target_path}"
    else:
        scan_target = f"file:{target_path}"

    cmd = ["syft", "scan", scan_target, "-o", output_format, "-q"]
    log(f"  📋 명령: {' '.join(cmd)}")

    import time
    t0 = time.time()

    try:
        proc = _run_cmd(cmd, timeout=600)
        result.duration = time.time() - t0

        if proc.returncode == 0 and proc.stdout.strip():
            result.success = True
            result.raw_output = proc.stdout
            try:
                result.sbom_json = json.loads(proc.stdout)
            except json.JSONDecodeError:
                result.sbom_json = {"raw": proc.stdout[:5000]}

            out_path = os.path.join(output_dir, "sbom.cdx.json")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(proc.stdout)
            result.sbom_path = out_path
            result.components_count = _count_components(result.sbom_json)
            log(f"  ✅ Syft 완료: {result.components_count}개 컴포넌트 ({result.duration:.1f}초)")
        else:
            err = proc.stderr.strip() or "출력 없음"
            result.error = f"Syft 실행 실패: {err[:300]}"
            log(f"  ❌ {result.error}")

    except FileNotFoundError as e:
        result.error = str(e)
    except subprocess.TimeoutExpired:
        result.error = "Syft 실행 시간 초과 (10분)"
    except Exception as e:
        result.error = f"Syft 오류: {e}"

    return result


def generate_sbom_cdxgen(
    target_path: str,
    output_dir: str = "",
    progress: Optional[Callable] = None,
    line_callback: Optional[Callable] = None,
) -> SBOMResult:
    """cdxgen으로 소스코드 기반 SBOM 생성"""
    result = SBOMResult(tool_used="cdxgen")

    if not _find_tool("cdxgen"):
        result.error = (
            "cdxgen이 설치되어 있지 않습니다.\n"
            "설치: npm install -g @cyclonedx/cdxgen\n"
            "(Node.js 필요: https://nodejs.org/)"
        )
        return result

    def log(msg):
        if progress:
            progress(msg)

    log(f"🔧 cdxgen SBOM 생성 시작: {os.path.basename(target_path)}")

    if not output_dir:
        output_dir = tempfile.mkdtemp(prefix="sbom_out_")

    out_path = os.path.join(output_dir, "sbom.cdx.json")
    # --deep: 딥 스캔 활성화, --evidence: 증거 기반 분석 (매니페스트가 없을 때 유용)
    cmd = ["cdxgen", "-o", out_path, "--format", "json", "--deep", "--evidence", target_path]
    log(f"  📋 명령: {' '.join(cmd)}")

    import time
    t0 = time.time()

    try:
        work_dir = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
        proc = _run_cmd(cmd, timeout=600, cwd=work_dir or None, line_callback=line_callback)
        result.duration = time.time() - t0

        if os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path, "r", encoding="utf-8") as f:
                content = f.read()
            try:
                result.sbom_json = json.loads(content)
                result.success = True
                result.raw_output = content
                result.sbom_path = out_path
                result.components_count = _count_components(result.sbom_json)
                log(f"  ✅ cdxgen 완료: {result.components_count}개 컴포넌트 ({result.duration:.1f}초)")
            except json.JSONDecodeError:
                # 파일은 있으나 JSON이 아닌 경우 (에러 메시지 등이 담겼을 수 있음)
                if not result.success:
                    result.error = "cdxgen 출력이 유효한 JSON이 아닙니다"
        else:
            # 파일이 없는 경우에만 에러로 처리
            err = proc.stderr.strip() or proc.stdout.strip() or "출력 파일 없음"
            # 단순 경고(Notice)만 있는 경우는 에러 메시지에서 제외하거나 필터링 시도
            if "Notice:" in err and not result.success:
                result.error = f"cdxgen 실행 중 경고 발생 (결과 파일 없음): {err[:200]}"
            else:
                result.error = f"cdxgen 실행 실패: {err[:300]}"
            log(f"  ❌ {result.error}")

    except FileNotFoundError as e:
        result.error = str(e)
    except subprocess.TimeoutExpired:
        result.error = "cdxgen 실행 시간 초과 (10분)"
    except Exception as e:
        result.error = f"cdxgen 오류: {e}"

    return result


def generate_sbom(
    target_path: str,
    tool: str = "auto",
    input_type: str = "auto",
    output_dir: str = "",
    progress: Optional[Callable] = None,
    line_callback: Optional[Callable] = None,
) -> SBOMResult:
    """자동 선택하여 SBOM 생성"""

    # 안전장치: 압축 파일이 직접 전달되면 먼저 추출
    _archive_exts = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".7z")
    if os.path.isfile(target_path) and any(target_path.lower().endswith(e) for e in _archive_exts):
        def _log(msg):
            if progress:
                progress(msg)
        _log(f"📦 압축 파일 감지 → 자동 추출: {os.path.basename(target_path)}")
        try:
            from archive_handler import extract_archive
            extracted, err = extract_archive(file_path=target_path)
            if err or not extracted:
                r = SBOMResult()
                r.error = f"압축 파일 추출 실패: {err}"
                return r
            _log(f"  ✅ 추출 완료 → {os.path.basename(extracted)}")
            target_path = extracted
        except Exception as e:
            r = SBOMResult()
            r.error = f"압축 파일 추출 오류: {e}"
            return r

    if tool == "auto":
        if input_type == "binary":
            tool = "syft"
        elif input_type == "source":
            tool = "cdxgen"
        else:
            if _find_tool("cdxgen"):
                tool = "cdxgen"
            elif _find_tool("syft"):
                tool = "syft"
            else:
                r = SBOMResult()
                r.error = (
                    "SBOM 생성 도구를 찾을 수 없습니다.\n\n"
                    "다음 중 하나 이상을 설치하세요:\n"
                    "  - Syft (바이너리): https://github.com/anchore/syft/releases\n"
                    "  - cdxgen (소스코드): npm install -g @cyclonedx/cdxgen"
                )
                return r

    if tool == "syft":
        return generate_sbom_syft(target_path, output_dir, "cyclonedx-json", progress, line_callback)
    elif tool == "cdxgen":
        res = generate_sbom_cdxgen(target_path, output_dir, progress, line_callback)
        
        # Fallback 로직 강화: 
        # 1. cdxgen이 실패했거나 (res.success=False)
        # 2. 성공했으나 컴포넌트를 하나도 찾지 못한 경우
        # syft가 사용 가능하다면 syft로 재시도합니다.
        if (not res.success or res.components_count == 0) and _find_tool("syft"):
            def _log(msg):
                if progress: progress(msg)
            
            reason = "컴포넌트를 찾지 못함" if res.success else "도구 실행 실패"
            _log(f"  ⚠️ cdxgen이 {reason}. Syft로 재시도합니다...")
            
            res_syft = generate_sbom_syft(target_path, output_dir, "cyclonedx-json", progress, line_callback)
            
            if res_syft.success:
                if res_syft.components_count > 0:
                    _log(f"  ✨ Syft가 {res_syft.components_count}개의 컴포넌트를 탐지하는 데 성공했습니다!")
                    return res_syft
                else:
                    _log("  ⚠️ Syft로도 컴포넌트를 찾지 못했습니다.")
            else:
                _log(f"  ❌ Syft 재시도 실패: {res_syft.error}")
        
        return res
    else:
        r = SBOMResult()
        r.error = f"알 수 없는 도구: {tool}"
        return r


def _count_components(sbom: dict) -> int:
    if "components" in sbom:
        return len(sbom["components"])
    if "packages" in sbom:
        return len(sbom["packages"])
    return 0


def parse_sbom_components(sbom: dict) -> list:
    """CycloneDX SBOM에서 컴포넌트 목록 추출"""
    components = []
    for comp in sbom.get("components", []):
        components.append({
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "type": comp.get("type", "library"),
            "purl": comp.get("purl", ""),
            "group": comp.get("group", ""),
            "scope": comp.get("scope", ""),
            "licenses": _extract_licenses(comp),
            "ecosystem": _purl_to_ecosystem(comp.get("purl", "")),
        })
    return components


def _extract_licenses(comp: dict) -> str:
    parts = []
    for lic in comp.get("licenses", []):
        if "license" in lic:
            lid = lic["license"].get("id", "") or lic["license"].get("name", "")
            if lid:
                parts.append(lid)
        elif "expression" in lic:
            parts.append(lic["expression"])
    return ", ".join(parts) or "-"


def _purl_to_ecosystem(purl: str) -> str:
    if not purl or ":" not in purl:
        return "-"
    try:
        return purl.split(":")[1].split("/")[0]
    except Exception:
        return "-"
