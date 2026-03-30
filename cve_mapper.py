"""
SBOM → CVE 매핑
  - osv-scanner (Google OSV)
  - depscan (OWASP dep-scan)
생성된 SBOM 파일을 입력받아 CVE/CWE/CVSS를 매핑합니다.
"""
import subprocess
import json
import os
import tempfile
import shutil
import threading
import time
import platform
from typing import Optional, Callable, List
from dataclasses import dataclass, field

IS_WIN = platform.system() == "Windows"


def _run_with_timeout(
    cmd: list,
    timeout: int = 300,
    line_callback: Optional[Callable] = None,
    env: Optional[dict] = None,
    capture_stdout: bool = False,
) -> tuple:
    """
    Popen 기반 실행: 실시간 스트리밍 + 진짜 타임아웃.

    Args:
        cmd: 실행할 명령어
        timeout: 초 단위 타임아웃
        line_callback: stderr/stdout 라인 콜백
        env: 환경변수
        capture_stdout: True면 stdout을 캡처(JSON)하고 stderr만 스트리밍
                       False면 stdout+stderr 합쳐서 스트리밍

    Returns:
        (stdout_text, stderr_text, returncode, timed_out)
    """
    if capture_stdout:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, shell=IS_WIN, env=env,
            encoding="utf-8", errors="replace",
        )
    else:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, shell=IS_WIN, env=env,
            encoding="utf-8", errors="replace",
        )

    stdout_lines = []
    stderr_lines = []
    timed_out = False

    def _kill():
        nonlocal timed_out
        timed_out = True
        try:
            proc.kill()
        except Exception:
            pass

    timer = threading.Timer(timeout, _kill)
    timer.start()

    try:
        if capture_stdout:
            # stderr 실시간 스트리밍 (별도 스레드), stdout 캡처
            def _read_stderr():
                for line in proc.stderr:
                    line = line.rstrip("\n\r")
                    if line:
                        stderr_lines.append(line)
                        if line_callback:
                            line_callback(line)

            t = threading.Thread(target=_read_stderr, daemon=True)
            t.start()

            # stdout 읽기 (메인 스레드)
            for line in proc.stdout:
                stdout_lines.append(line.rstrip("\n\r"))

            t.join(timeout=5)
        else:
            # stdout+stderr 합쳐서 실시간 스트리밍
            for line in proc.stdout:
                line = line.rstrip("\n\r")
                if line:
                    stdout_lines.append(line)
                    if line_callback:
                        line_callback(line)

        proc.wait(timeout=10)
    except Exception:
        pass
    finally:
        timer.cancel()

    rc = proc.returncode if proc.returncode is not None else -1
    return (
        "\n".join(stdout_lines),
        "\n".join(stderr_lines),
        rc,
        timed_out,
    )


@dataclass
class CVEEntry:
    """개별 CVE 항목"""
    cve_id: str = ""
    severity: str = ""       # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    package_name: str = ""
    package_version: str = ""
    fixed_version: str = ""
    summary: str = ""
    source: str = ""         # osv-scanner / depscan
    aliases: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class CVEMapResult:
    """CVE 매핑 결과"""
    success: bool = False
    tool_used: str = ""
    total_vulns: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    vulns: List[CVEEntry] = field(default_factory=list)
    error: str = ""
    duration: float = 0.0
    raw_output: str = ""
    output_path: str = ""


# ─────────────────────────────────────────
# osv-scanner
# ─────────────────────────────────────────

def run_osv_scanner(
    sbom_path: str,
    progress: Optional[Callable] = None,
    line_callback: Optional[Callable] = None,
    timeout: int = 600,
    scan_path: str = "",
) -> CVEMapResult:
    """
    osv-scanner로 CVE 매핑.

    전략:
      1차: Lock 파일 직접 타겟 스캔 (--lockfile) — 가장 정확하고 안정적
      2차: SBOM 파일 기반 스캔 (-L) — 1차 실패 또는 scan_path 미제공 시

    Args:
        sbom_path: SBOM JSON 파일 경로
        progress: 진행 콜백
        line_callback: 실시간 출력 콜백
        timeout: 초 단위 타임아웃 (기본 10분)
        scan_path: 프로젝트 원본 디렉토리 경로 (있으면 lock 파일 직접 스캔 우선)

    Returns:
        CVEMapResult
    """
    result = CVEMapResult(tool_used="osv-scanner")

    if not shutil.which("osv-scanner"):
        result.error = "osv-scanner가 설치되어 있지 않습니다."
        return result

    def log(msg):
        if progress:
            progress(msg)

    log("🔍 osv-scanner CVE 스캔 시작...")

    t0 = time.time()

    def _parse_output(output_text, elapsed):
        """JSON 출력을 파싱하여 result에 반영"""
        result.duration = elapsed
        result.raw_output = output_text
        if output_text:
            try:
                data = json.loads(output_text)
                result.success = True
                result.vulns = _parse_osv_results(data)
                _compute_stats(result)
                log(f"  ✅ osv-scanner 완료: {result.total_vulns}건 "
                    f"(🔴{result.critical} 🟠{result.high} "
                    f"🟡{result.medium} 🟢{result.low}) [{elapsed:.1f}초]")
                return True
            except json.JSONDecodeError:
                pass
        return False

    # ── 1차: Lock 파일 직접 타겟 스캔 (가장 정확 + 안정적) ──
    # 핵심: --lockfile 플래그는 실제 lock 파일만 받을 수 있음
    #       package.json 같은 매니페스트는 --lockfile로 처리 불가 (exit 127)
    #       STEP 0에서 npm install 후 package-lock.json이 생성되어야 함
    if scan_path and os.path.isdir(scan_path):
        # osv-scanner --lockfile이 인식하는 lock/매니페스트 파일
        LOCKFILE_NAMES = {
            # JavaScript / Node.js
            "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
            # Python
            "poetry.lock", "Pipfile.lock", "requirements.txt",
            # Go
            "go.sum",
            # Java
            "pom.xml", "gradle.lockfile",
            # C# (.NET)
            "packages.lock.json", "project.assets.json",
            # Ruby
            "Gemfile.lock",
            # Rust
            "Cargo.lock",
            # PHP
            "composer.lock",
            # Dart / Flutter
            "pubspec.lock",
            # Swift (iOS)
            "Podfile.lock", "Package.resolved",
            # C / C++
            "conan.lock",
        }
        SKIP_DIRS = {
            "node_modules", ".git", "venv", ".venv", "vendor",
            "dist", "build", "__pycache__", ".dart_tool", ".pub-cache",
        }

        lockfiles = []
        for dirpath, dirnames, filenames in os.walk(scan_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            rel = os.path.relpath(dirpath, scan_path)
            if rel != "." and rel.count(os.sep) >= 5:
                dirnames.clear()
                continue
            for fname in filenames:
                if fname in LOCKFILE_NAMES:
                    lockfiles.append(os.path.join(dirpath, fname))

        if lockfiles:
            log(f"  🔒 Lock 파일 {len(lockfiles)}개 발견 → 타겟 스캔")
            for lf in lockfiles:
                rel_lf = os.path.relpath(lf, scan_path)
                if line_callback:
                    line_callback(f"    📄 {rel_lf}")

            cmd_lock = ["osv-scanner", "scan", "--format", "json"]
            for lf in lockfiles:
                cmd_lock.extend(["--lockfile", lf])

            if line_callback:
                if len(lockfiles) > 3:
                    line_callback(f"$ osv-scanner scan --format json --lockfile <{len(lockfiles)}개 파일>")
                else:
                    line_callback(f"$ {' '.join(cmd_lock)}")
                line_callback(f"  ⏱️ 타임아웃: {timeout}초")

            try:
                stdout, stderr_text, rc, was_timeout = _run_with_timeout(
                    cmd_lock, timeout=timeout,
                    line_callback=line_callback,
                    capture_stdout=True,
                )

                if was_timeout:
                    result.error = f"osv-scanner 시간 초과 ({time.time()-t0:.0f}초)"
                    result.duration = time.time() - t0
                    log(f"  ❌ {result.error}")
                    return result

                output = stdout.strip()

                if rc in (0, 1) and output:
                    if _parse_output(output, time.time() - t0):
                        return result
                elif rc == 0 and not output:
                    result.success = True
                    result.duration = time.time() - t0
                    log(f"  ✅ osv-scanner 완료: 취약점 0건 ({result.duration:.1f}초)")
                    return result

                if rc not in (0, 1):
                    log(f"  ⚠️ Lock 파일 스캔 실패 (exit {rc}) → SBOM 스캔으로 전환")
            except Exception as e:
                log(f"  ⚠️ Lock 파일 스캔 오류: {e} → SBOM 스캔으로 전환")
        else:
            log(f"  ⚠️ Lock 파일을 찾지 못함")
            log(f"     STEP 0에서 package-lock.json이 생성되지 않았을 수 있음")
            log(f"     → SBOM 스캔으로 전환")

    # ── 2차: SBOM 파일 기반 스캔 ──
    # 주의: -L은 lockfile 전용, SBOM에는 --sbom 사용해야 함
    if not result.success and sbom_path and os.path.isfile(sbom_path):
        # v2: scan --sbom path, v1: --sbom path
        cmd_v2 = ["osv-scanner", "scan", "--sbom", sbom_path, "--format", "json"]
        cmd_v1 = ["osv-scanner", "--format", "json", "--sbom", sbom_path]

        log(f"  📄 SBOM 파일 기반 스캔 (fallback)")
        if line_callback:
            line_callback(f"$ {' '.join(cmd_v2)}")

        try:
            stdout, stderr_text, rc, was_timeout = _run_with_timeout(
                cmd_v2, timeout=timeout,
                line_callback=line_callback,
                capture_stdout=True,
            )

            if was_timeout:
                result.error = f"osv-scanner SBOM 스캔 시간 초과"
                result.duration = time.time() - t0
                log(f"  ❌ {result.error}")
                return result

            output = stdout.strip()

            if rc in (0, 1) and output:
                if _parse_output(output, time.time() - t0):
                    return result

            # v2 scan --sbom 실패 → v1 --sbom fallback
            if rc not in (0, 1) or not output:
                log("  ⚠️ v2 형식 실패 → v1 형식으로 재시도")
                if line_callback:
                    line_callback(f"$ {' '.join(cmd_v1)}")
                stdout, stderr_text, rc, was_timeout = _run_with_timeout(
                    cmd_v1, timeout=timeout,
                    line_callback=line_callback,
                    capture_stdout=True,
                )
                if not was_timeout:
                    output = stdout.strip()
                    if rc in (0, 1) and output:
                        _parse_output(output, time.time() - t0)
                        return result

        except Exception as e:
            log(f"  ❌ SBOM 스캔 오류: {e}")

    # 최종: 결과 없음 처리
    if not result.success:
        result.duration = time.time() - t0
        if not result.vulns:
            result.success = True
            log(f"  ✅ osv-scanner 완료: 취약점 0건 ({result.duration:.1f}초)")

    return result


def _parse_osv_results(data: dict) -> List[CVEEntry]:
    """osv-scanner JSON 출력 파싱"""
    vulns = []
    seen = set()

    for result_item in data.get("results", []):
        for pkg_info in result_item.get("packages", []):
            pkg = pkg_info.get("package", {})
            pkg_name = pkg.get("name", "")
            pkg_version = pkg.get("version", "")

            for vuln_info in pkg_info.get("vulnerabilities", []):
                vuln_id = vuln_info.get("id", "")
                if vuln_id in seen:
                    continue
                seen.add(vuln_id)

                entry = CVEEntry(
                    package_name=pkg_name,
                    package_version=pkg_version,
                    source="osv-scanner",
                )

                # CVE ID
                aliases = vuln_info.get("aliases", [])
                entry.aliases = aliases
                for alias in aliases:
                    if alias.startswith("CVE-"):
                        entry.cve_id = alias
                        break
                if not entry.cve_id:
                    entry.cve_id = vuln_id

                # 설명
                entry.summary = vuln_info.get("summary", "")[:200]

                # Severity / CVSS
                for sev in vuln_info.get("severity", []):
                    if sev.get("type") == "CVSS_V3":
                        entry.cvss_vector = sev.get("score", "")

                db_specific = vuln_info.get("database_specific", {})
                severity_str = db_specific.get("severity", "").upper()
                if severity_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    entry.severity = severity_str

                # CWE
                entry.cwe_ids = db_specific.get("cwe_ids", [])

                # 수정 버전
                for affected in vuln_info.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                entry.fixed_version = event["fixed"]

                # 참조
                for ref in vuln_info.get("references", [])[:3]:
                    entry.references.append(ref.get("url", ""))

                # CVSS 점수 추정 (severity 기반)
                if not entry.cvss_score and entry.severity:
                    approx = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5}
                    entry.cvss_score = approx.get(entry.severity, 0)

                vulns.append(entry)

    return vulns


# ─────────────────────────────────────────
# OWASP dep-scan
# ─────────────────────────────────────────

def run_depscan(
    sbom_path: str = "",
    target_path: str = "",
    progress: Optional[Callable] = None,
    line_callback: Optional[Callable] = None,
) -> CVEMapResult:
    """
    OWASP dep-scan으로 CVE 매핑

    Args:
        sbom_path: SBOM 파일 경로 (BOM 입력)
        target_path: 프로젝트 경로 (직접 스캔)
        progress: 진행 콜백
        line_callback: 실시간 출력 콜백

    Returns:
        CVEMapResult
    """
    result = CVEMapResult(tool_used="depscan")

    if not shutil.which("depscan"):
        result.error = "depscan이 설치되어 있지 않습니다. pip install owasp-depscan"
        return result

    def log(msg):
        if progress:
            progress(msg)

    log("🛡️ OWASP dep-scan CVE 스캔 시작...")

    # GITHUB_TOKEN 확인 (dep-scan의 VDB 다운로드에 필요)
    has_gh_token = bool(os.environ.get("GITHUB_TOKEN"))
    if not has_gh_token and line_callback:
        line_callback("  ⚠️ GITHUB_TOKEN 환경변수 미설정 — GitHub API 호출 제한에 걸릴 수 있습니다")
        line_callback("     설정: set GITHUB_TOKEN=ghp_xxxxx (GitHub Personal Access Token)")

    out_dir = tempfile.mkdtemp(prefix="depscan_out_")

    # dep-scan 명령 구성
    cmd = ["depscan"]
    if sbom_path:
        cmd.extend(["--bom", sbom_path])
    elif target_path:
        cmd.extend(["--src", target_path])
    else:
        result.error = "SBOM 경로 또는 프로젝트 경로가 필요합니다."
        return result

    cmd.extend(["--reports-dir", out_dir])

    if line_callback:
        line_callback(f"$ {' '.join(cmd)}")

    t0 = time.time()

    try:
        dep_env = os.environ.copy()

        # _run_with_timeout: stdout+stderr 합쳐서 실시간 스트리밍 + 타임아웃
        stdout_text, _, rc, was_timeout = _run_with_timeout(
            cmd, timeout=600,
            line_callback=line_callback,
            env=dep_env,
            capture_stdout=False,  # 결과는 파일로 저장되므로 합쳐서 스트리밍
        )

        result.duration = time.time() - t0
        result.raw_output = stdout_text[:5000]

        if was_timeout:
            result.error = f"dep-scan 시간 초과 ({result.duration:.0f}초)"
            log(f"  ❌ {result.error}")
            return result

        # dep-scan은 reports 디렉토리에 결과 파일 생성
        # 파일 종류: depscan.json, vdr.json, bom.vdr.json 등
        try:
            all_files = os.listdir(out_dir)
            report_files = [f for f in all_files if f.endswith(".json")]
        except Exception:
            all_files = []
            report_files = []

        if line_callback:
            line_callback(f"  📂 리포트 폴더: {out_dir}")
            line_callback(f"  📄 생성된 파일: {', '.join(all_files) if all_files else '(없음)'}")

        # 0.0초 종료 감지: 스캔이 아예 동작하지 않았을 가능성
        if result.duration < 1.0 and not report_files:
            warning_msg = "dep-scan이 즉시 종료됨 — VDB 다운로드 실패 또는 SBOM 인식 실패 가능성"
            if not has_gh_token:
                warning_msg += " (GITHUB_TOKEN 미설정)"
            log(f"  ⚠️ {warning_msg}")
            if line_callback:
                line_callback(f"  💡 해결: 시스템 환경변수에 GITHUB_TOKEN=ghp_xxxxx 추가 후 재시도")

        for rf in report_files:
            rf_path = os.path.join(out_dir, rf)
            try:
                with open(rf_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for item in data:
                        entry = _parse_depscan_entry(item)
                        if entry:
                            result.vulns.append(entry)
                elif isinstance(data, dict):
                    # CycloneDX VDR 형식
                    vulns_list = data.get("vulnerabilities", [])
                    if vulns_list:
                        for item in vulns_list:
                            entry = _parse_depscan_entry(item)
                            if entry:
                                result.vulns.append(entry)
                    # dep-scan 자체 결과 형식
                    results_list = data.get("results", [])
                    if results_list:
                        for item in results_list:
                            entry = _parse_depscan_entry(item)
                            if entry:
                                result.vulns.append(entry)
            except Exception:
                continue

        result.success = True
        _compute_stats(result)
        log(f"  ✅ dep-scan 완료: {result.total_vulns}건 "
            f"(🔴{result.critical} 🟠{result.high} "
            f"🟡{result.medium} 🟢{result.low}) [{result.duration:.1f}초]")

        result.output_path = out_dir

    except subprocess.TimeoutExpired:
        result.error = "dep-scan 시간 초과 (10분)"
    except FileNotFoundError:
        result.error = (
            "depscan을 실행할 수 없습니다.\n"
            "설치: pip install owasp-depscan"
        )
    except Exception as e:
        result.error = f"dep-scan 오류: {e}"

    return result


def _parse_depscan_entry(item: dict) -> Optional[CVEEntry]:
    """dep-scan 결과 항목 파싱"""
    entry = CVEEntry(source="depscan")

    entry.cve_id = item.get("id", item.get("cve_id", ""))
    if not entry.cve_id:
        return None

    entry.severity = (item.get("severity", "") or "").upper()
    entry.cvss_score = item.get("cvss_score", 0) or 0


# ─────────────────────────────────────────
# Anchore Grype (SBOM 네이티브 스캐너)
# ─────────────────────────────────────────

def run_grype(
    sbom_path: str,
    progress: Optional[Callable] = None,
    line_callback: Optional[Callable] = None,
    timeout: int = 600,
) -> CVEMapResult:
    """
    Grype로 SBOM 파일의 CVE 매핑.

    Windows 호환 전략:
      - sbom:C:\\path 는 콜론 충돌 → stdin 파이프 방식 사용
      - DB 만료 시 GRYPE_DB_VALIDATE_AGE=false로 강제 사용
      - grype db update 선행 실행

    명령: type sbom.cdx.json | grype -o json (Windows)
          cat sbom.cdx.json | grype -o json  (Linux/Mac)
    """
    result = CVEMapResult(tool_used="grype")

    if not shutil.which("grype"):
        result.error = "grype가 설치되어 있지 않습니다."
        return result

    if not os.path.isfile(sbom_path):
        result.error = f"SBOM 파일을 찾을 수 없습니다: {sbom_path}"
        return result

    def log(msg):
        if progress:
            progress(msg)

    log("🔍 Grype CVE 스캔 시작...")

    # 환경변수 설정
    grype_env = os.environ.copy()
    grype_env["GRYPE_DB_AUTO_UPDATE"] = "true"
    grype_env["GRYPE_DB_VALIDATE_AGE"] = "false"  # 오래된 DB라도 강제 사용

    # 1단계: VDB 업데이트 시도
    if line_callback:
        line_callback("  📥 취약점 DB 최신화 중 (grype db update)...")
    try:
        db_stdout, db_stderr, db_rc, db_timeout = _run_with_timeout(
            ["grype", "db", "update"], timeout=120,
            line_callback=line_callback, capture_stdout=False, env=grype_env,
        )
        if db_rc == 0:
            if line_callback:
                line_callback("  ✅ 취약점 DB 최신화 완료")
        else:
            if line_callback:
                line_callback(f"  ⚠️ DB 업데이트 실패 (exit {db_rc}) — GRYPE_DB_VALIDATE_AGE=false로 강제 진행")
    except Exception as e:
        if line_callback:
            line_callback(f"  ⚠️ DB 업데이트 오류: {e} — 기존 DB로 진행")

    # 2단계: SBOM 스캔 (stdin 파이프 방식 — Windows 경로 콜론 충돌 회피)
    # grype는 stdin으로 SBOM을 받을 수 있음: cat sbom.json | grype -o json
    cmd = ["grype", "-o", "json"]
    if line_callback:
        line_callback(f"$ [stdin pipe] {sbom_path} → grype -o json")
        line_callback(f"  ⏱️ 타임아웃: {timeout}초")
        line_callback(f"  📋 GRYPE_DB_VALIDATE_AGE=false (DB 만료 무시)")

    t0 = time.time()

    try:
        # SBOM 파일을 stdin으로 전달
        sbom_file = open(sbom_path, "r", encoding="utf-8")

        proc = subprocess.Popen(
            cmd,
            stdin=sbom_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            shell=IS_WIN,
            env=grype_env,
            encoding="utf-8", errors="replace",
        )

        # stderr 실시간 스트리밍 (별도 스레드)
        stderr_lines = []
        timed_out = False

        def _kill():
            nonlocal timed_out
            timed_out = True
            try:
                proc.kill()
            except Exception:
                pass

        timer = threading.Timer(timeout, _kill)
        timer.start()

        def _read_stderr():
            for line in proc.stderr:
                line = line.rstrip("\n\r")
                if line:
                    stderr_lines.append(line)
                    if line_callback:
                        line_callback(line)

        stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
        stderr_thread.start()

        # stdout 읽기 (JSON 결과)
        stdout_data = proc.stdout.read()
        proc.wait(timeout=timeout + 10)
        stderr_thread.join(timeout=5)
        timer.cancel()
        sbom_file.close()

        if timed_out:
            result.error = f"grype 시간 초과 ({time.time()-t0:.0f}초)"
            result.duration = time.time() - t0
            log(f"  ❌ {result.error}")
            return result

        result.duration = time.time() - t0
        output = stdout_data.strip()
        result.raw_output = output
        stderr_text = "\n".join(stderr_lines)

        if output:
            try:
                data = json.loads(output)
                result.success = True
                result.vulns = _parse_grype_results(data)
                _compute_stats(result)
                log(f"  ✅ Grype 완료: {result.total_vulns}건 "
                    f"(🔴{result.critical} 🟠{result.high} "
                    f"🟡{result.medium} 🟢{result.low}) [{result.duration:.1f}초]")
            except json.JSONDecodeError as e:
                result.error = f"Grype JSON 파싱 실패: {e}"
                log(f"  ❌ {result.error}")
                if line_callback:
                    line_callback(f"  📋 stdout 첫 200자: {output[:200]}")
        else:
            rc = proc.returncode or 0
            if rc == 0:
                result.success = True
                log(f"  ✅ Grype 완료: 취약점 0건 ({result.duration:.1f}초)")
            else:
                result.error = f"Grype 실행 실패 (exit {rc}): {stderr_text[:300]}"
                log(f"  ❌ {result.error}")

    except FileNotFoundError:
        result.error = "grype를 실행할 수 없습니다."
    except Exception as e:
        result.error = f"Grype 오류: {e}"
        log(f"  ❌ {result.error}")

    return result


def _parse_grype_results(data: dict) -> List[CVEEntry]:
    """
    Grype JSON 결과 파싱.

    Grype JSON 구조:
    {
      "matches": [{
        "vulnerability": {"id": "CVE-...", "severity": "High", ...},
        "artifact": {"name": "express", "version": "4.17.1", ...}
      }]
    }
    """
    vulns = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        cve_id = vuln.get("id", "")
        if not cve_id:
            continue

        entry = CVEEntry(source="grype")
        entry.cve_id = cve_id
        entry.severity = (vuln.get("severity", "") or "").upper()
        entry.summary = vuln.get("description", "")[:300]
        entry.package_name = artifact.get("name", "")
        entry.package_version = artifact.get("version", "")

        # CVSS 점수
        for cvss_item in vuln.get("cvss", []):
            metrics = cvss_item.get("metrics", {})
            score = metrics.get("baseScore", 0)
            if score:
                entry.cvss_score = score
                entry.cvss_vector = metrics.get("exploitabilityScore", "")
                break

        # CVSS가 없으면 severity 기반 추정
        if not entry.cvss_score and entry.severity:
            approx = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5}
            entry.cvss_score = approx.get(entry.severity, 0)

        # 수정 버전
        fix_info = vuln.get("fix", {})
        fix_versions = fix_info.get("versions", [])
        if fix_versions:
            entry.fixed_version = fix_versions[0]
        elif fix_info.get("state") == "fixed":
            entry.fixed_version = fix_info.get("version", "")

        # 참조 URL
        for url in vuln.get("urls", [])[:3]:
            entry.references.append(url)

        # CWE
        related = vuln.get("relatedVulnerabilities", [])
        for rv in related:
            for cwe in rv.get("cwes", []):
                if isinstance(cwe, str):
                    entry.cwe_ids.append(cwe)
                elif isinstance(cwe, dict):
                    entry.cwe_ids.append(cwe.get("cweId", ""))

        # 별칭 (GHSA 등)
        entry.aliases = vuln.get("aliases", [])

        vulns.append(entry)

    return vulns

    if isinstance(entry.cvss_score, str):
        try:
            entry.cvss_score = float(entry.cvss_score)
        except ValueError:
            entry.cvss_score = 0

    entry.summary = (item.get("short_description", "") or
                     item.get("description", "") or "")[:200]
    entry.package_name = item.get("package", item.get("name", ""))
    entry.package_version = item.get("version", item.get("installed_version", ""))
    entry.fixed_version = item.get("fix_version", item.get("fixed_version", ""))

    # CWE
    cwe = item.get("cwe_id", item.get("problem_type", ""))
    if cwe:
        entry.cwe_ids = [cwe] if isinstance(cwe, str) else cwe

    return entry


# ─────────────────────────────────────────
# 공통
# ─────────────────────────────────────────

def _compute_stats(result: CVEMapResult):
    """통계 계산"""
    result.total_vulns = len(result.vulns)
    for v in result.vulns:
        sev = v.severity.upper()
        if sev == "CRITICAL":
            result.critical += 1
        elif sev == "HIGH":
            result.high += 1
        elif sev == "MEDIUM":
            result.medium += 1
        elif sev == "LOW":
            result.low += 1


def merge_cve_results(*results: CVEMapResult) -> CVEMapResult:
    """여러 CVE 매핑 결과를 병합 (중복 CVE 제거)"""
    merged = CVEMapResult(success=True, tool_used="merged")
    seen_cves = set()

    for r in results:
        if not r or not r.success:
            continue
        for v in r.vulns:
            key = v.cve_id or f"{v.package_name}:{v.package_version}"
            if key not in seen_cves:
                seen_cves.add(key)
                merged.vulns.append(v)
        merged.duration += r.duration

    _compute_stats(merged)
    merged.tool_used = " + ".join(r.tool_used for r in results if r and r.success)
    return merged


def vulns_to_table(vulns: List[CVEEntry]) -> List[dict]:
    """CVE 목록을 테이블용 딕셔너리로 변환"""
    rows = []
    for v in vulns:
        rows.append({
            "심각도": v.severity or "UNKNOWN",
            "CVSS": v.cvss_score,
            "CVE ID": v.cve_id,
            "CWE": ", ".join(v.cwe_ids) if v.cwe_ids else "-",
            "패키지": v.package_name,
            "현재 버전": v.package_version,
            "수정 버전": v.fixed_version or "-",
            "설명": v.summary,
            "출처": v.source,
            "참조": v.references[0] if v.references else "-",
        })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    rows.sort(key=lambda r: (order.get(r["심각도"], 5), -r["CVSS"]))
    return rows
