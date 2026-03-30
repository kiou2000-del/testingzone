"""
🔍 SAST (Static Application Security Testing) 스캔 모듈
Semgrep CLI를 백엔드에서 실행하여 소스코드 취약점을 분석합니다.

워크플로:
  1. 대상 코드 준비 (폴더 경로 / ZIP 업로드 / Git URL)
  2. semgrep scan --json [대상폴더] 실행
  3. JSON 결과 파싱 → 핵심 데이터 추출
  4. 임시 폴더 정리
  5. 요약 카드용 데이터 반환

추출 항목:
  - 총 취약점 개수
  - 심각도별 개수 (ERROR/WARNING/INFO → High/Medium/Low)
  - 주요 CWE 번호 + 설명
  - 취약점 발생 파일명 + 라인 수
"""
import os
import json
import shutil
import subprocess
import tempfile
import threading
import time
import platform
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict
from collections import Counter

IS_WIN = platform.system() == "Windows"


# ─────────────────────────────────────────
# 데이터 클래스
# ─────────────────────────────────────────
@dataclass
class SASTFinding:
    """개별 SAST 취약점"""
    rule_id: str = ""           # semgrep 규칙 ID
    severity: str = ""          # HIGH / MEDIUM / LOW
    message: str = ""           # 취약점 설명
    file_path: str = ""         # 발생 파일 (상대 경로)
    line_start: int = 0         # 시작 라인
    line_end: int = 0           # 종료 라인
    code_snippet: str = ""      # 취약 코드 스니펫
    cwe_ids: List[str] = field(default_factory=list)  # CWE 번호
    owasp_ids: List[str] = field(default_factory=list) # OWASP 카테고리
    fix_suggestion: str = ""    # 수정 제안
    reference_url: str = ""     # 참조 URL


@dataclass
class CWESummary:
    """CWE 요약 정보"""
    cwe_id: str = ""
    name: str = ""
    count: int = 0


@dataclass
class SASTResult:
    """SAST 스캔 전체 결과"""
    success: bool = False
    scan_path: str = ""

    # 통계
    total_findings: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # 상세 데이터
    findings: List[SASTFinding] = field(default_factory=list)
    top_cwes: List[CWESummary] = field(default_factory=list)
    affected_files: List[str] = field(default_factory=list)
    file_finding_counts: Dict[str, int] = field(default_factory=dict)

    # 메타
    duration: float = 0.0
    error: str = ""
    semgrep_version: str = ""
    rules_used: int = 0
    files_scanned: int = 0
    raw_output: str = ""
    logs: List[str] = field(default_factory=list)


# ─────────────────────────────────────────
# CWE 이름 매핑 (주요 CWE)
# ─────────────────────────────────────────
CWE_NAMES = {
    "CWE-20": "부적절한 입력 검증",
    "CWE-22": "경로 탐색 (Path Traversal)",
    "CWE-78": "OS 명령 인젝션",
    "CWE-79": "크로스 사이트 스크립팅 (XSS)",
    "CWE-89": "SQL 인젝션",
    "CWE-94": "코드 인젝션",
    "CWE-95": "Eval 인젝션",
    "CWE-200": "민감 정보 노출",
    "CWE-209": "에러 메시지 정보 노출",
    "CWE-215": "디버그 정보 노출",
    "CWE-250": "불필요한 권한으로 실행",
    "CWE-259": "하드코딩된 비밀번호",
    "CWE-276": "잘못된 기본 권한",
    "CWE-295": "부적절한 인증서 검증",
    "CWE-312": "민감 데이터 평문 저장",
    "CWE-319": "민감 데이터 평문 전송",
    "CWE-326": "부적절한 암호화 강도",
    "CWE-327": "취약한 암호화 알고리즘",
    "CWE-328": "약한 해시 사용",
    "CWE-330": "불충분한 난수성",
    "CWE-338": "암호학적으로 약한 PRNG",
    "CWE-352": "CSRF (크로스 사이트 요청 위조)",
    "CWE-400": "자원 고갈 (DoS)",
    "CWE-434": "위험한 파일 업로드",
    "CWE-502": "안전하지 않은 역직렬화",
    "CWE-522": "불충분한 자격증명 보호",
    "CWE-601": "오픈 리다이렉트",
    "CWE-611": "XXE (XML 외부 엔티티)",
    "CWE-614": "HTTPS 세션 쿠키 미설정",
    "CWE-693": "보호 메커니즘 미적용",
    "CWE-798": "하드코딩된 인증 정보",
    "CWE-918": "SSRF (서버 사이드 요청 위조)",
    "CWE-1004": "HttpOnly 쿠키 미설정",
}


# ─────────────────────────────────────────
# Semgrep 설치 확인
# ─────────────────────────────────────────
def check_semgrep() -> tuple:
    """Semgrep 설치 상태 확인. (설치여부, 버전)."""
    path = shutil.which("semgrep")
    if not path:
        return False, ""
    try:
        r = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace",
            shell=IS_WIN,
        )
        ver = (r.stdout.strip() or r.stderr.strip() or "").split("\n")[0]
        return True, ver if ver else "(installed)"
    except Exception:
        return True, "(installed)"


# ─────────────────────────────────────────
# Semgrep 실행 (타임아웃 + 실시간 로그)
# ─────────────────────────────────────────
def _run_semgrep(
    target_path: str,
    config: str = "auto",
    timeout: int = 600,
    line_callback: Optional[Callable] = None,
) -> tuple:
    """
    semgrep scan --json 실행.
    config: "auto" (온라인) 또는 로컬 규칙 파일 경로
    반환: (json_output, stderr_text, returncode, timed_out)
    """
    cmd = [
        "semgrep", "scan",
        "--config", config,
        "--json",
        "--timeout", "300",
        "--max-target-bytes", "5000000",
        target_path,
    ]

    if line_callback:
        line_callback(f"$ {' '.join(cmd)}")
        if config == "auto":
            line_callback("  📋 --config auto: Semgrep 공식 보안 규칙셋 (온라인)")
        else:
            line_callback(f"  📋 --config {os.path.basename(config)}: 로컬 내장 보안 규칙셋 (오프라인)")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,  # 바이너리 모드로 읽음
        shell=IS_WIN,
    )

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
        # 바이너리로 읽어서 수동 디코딩
        for raw in proc.stderr:
            try:
                line = raw.decode("utf-8", errors="replace").rstrip("\n\r")
                if line:
                    stderr_lines.append(line)
                    if line_callback:
                        line_callback(line)
            except Exception:
                pass

    t = threading.Thread(target=_read_stderr, daemon=True)
    t.start()

    stdout_raw = proc.stdout.read()
    proc.wait(timeout=timeout + 10)
    t.join(timeout=5)
    timer.cancel()

    # stdout 결과도 수동 디코딩
    stdout_data = stdout_raw.decode("utf-8", errors="replace")
    return stdout_data, "\n".join(stderr_lines), proc.returncode or 0, timed_out


# ─────────────────────────────────────────
# JSON 결과 파싱
# ─────────────────────────────────────────
def _parse_semgrep_json(raw_json: str, scan_path: str) -> SASTResult:
    """Semgrep JSON 결과를 파싱하여 SASTResult로 변환."""
    result = SASTResult(success=True, scan_path=scan_path)

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        result.success = False
        result.error = f"Semgrep JSON 파싱 실패: {e}"
        return result

    # Semgrep JSON 구조: {"results": [...], "errors": [...], "paths": {...}}
    raw_results = data.get("results", [])
    paths_info = data.get("paths", {})
    result.files_scanned = len(paths_info.get("scanned", []))

    # severity 매핑: Semgrep severity → 표준 severity
    SEV_MAP = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    cwe_counter = Counter()
    file_counter = Counter()
    seen_rules = set()

    for item in raw_results:
        finding = SASTFinding()

        # 규칙 ID
        finding.rule_id = item.get("check_id", "")
        seen_rules.add(finding.rule_id)

        # 심각도
        extra = item.get("extra", {})
        sev_raw = extra.get("severity", "INFO").upper()
        finding.severity = SEV_MAP.get(sev_raw, "LOW")

        # 메시지
        finding.message = extra.get("message", "")

        # 파일 위치
        finding.file_path = item.get("path", "")
        # 상대 경로로 변환
        if scan_path and finding.file_path.startswith(scan_path):
            finding.file_path = os.path.relpath(finding.file_path, scan_path)
        finding.file_path = finding.file_path.replace("\\", "/")

        start = item.get("start", {})
        end = item.get("end", {})
        finding.line_start = start.get("line", 0)
        finding.line_end = end.get("line", 0)

        # 코드 스니펫
        lines = extra.get("lines", "")
        finding.code_snippet = lines[:300] if lines else ""

        # CWE / OWASP 메타데이터
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        for cwe in cwe_list:
            # "CWE-79: Improper Neutralization..." → "CWE-79"
            cwe_id = cwe.split(":")[0].strip() if ":" in cwe else cwe.strip()
            if cwe_id.startswith("CWE-"):
                finding.cwe_ids.append(cwe_id)
                cwe_counter[cwe_id] += 1

        owasp_list = metadata.get("owasp", [])
        if isinstance(owasp_list, str):
            owasp_list = [owasp_list]
        finding.owasp_ids = owasp_list[:5]

        # 참조 URL
        refs = metadata.get("references", [])
        if refs:
            finding.reference_url = refs[0] if isinstance(refs, list) else str(refs)

        # 수정 제안
        finding.fix_suggestion = extra.get("fix", "") or metadata.get("fix", "")

        result.findings.append(finding)
        file_counter[finding.file_path] += 1

    # 통계 계산
    result.total_findings = len(result.findings)
    result.high_count = sum(1 for f in result.findings if f.severity == "HIGH")
    result.medium_count = sum(1 for f in result.findings if f.severity == "MEDIUM")
    result.low_count = sum(1 for f in result.findings if f.severity == "LOW")
    result.rules_used = len(seen_rules)

    # Top CWE
    for cwe_id, count in cwe_counter.most_common(10):
        name = CWE_NAMES.get(cwe_id, "")
        result.top_cwes.append(CWESummary(cwe_id=cwe_id, name=name, count=count))

    # 영향받은 파일
    result.file_finding_counts = dict(file_counter.most_common(20))
    result.affected_files = list(file_counter.keys())

    return result


# ─────────────────────────────────────────
# 메인: SAST 스캔
# ─────────────────────────────────────────
def run_sast_scan(
    scan_path: str,
    progress: Optional[Callable] = None,
    line_callback: Optional[Callable] = None,
    timeout: int = 600,
) -> SASTResult:
    """
    Semgrep으로 SAST 스캔을 실행합니다.

    Args:
        scan_path: 스캔 대상 디렉토리 경로
        progress: 단계 진행 콜백
        line_callback: 실시간 로그 콜백
        timeout: 초 단위 타임아웃

    Returns:
        SASTResult
    """
    result = SASTResult(scan_path=scan_path)
    t0 = time.time()

    def log(msg):
        result.logs.append(msg)
        if progress:
            progress(msg)

    def cb(msg):
        result.logs.append(msg)
        if line_callback:
            line_callback(msg)

    # 1. Semgrep 확인
    installed, ver = check_semgrep()
    if not installed:
        result.error = "Semgrep이 설치되어 있지 않습니다. pip install semgrep"
        log(f"❌ {result.error}")
        return result

    result.semgrep_version = ver
    log(f"🔍 SAST 스캔 시작 (Semgrep {ver})")
    cb(f"  📂 대상: {scan_path}")
    cb(f"  ⏱️ 타임아웃: {timeout}초")

    # 2. 대상 확인
    if not os.path.isdir(scan_path):
        result.error = f"스캔 대상을 찾을 수 없습니다: {scan_path}"
        log(f"❌ {result.error}")
        return result

    # 3. Semgrep 실행 (auto → 로컬 규칙 자동 fallback)
    # 로컬 규칙 파일 경로
    _app_dir = os.path.dirname(os.path.abspath(__file__))
    _local_rules = os.path.join(_app_dir, "semgrep-rules.yml")

    cb("  🚀 Semgrep 스캔 실행 중...")

    # 1차: --config auto (온라인 규칙)
    cb("  📡 1차 시도: 온라인 규칙셋 (--config auto)")
    stdout, stderr_text, rc, was_timeout = _run_semgrep(
        scan_path, config="auto", timeout=timeout, line_callback=line_callback,
    )

    # SSL 에러 / 네트워크 실패 감지 → 로컬 규칙으로 fallback
    if rc >= 2 and not was_timeout:
        is_network_error = any(kw in stderr_text.lower() for kw in [
            "ssl", "certificate", "connection", "timeout", "network",
            "httpsconnectionpool", "max retries", "urlopen",
        ])
        if is_network_error and os.path.isfile(_local_rules):
            cb("")
            cb("  ⚠️ 온라인 규칙 다운로드 실패 (SSL/네트워크 오류)")
            cb("  🔄 2차 시도: 로컬 내장 규칙셋으로 전환")
            stdout, stderr_text, rc, was_timeout = _run_semgrep(
                scan_path, config=_local_rules, timeout=timeout, line_callback=line_callback,
            )
        elif not os.path.isfile(_local_rules):
            cb("  ❌ 로컬 규칙 파일(semgrep-rules.yml)도 없음 — 스캔 불가")

    if was_timeout:
        result.error = f"Semgrep 시간 초과 ({time.time()-t0:.0f}초)"
        result.duration = time.time() - t0
        log(f"❌ {result.error}")
        return result

    result.raw_output = stdout

    # 4. 결과 파싱
    # Semgrep exit codes: 0=취약점 없음, 1=취약점 발견, 2+=에러
    if stdout.strip() and rc in (0, 1):
        parsed = _parse_semgrep_json(stdout, scan_path)
        result.success = parsed.success
        result.total_findings = parsed.total_findings
        result.high_count = parsed.high_count
        result.medium_count = parsed.medium_count
        result.low_count = parsed.low_count
        result.findings = parsed.findings
        result.top_cwes = parsed.top_cwes
        result.affected_files = parsed.affected_files
        result.file_finding_counts = parsed.file_finding_counts
        result.rules_used = parsed.rules_used
        result.files_scanned = parsed.files_scanned
        if parsed.error:
            result.error = parsed.error
    elif rc == 0 and not stdout.strip():
        result.success = True
        result.total_findings = 0
    else:
        # rc >= 2: 실제 에러
        err_detail = stderr_text[:500] if stderr_text else "(stderr 없음)"
        result.error = f"Semgrep 실행 실패 (exit {rc})"
        cb(f"  ❌ exit code: {rc}")
        if stderr_text:
            for line in stderr_text.split("\n")[:10]:
                cb(f"  📋 {line}")
        else:
            cb("  📋 stderr 없음 — Semgrep 내부 오류 가능성")
            cb("  💡 수동 테스트: semgrep scan --config auto --json [경로]")

    result.duration = time.time() - t0

    # 5. 결과 요약 로그
    if result.success:
        log(f"✅ SAST 스캔 완료: {result.total_findings}건 취약점 "
            f"(🔴 High {result.high_count} · 🟡 Medium {result.medium_count} · "
            f"🔵 Low {result.low_count}) [{result.duration:.1f}초]")
        if result.top_cwes:
            log(f"  🔥 Top CWE: {', '.join(c.cwe_id for c in result.top_cwes[:3])}")
        log(f"  📄 스캔 파일: {result.files_scanned}개 · 규칙: {result.rules_used}개")
    else:
        log(f"❌ SAST 스캔 실패: {result.error}")

    return result
