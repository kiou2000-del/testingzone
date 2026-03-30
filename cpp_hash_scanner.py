"""
🔍 C/C++ 소스코드 해시 기반 취약점 스캔 모듈

C/C++는 npm, pip 같은 패키지 매니저가 없어서 lock 파일이 존재하지 않습니다.
이 모듈은 소스 파일의 해시를 계산하고, 알려진 오픈소스 라이브러리를 식별하여
OSV(Open Source Vulnerability) API에 취약점을 조회합니다.

워크플로:
  1. C/C++ 소스 파일 탐색 (.c, .h, .cpp, .hpp 등)
  2. 각 파일의 SHA-256 해시 계산
  3. 소스 파일에서 알려진 라이브러리 시그니처 탐색
     (예: #define OPENSSL_VERSION, #define ZLIB_VERSION 등)
  4. 식별된 라이브러리 + 버전으로 OSV API 질의
  5. CVE 결과 반환
"""
import os
import re
import json
import hashlib
import ssl
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Tuple


# ─────────────────────────────────────────
# C/C++ 소스 파일 확장자
# ─────────────────────────────────────────
CPP_EXTENSIONS = {
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx",
    ".c++", ".h++", ".ipp", ".inl", ".inc",
}

SKIP_DIRS = {
    "node_modules", ".git", ".svn", "build", "cmake-build",
    "__pycache__", "venv", ".venv", "vendor",
    "test", "tests", "examples", "doc", "docs",
    "third_party", "3rdparty", "external",
}


# ─────────────────────────────────────────
# 알려진 오픈소스 라이브러리 시그니처
# ─────────────────────────────────────────
# (정규식 패턴, 라이브러리명, OSV ecosystem)
# 헤더 파일에서 버전 문자열을 추출하는 패턴
KNOWN_LIBRARY_SIGNATURES = [
    # OpenSSL
    {
        "name": "openssl",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+OPENSSL_VERSION_TEXT\s+"OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)',
            r'#\s*define\s+OPENSSL_VERSION_STR\s+"([0-9]+\.[0-9]+\.[0-9]+)',
            r'#\s*define\s+SHLIB_VERSION_NUMBER\s+"([0-9]+\.[0-9]+)',
        ],
        "files": ["opensslv.h", "openssl/opensslv.h", "crypto/opensslv.h"],
    },
    # zlib
    {
        "name": "zlib",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+ZLIB_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)',
            r'#\s*define\s+ZLIB_VER_MAJOR\s+([0-9]+)',
        ],
        "files": ["zlib.h"],
    },
    # libpng
    {
        "name": "libpng",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+PNG_LIBPNG_VER_STRING\s+"([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "files": ["png.h", "pngconf.h"],
    },
    # libcurl
    {
        "name": "curl",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+LIBCURL_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "files": ["curl/curlver.h", "curlver.h"],
    },
    # SQLite
    {
        "name": "sqlite3",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+SQLITE_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "files": ["sqlite3.h"],
    },
    # libxml2
    {
        "name": "libxml2",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+LIBXML_DOTTED_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "files": ["libxml/xmlversion.h", "xmlversion.h"],
    },
    # libjpeg / libjpeg-turbo
    {
        "name": "libjpeg-turbo",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+JVERSION\s+"([0-9]+[a-z]?)',
            r'#\s*define\s+LIBJPEG_TURBO_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "files": ["jconfig.h", "jpeglib.h", "jversion.h"],
    },
    # libexpat
    {
        "name": "expat",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+XML_MAJOR_VERSION\s+([0-9]+)',
        ],
        "files": ["expat.h", "expat_external.h"],
    },
    # freetype
    {
        "name": "freetype2",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+FREETYPE_MAJOR\s+([0-9]+)',
        ],
        "files": ["freetype.h", "ft2build.h"],
    },
    # mbedTLS
    {
        "name": "mbedtls",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+MBEDTLS_VERSION_STRING\s+"([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "files": ["mbedtls/version.h", "version.h"],
    },
    # wolfSSL
    {
        "name": "wolfssl",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+LIBWOLFSSL_VERSION_STRING\s+"([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "files": ["wolfssl/version.h"],
    },
    # protobuf
    {
        "name": "protobuf",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+GOOGLE_PROTOBUF_VERSION\s+([0-9]+)',
        ],
        "files": ["google/protobuf/stubs/common.h"],
    },
    # libevent
    {
        "name": "libevent",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+LIBEVENT_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)',
        ],
        "files": ["event2/event.h", "event.h"],
    },
    # Boost
    {
        "name": "boost",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+BOOST_VERSION\s+([0-9]+)',
            r'#\s*define\s+BOOST_LIB_VERSION\s+"([0-9_]+)',
        ],
        "files": ["boost/version.hpp"],
    },
    # nginx (임베디드/라이브러리로 사용 시)
    {
        "name": "nginx",
        "ecosystem": "OSS-Fuzz",
        "patterns": [
            r'#\s*define\s+NGINX_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)',
            r'#\s*define\s+nginx_version\s+([0-9]+)',
        ],
        "files": ["nginx.h", "ngx_core.h"],
    },
]

# 일반적인 버전 추출 패턴 (라이브러리 특정이 아닌 범용)
GENERIC_VERSION_PATTERNS = [
    r'#\s*define\s+VERSION\s+"([0-9]+\.[0-9]+\.?[0-9]*)',
    r'#\s*define\s+PACKAGE_VERSION\s+"([0-9]+\.[0-9]+\.?[0-9]*)',
    r'#\s*define\s+(?:LIB)?[A-Z_]*_VERSION_STRING\s+"([0-9]+\.[0-9]+\.?[0-9]*)',
    r'#\s*define\s+(?:LIB)?[A-Z_]*_VERSION\s+"([0-9]+\.[0-9]+\.?[0-9]*)',
]


# ─────────────────────────────────────────
# 데이터 클래스
# ─────────────────────────────────────────
@dataclass
class FileHashInfo:
    """개별 파일의 해시 정보"""
    file_path: str
    relative_path: str
    sha256: str
    size: int


@dataclass
class IdentifiedLibrary:
    """식별된 오픈소스 라이브러리"""
    name: str
    version: str
    ecosystem: str
    confidence: str  # "high", "medium", "low"
    source_file: str  # 버전이 발견된 파일
    matched_pattern: str


@dataclass
class CppScanResult:
    """C/C++ 해시 스캔 결과"""
    total_files: int = 0
    total_hashed: int = 0
    file_hashes: List[FileHashInfo] = field(default_factory=list)
    identified_libs: List[IdentifiedLibrary] = field(default_factory=list)
    osv_results: list = field(default_factory=list)  # CVEEntry 리스트
    duration: float = 0.0
    error: str = ""


# ─────────────────────────────────────────
# 파일 해시 계산
# ─────────────────────────────────────────
def compute_file_hash(file_path: str) -> Tuple[str, int]:
    """파일의 SHA-256 해시와 크기를 계산합니다."""
    sha256 = hashlib.sha256()
    size = 0
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
                size += len(chunk)
        return sha256.hexdigest(), size
    except Exception:
        return "", 0


# ─────────────────────────────────────────
# 소스 파일에서 라이브러리 시그니처 탐색
# ─────────────────────────────────────────
def identify_libraries(
    scan_path: str,
    line_callback: Optional[Callable] = None,
) -> Tuple[List[FileHashInfo], List[IdentifiedLibrary]]:
    """
    C/C++ 소스 파일을 탐색하여:
    1. 각 파일의 SHA-256 해시 계산
    2. 알려진 라이브러리 시그니처 매칭
    """
    file_hashes = []
    identified = []
    seen_libs = set()  # 중복 방지

    for dirpath, dirnames, filenames in os.walk(scan_path):
        # 제외 디렉토리
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith(".")]

        # 깊이 제한
        rel = os.path.relpath(dirpath, scan_path)
        if rel != "." and rel.count(os.sep) >= 8:
            dirnames.clear()
            continue

        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in CPP_EXTENSIONS:
                continue

            full_path = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(full_path, scan_path)

            # 1. 해시 계산
            sha256, size = compute_file_hash(full_path)
            if sha256:
                file_hashes.append(FileHashInfo(
                    file_path=full_path,
                    relative_path=rel_path,
                    sha256=sha256,
                    size=size,
                ))

            # 2. 라이브러리 시그니처 매칭 (헤더 파일 중심)
            fname_lower = fname.lower()
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(50000)  # 상위 50KB만 읽기
            except Exception:
                continue

            # 알려진 라이브러리별 패턴 매칭
            for lib_def in KNOWN_LIBRARY_SIGNATURES:
                lib_name = lib_def["name"]
                if lib_name in seen_libs:
                    continue

                # 대상 파일인지 확인 (선택적)
                target_files = lib_def.get("files", [])
                is_target = not target_files or any(
                    rel_path.replace("\\", "/").endswith(tf) for tf in target_files
                )

                for pattern in lib_def["patterns"]:
                    match = re.search(pattern, content)
                    if match:
                        version = match.group(1)
                        confidence = "high" if is_target else "medium"
                        identified.append(IdentifiedLibrary(
                            name=lib_name,
                            version=version,
                            ecosystem=lib_def["ecosystem"],
                            confidence=confidence,
                            source_file=rel_path,
                            matched_pattern=pattern[:60],
                        ))
                        seen_libs.add(lib_name)
                        if line_callback:
                            line_callback(f"  🔍 {lib_name} v{version} 발견 ({rel_path})")
                        break

            # 범용 버전 패턴 (라이브러리 특정이 아닌)
            # 파일명에서 라이브러리명 추정
            base_name = os.path.splitext(fname)[0].lower()
            if base_name not in seen_libs and ext == ".h":
                for pattern in GENERIC_VERSION_PATTERNS:
                    match = re.search(pattern, content)
                    if match:
                        version = match.group(1)
                        if version and len(version) >= 3:  # 최소 "1.0"
                            identified.append(IdentifiedLibrary(
                                name=base_name,
                                version=version,
                                ecosystem="",  # 범용
                                confidence="low",
                                source_file=rel_path,
                                matched_pattern=pattern[:60],
                            ))
                            seen_libs.add(base_name)
                            break

    return file_hashes, identified


# ─────────────────────────────────────────
# OSV API 질의
# ─────────────────────────────────────────
def _query_osv_batch(queries: list) -> list:
    """
    OSV API 배치 질의.
    https://api.osv.dev/v1/querybatch

    Args:
        queries: [{"package": {"name": "...", "ecosystem": "..."}, "version": "..."}]

    Returns:
        결과 리스트
    """
    url = "https://api.osv.dev/v1/querybatch"
    payload = json.dumps({"queries": queries}).encode("utf-8")

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "SBOM-Generator/2.2",
            },
        )
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}


def _query_osv_single(commit_hash: str) -> dict:
    """OSV API 단건 질의 (커밋/해시 기반)."""
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({"commit": commit_hash}).encode("utf-8")

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "SBOM-Generator/2.2",
            },
        )
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}


# ─────────────────────────────────────────
# 메인: C/C++ 해시 스캔
# ─────────────────────────────────────────
def scan_cpp_hashes(
    scan_path: str,
    line_callback: Optional[Callable] = None,
) -> CppScanResult:
    """
    C/C++ 프로젝트를 해시 기반으로 스캔합니다.

    1단계: 소스 파일 SHA-256 해시 계산
    2단계: 알려진 오픈소스 라이브러리 시그니처 매칭
    3단계: 식별된 라이브러리로 OSV API 취약점 조회

    Args:
        scan_path: 스캔 대상 디렉토리
        line_callback: 실시간 로그 콜백

    Returns:
        CppScanResult
    """
    import time
    t0 = time.time()
    result = CppScanResult()

    def cb(msg):
        if line_callback:
            line_callback(msg)

    cb("🔍 C/C++ 소스코드 해시 스캔 시작...")
    cb(f"  📂 스캔 경로: {scan_path}")

    # 1단계: 파일 해시 계산 + 라이브러리 시그니처 매칭
    cb("  📊 파일 해시 계산 + 라이브러리 식별 중...")
    file_hashes, identified_libs = identify_libraries(scan_path, line_callback)
    result.file_hashes = file_hashes
    result.identified_libs = identified_libs
    result.total_files = len(file_hashes)

    cb(f"  📄 C/C++ 파일: {len(file_hashes)}개 (SHA-256 해시 계산 완료)")
    cb(f"  🔧 식별된 라이브러리: {len(identified_libs)}개")

    # 해시 요약 (상위 5개만 표시)
    for fh in file_hashes[:5]:
        cb(f"    {fh.sha256[:16]}... {fh.relative_path} ({fh.size:,}B)")
    if len(file_hashes) > 5:
        cb(f"    ... 외 {len(file_hashes) - 5}개")

    # 식별된 라이브러리 상세
    if identified_libs:
        cb("")
        cb("  🔧 식별된 오픈소스 라이브러리:")
        for lib in identified_libs:
            conf_icon = {"high": "🟢", "medium": "🟡", "low": "⚪"}.get(lib.confidence, "⚪")
            cb(f"    {conf_icon} {lib.name} v{lib.version} [{lib.confidence}] ← {lib.source_file}")

    # 2단계: OSV API 질의 (식별된 라이브러리만)
    if not identified_libs:
        cb("")
        cb("  ℹ️  알려진 라이브러리 시그니처를 찾지 못함")
        cb("     (소스코드가 자체 개발 코드이거나, 지원되지 않는 라이브러리일 수 있음)")
        result.duration = time.time() - t0
        return result

    cb("")
    cb("  🌐 OSV API로 취약점 조회 중...")

    # 배치 질의 구성
    queries = []
    query_map = []  # 인덱스 ↔ 라이브러리 매핑

    for lib in identified_libs:
        if lib.confidence == "low":
            continue  # 낮은 신뢰도는 API 질의 건너뜀

        query = {"version": lib.version}
        if lib.ecosystem:
            query["package"] = {"name": lib.name, "ecosystem": lib.ecosystem}
        else:
            query["package"] = {"name": lib.name}

        queries.append(query)
        query_map.append(lib)

    if not queries:
        cb("  ℹ️  높은 신뢰도의 라이브러리가 없어 API 질의 건너뜀")
        result.duration = time.time() - t0
        return result

    cb(f"  📡 {len(queries)}개 라이브러리 질의 중...")

    # API 호출
    from cve_mapper import CVEEntry
    api_result = _query_osv_batch(queries)

    if isinstance(api_result, dict) and "error" in api_result:
        cb(f"  ❌ OSV API 오류: {api_result['error']}")
        result.error = api_result["error"]
        result.duration = time.time() - t0
        return result

    # 결과 파싱
    results_list = api_result.get("results", [])
    for idx, res in enumerate(results_list):
        vulns = res.get("vulns", [])
        if not vulns or idx >= len(query_map):
            continue

        lib = query_map[idx]
        for vuln in vulns:
            entry = CVEEntry(source="osv-hash")
            entry.cve_id = vuln.get("id", "")

            # 심각도 추출
            severity_list = vuln.get("severity", [])
            if severity_list:
                for sev in severity_list:
                    score_str = sev.get("score", "")
                    if score_str:
                        try:
                            entry.cvss_score = float(score_str.split("/")[0]) if "/" in score_str else float(score_str)
                        except (ValueError, IndexError):
                            pass

            # CVSS → severity 매핑
            if entry.cvss_score >= 9.0:
                entry.severity = "CRITICAL"
            elif entry.cvss_score >= 7.0:
                entry.severity = "HIGH"
            elif entry.cvss_score >= 4.0:
                entry.severity = "MEDIUM"
            elif entry.cvss_score > 0:
                entry.severity = "LOW"
            else:
                # DB에서 severity 직접 가져오기
                db_specific = vuln.get("database_specific", {})
                entry.severity = (db_specific.get("severity", "") or "UNKNOWN").upper()
                if entry.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    approx = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5}
                    entry.cvss_score = approx.get(entry.severity, 0)

            entry.package_name = lib.name
            entry.package_version = lib.version
            entry.summary = vuln.get("summary", "")[:300]

            # 수정 버전
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            entry.fixed_version = event["fixed"]

            # 참조
            for ref in vuln.get("references", [])[:3]:
                entry.references.append(ref.get("url", ""))

            # 별칭 (CVE-XXXX 등)
            entry.aliases = vuln.get("aliases", [])
            # 별칭에 CVE ID가 있으면 교체
            for alias in entry.aliases:
                if alias.startswith("CVE-"):
                    entry.cve_id = alias
                    break

            result.osv_results.append(entry)

    # 결과 요약
    result.duration = time.time() - t0
    total = len(result.osv_results)
    if total > 0:
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in result.osv_results:
            sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1
        cb(f"  ✅ C/C++ 해시 스캔 완료: {total}건 취약점 "
           f"(🔴{sev_counts.get('CRITICAL',0)} 🟠{sev_counts.get('HIGH',0)} "
           f"🟡{sev_counts.get('MEDIUM',0)} 🟢{sev_counts.get('LOW',0)}) "
           f"[{result.duration:.1f}초]")
    else:
        cb(f"  ✅ C/C++ 해시 스캔 완료: 취약점 0건 ({result.duration:.1f}초)")

    return result
