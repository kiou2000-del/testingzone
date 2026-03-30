"""
🛡️ 사전 패키지 설치 모듈 (다국어 지원)
스캔 대상 프로젝트의 패키지를 원본 버전 그대로 설치합니다.

지원 언어/프레임워크:
  JavaScript/Node.js : package-lock.json, yarn.lock, package.json
  Python             : poetry.lock, Pipfile.lock, requirements.txt, pyproject.toml
  Java               : pom.xml, build.gradle (스캔 전용)
  Go                 : go.mod / go.sum
  C# (.NET)          : .csproj / packages.lock.json
  Ruby               : Gemfile / Gemfile.lock
  Rust               : Cargo.toml / Cargo.lock
  PHP                : composer.json / composer.lock
  Dart/Flutter       : pubspec.yaml / pubspec.lock
  Swift (iOS)        : Podfile / Podfile.lock, Package.swift / Package.resolved
"""
import os
import subprocess
import shutil
from dataclasses import dataclass, field
from typing import Callable, Optional, List


# ─────────────────────────────────────────
# 스캔 제외 디렉토리
# ─────────────────────────────────────────
SKIP_DIRS = {
    "node_modules", ".git", ".svn", ".hg",
    "venv", ".venv", "env", ".env",
    "__pycache__", ".tox", ".pytest_cache",
    "dist", "build", ".next", ".nuxt",
    "vendor", "target", "bin", "obj",
    ".gradle", ".idea", ".vscode",
    ".dart_tool", ".pub-cache",
}

MAX_DEPTH = 5

# ─────────────────────────────────────────
# 매니페스트 정의 (우선순위: lock > 매니페스트)
# ─────────────────────────────────────────
# (파일명, manifest_type, 설명, lock 여부)
MANIFEST_DEFS = [
    # ── JavaScript / Node.js ──
    ("package-lock.json",    "node_lock",    "Node.js (npm ci)",         True),
    ("npm-shrinkwrap.json",  "node_lock",    "Node.js (npm ci)",         True),
    ("yarn.lock",            "node_yarn",    "Node.js (yarn)",           True),
    ("pnpm-lock.yaml",       "node_pnpm",    "Node.js (pnpm)",          True),
    ("package.json",         "node",         "Node.js (npm install)",    False),
    # ── Python ──
    ("poetry.lock",          "python_poetry","Python (poetry)",          True),
    ("Pipfile.lock",         "python_pipenv","Python (pipenv)",          True),
    ("requirements.txt",     "python",       "Python (pip)",             True),
    ("pyproject.toml",       "python_toml",  "Python (pyproject)",       False),
    # ── Go ──
    ("go.sum",               "go_lock",      "Go (go.sum)",              True),
    ("go.mod",               "go",           "Go (go mod)",              False),
    # ── Java ──
    ("pom.xml",              "java_maven",   "Java (Maven)",             False),
    ("build.gradle",         "java_gradle",  "Java (Gradle)",            False),
    ("gradle.lockfile",      "java_gradle_lock", "Java (Gradle lock)",   True),
    # ── C# (.NET) ──
    ("packages.lock.json",   "dotnet_lock",  "C# (NuGet lock)",         True),
    # ── Ruby ──
    ("Gemfile.lock",         "ruby_lock",    "Ruby (Bundler lock)",      True),
    ("Gemfile",              "ruby",         "Ruby (Bundler)",           False),
    # ── Rust ──
    ("Cargo.lock",           "rust_lock",    "Rust (Cargo lock)",        True),
    ("Cargo.toml",           "rust",         "Rust (Cargo)",             False),
    # ── PHP ──
    ("composer.lock",        "php_lock",     "PHP (Composer lock)",      True),
    ("composer.json",        "php",          "PHP (Composer)",           False),
    # ── Dart / Flutter ──
    ("pubspec.lock",         "dart_lock",    "Dart/Flutter (lock)",      True),
    ("pubspec.yaml",         "dart",         "Dart/Flutter",             False),
    # ── Swift (iOS) ──
    ("Podfile.lock",         "swift_pod_lock","Swift (CocoaPods lock)",  True),
    ("Podfile",              "swift_pod",    "Swift (CocoaPods)",        False),
    ("Package.resolved",     "swift_spm_lock","Swift (SPM lock)",       True),
    # ── C / C++ (Build Interception) ──
    ("Makefile",             "cpp_make",     "C/C++ (Makefile)",         False),
    ("CMakeLists.txt",       "cpp_cmake",    "C/C++ (CMake)",            False),
    ("configure",            "cpp_configure","C/C++ (Configure)",        False),
]

# 같은 디렉토리에서 lock이 있으면 매니페스트 건너뛰기 위한 매핑
LOCK_OVERRIDES = {
    "node": {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"},
    "python_toml": {"poetry.lock", "Pipfile.lock"},
    "go": {"go.sum"},
    "ruby": {"Gemfile.lock"},
    "rust": {"Cargo.lock"},
    "php": {"composer.lock"},
    "dart": {"pubspec.lock"},
    "swift_pod": {"Podfile.lock"},
}


# ─────────────────────────────────────────
# 데이터 클래스
# ─────────────────────────────────────────
@dataclass
class ManifestInfo:
    directory: str
    manifest_type: str
    manifest_file: str
    relative_path: str = ""
    description: str = ""
    is_lock: bool = False


@dataclass
class InstallResult:
    manifest: ManifestInfo
    success: bool = False
    command_used: str = ""
    message: str = ""


@dataclass
class PrepareResult:
    success: bool = False
    project_type: str = "unknown"
    command_used: str = ""
    message: str = ""
    logs: list = field(default_factory=list)
    skipped: bool = False
    manifests_found: List[ManifestInfo] = field(default_factory=list)
    install_results: List[InstallResult] = field(default_factory=list)
    total_installed: int = 0
    total_failed: int = 0
    total_skipped: int = 0


# ─────────────────────────────────────────
# 매니페스트 탐색
# ─────────────────────────────────────────
def scan_all_manifests(scan_path: str) -> List[ManifestInfo]:
    """
    루트 및 하위 디렉토리를 재귀 탐색하여 모든 패키지 매니페스트를 찾습니다.
    같은 디렉토리에 lock 파일이 있으면 해당 매니페스트는 제외합니다.
    """
    if os.path.isfile(scan_path):
        return []

    found = []
    root_abs = os.path.abspath(scan_path)

    for dirpath, dirnames, filenames in os.walk(scan_path):
        rel = os.path.relpath(dirpath, scan_path)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if depth > MAX_DEPTH:
            dirnames.clear()
            continue

        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]

        abs_dir = os.path.abspath(dirpath)
        rel_dir = os.path.relpath(abs_dir, root_abs)
        if rel_dir == ".":
            rel_dir = "(루트)"

        filenames_set = set(filenames)

        # 이 디렉토리에서 이미 추가된 타입 추적
        added_types = set()

        for fname, mtype, desc, is_lock in MANIFEST_DEFS:
            if fname not in filenames_set:
                continue

            # lock 파일이 이미 있으면 같은 계열 매니페스트 건너뛰기
            if not is_lock and mtype in LOCK_OVERRIDES:
                override_files = LOCK_OVERRIDES[mtype]
                if override_files & filenames_set:
                    continue

            # 같은 디렉토리에서 같은 계열 중복 방지
            base_type = mtype.split("_")[0]  # node, python, go, ...
            if base_type in added_types and not is_lock:
                continue

            found.append(ManifestInfo(
                directory=abs_dir,
                manifest_type=mtype,
                manifest_file=fname,
                relative_path=rel_dir,
                description=desc,
                is_lock=is_lock,
            ))
            added_types.add(base_type)

    return found


def detect_project_type(scan_path: str) -> str:
    manifests = scan_all_manifests(scan_path)
    if not manifests:
        return "unknown"
    if len(manifests) > 1:
        return "monorepo"
    return manifests[0].manifest_type


# ─────────────────────────────────────────
# 도구 확인
# ─────────────────────────────────────────
def check_tool_available(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


# ─────────────────────────────────────────
# 명령 실행 (실시간 스트리밍)
# ─────────────────────────────────────────
def _run_command_streaming(cmd, cwd, logs, line_callback=None, env=None):
    cmd_str = " ".join(cmd)
    logs.append(f"$ {cmd_str}")
    if line_callback:
        line_callback(f"$ {cmd_str}")
    logs.append(f"  📂 cwd: {cwd}")
    if line_callback:
        line_callback(f"  📂 cwd: {cwd}")

    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            shell=(os.name == "nt"), env=env,
            encoding="utf-8", errors="replace",
        )
        full_output = []
        for line in proc.stdout:
            line = line.rstrip("\n\r")
            if not line:
                continue
            full_output.append(line)
            logs.append(line)
            if line_callback:
                line_callback(line)
        proc.wait(timeout=600)
        return proc.returncode, "\n".join(full_output), ""
    except subprocess.TimeoutExpired:
        proc.kill()
        msg = "[ERROR] 명령 실행 시간 초과 (10분)"
        logs.append(msg)
        if line_callback:
            line_callback(msg)
        return -1, "", "Timeout"
    except FileNotFoundError as e:
        msg = f"[ERROR] 명령을 찾을 수 없음: {e}"
        logs.append(msg)
        if line_callback:
            line_callback(msg)
        return -1, "", str(e)


# ─────────────────────────────────────────
# 개별 매니페스트 설치
# ─────────────────────────────────────────
def _install_one(manifest, logs, line_callback=None, npm_env=None):
    ir = InstallResult(manifest=manifest)
    mtype = manifest.manifest_type
    mdir = manifest.directory

    # ── JavaScript / Node.js ──
    if mtype == "node_lock":
        if not check_tool_available("npm"):
            ir.message = "npm 미설치 — 건너뜀"; return ir
        cmd = ["npm", "ci", "--no-audit", "--no-fund", "--ignore-scripts"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback, env=npm_env)
        if rc != 0:
            if line_callback:
                line_callback("  ⚠️ npm ci 실패 → npm install로 전환")
            cmd2 = ["npm", "install", "--no-audit", "--no-fund", "--ignore-scripts", "--legacy-peer-deps"]
            ir.command_used = " ".join(cmd2)
            rc, _, _ = _run_command_streaming(cmd2, mdir, logs, line_callback, env=npm_env)
        ir.success = (rc == 0)
        ir.message = "npm install 완료" if ir.success else f"실패 (exit {rc})"

    elif mtype == "node":
        if not check_tool_available("npm"):
            ir.message = "npm 미설치 — 건너뜀"; return ir
        cmd = ["npm", "install", "--no-audit", "--no-fund", "--ignore-scripts", "--legacy-peer-deps"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback, env=npm_env)
        ir.success = (rc == 0)
        ir.message = "npm install 완료" if ir.success else f"실패 (exit {rc})"
        # lock 파일 강제 생성
        lock_path = os.path.join(mdir, "package-lock.json")
        if ir.success and not os.path.isfile(lock_path):
            if line_callback:
                line_callback("  🔒 package-lock.json 강제 생성 중...")
            lock_cmd = ["npm", "install", "--package-lock-only", "--no-audit", "--no-fund",
                        "--ignore-scripts", "--legacy-peer-deps"]
            rc2, _, _ = _run_command_streaming(lock_cmd, mdir, logs, line_callback, env=npm_env)
            if rc2 == 0:
                if line_callback: line_callback("  ✅ package-lock.json 생성 완료")

    elif mtype == "node_yarn":
        if not check_tool_available("yarn"):
            ir.message = "yarn 미설치 — 건너뜀"; return ir
        cmd = ["yarn", "install", "--frozen-lockfile", "--ignore-scripts"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "yarn install 완료" if ir.success else f"실패 (exit {rc})"

    elif mtype == "node_pnpm":
        if not check_tool_available("pnpm"):
            ir.message = "pnpm 미설치 — 건너뜀"; return ir
        cmd = ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "pnpm install 완료" if ir.success else f"실패 (exit {rc})"

    # ── Python ──
    elif mtype == "python":
        if not check_tool_available("pip"):
            ir.message = "pip 미설치 — 건너뜀"; return ir
        req_path = os.path.join(mdir, "requirements.txt")
        cmd = ["pip", "install", "-r", req_path]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "pip install 완료" if ir.success else f"실패 (exit {rc})"

    elif mtype == "python_poetry":
        if not check_tool_available("poetry"):
            ir.message = "poetry 미설치 — 건너뜀 (lock 파일은 스캔에 활용)"; ir.success = True; return ir
        cmd = ["poetry", "install", "--no-interaction"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "poetry install 완료" if ir.success else f"실패 (exit {rc})"

    elif mtype == "python_pipenv":
        if not check_tool_available("pipenv"):
            ir.message = "pipenv 미설치 — 건너뜀 (lock 파일은 스캔에 활용)"; ir.success = True; return ir
        cmd = ["pipenv", "install"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "pipenv install 완료" if ir.success else f"실패 (exit {rc})"

    elif mtype == "python_toml":
        if check_tool_available("poetry"):
            cmd = ["poetry", "install", "--no-interaction"]
        elif check_tool_available("pip"):
            cmd = ["pip", "install", "."]
        else:
            ir.message = "pip/poetry 미설치 — 건너뜀"; return ir
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "Python 설치 완료" if ir.success else f"실패 (exit {rc})"

    # ── Go ──
    elif mtype in ("go", "go_lock"):
        if not check_tool_available("go"):
            ir.message = "go 미설치 — 건너뜀 (go.sum은 스캔에 활용)"; ir.success = True; return ir
        cmd = ["go", "mod", "download"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "go mod download 완료" if ir.success else f"실패 (exit {rc})"

    # ── Java ──
    elif mtype == "java_maven":
        if not check_tool_available("mvn"):
            ir.message = "Maven 미설치 — 건너뜀 (pom.xml은 SBOM 생성에 활용)"
            ir.success = True; return ir
        cmd = ["mvn", "dependency:resolve", "-q"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "Maven 의존성 다운로드 완료" if ir.success else f"실패 (exit {rc})"

    elif mtype in ("java_gradle", "java_gradle_lock"):
        if not check_tool_available("gradle"):
            ir.message = "Gradle 미설치 — 건너뜀 (build.gradle은 SBOM 생성에 활용)"
            ir.success = True; return ir
        cmd = ["gradle", "dependencies", "--quiet"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "Gradle 의존성 확인 완료" if ir.success else f"실패 (exit {rc})"

    # ── C# (.NET) ──
    elif mtype == "dotnet_lock":
        if not check_tool_available("dotnet"):
            ir.message = "dotnet 미설치 — 건너뜀 (lock 파일은 스캔에 활용)"; ir.success = True; return ir
        cmd = ["dotnet", "restore"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "dotnet restore 완료" if ir.success else f"실패 (exit {rc})"

    # ── Ruby ──
    elif mtype in ("ruby", "ruby_lock"):
        if not check_tool_available("bundle"):
            ir.message = "Bundler 미설치 — 건너뜀 (lock 파일은 스캔에 활용)"; ir.success = True; return ir
        cmd = ["bundle", "install"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "bundle install 완료" if ir.success else f"실패 (exit {rc})"

    # ── Rust ──
    elif mtype in ("rust", "rust_lock"):
        if not check_tool_available("cargo"):
            ir.message = "Cargo 미설치 — 건너뜀 (lock 파일은 스캔에 활용)"; ir.success = True; return ir
        cmd = ["cargo", "fetch"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "cargo fetch 완료" if ir.success else f"실패 (exit {rc})"

    # ── PHP ──
    elif mtype in ("php", "php_lock"):
        if not check_tool_available("composer"):
            ir.message = "Composer 미설치 — 건너뜀 (lock 파일은 스캔에 활용)"; ir.success = True; return ir
        cmd = ["composer", "install", "--no-interaction", "--no-scripts"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "composer install 완료" if ir.success else f"실패 (exit {rc})"

    # ── Dart / Flutter ──
    elif mtype in ("dart", "dart_lock"):
        if check_tool_available("flutter"):
            cmd = ["flutter", "pub", "get"]
        elif check_tool_available("dart"):
            cmd = ["dart", "pub", "get"]
        else:
            ir.message = "dart/flutter 미설치 — 건너뜀 (lock 파일은 스캔에 활용)"; ir.success = True; return ir
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "pub get 완료" if ir.success else f"실패 (exit {rc})"

    # ── Swift (iOS) ──
    elif mtype in ("swift_pod", "swift_pod_lock"):
        if not check_tool_available("pod"):
            ir.message = "CocoaPods 미설치 — 건너뜀 (lock 파일은 스캔에 활용)"; ir.success = True; return ir
        cmd = ["pod", "install"]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        ir.message = "pod install 완료" if ir.success else f"실패 (exit {rc})"

    elif mtype == "cpp_cmake":
        # CMake는 컴파일 데이터베이스를 쉽게 생성 가능
        if not check_tool_available("cmake"):
            ir.message = "cmake 미설치 — 건너뜀"; return ir
        cmd = ["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "."]
        ir.command_used = " ".join(cmd)
        rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
        ir.success = (rc == 0)
        if ir.success:
            ir.message = "compile_commands.json 생성 완료 (CMake)"
        else:
            ir.message = f"CMake 설정 실패 (exit {rc})"

    elif mtype == "cpp_make":
        # Makefile은 compiledb 또는 bear가 필요함
        tool = None
        if check_tool_available("compiledb"): tool = "compiledb"
        elif check_tool_available("bear"): tool = "bear"
        
        if tool == "compiledb":
            cmd = ["compiledb", "-n", "make"] # -n: 실제 빌드 없이 정보만 추출 시도
            ir.command_used = " ".join(cmd)
            rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
            ir.success = (rc == 0)
            ir.message = "compile_commands.json 추출 완료 (compiledb)" if ir.success else "추출 실패"
        elif tool == "bear":
            cmd = ["bear", "--", "make", "-n"]
            ir.command_used = " ".join(cmd)
            rc, _, _ = _run_command_streaming(cmd, mdir, logs, line_callback)
            ir.success = (rc == 0)
            ir.message = "compile_commands.json 추출 완료 (bear)" if ir.success else "추출 실패"
        else:
            ir.message = "compiledb/bear 미설치 — 빌드 가로채기 건너뜀 (C++ 정밀분석 제한)"
            ir.success = True # 에러는 아니므로 계속 진행

    elif mtype == "cpp_configure":
        ir.message = "configure 확인 완료 — 빌드 전 설정 파일 탐지됨"
        ir.success = True

    else:
        ir.message = f"알 수 없는 타입: {mtype} — 건너뜀"

    return ir


# ─────────────────────────────────────────
# 메인: 사전 설치
# ─────────────────────────────────────────
def prepare_scan(scan_path, progress=None, line_callback=None):
    result = PrepareResult()

    def log(msg):
        result.logs.append(msg)
        if progress: progress(msg)
        if line_callback: line_callback(msg)

    log("🔍 매니페스트 탐색 중... (하위 디렉토리 포함)")
    manifests = scan_all_manifests(scan_path)
    result.manifests_found = manifests

    if not manifests:
        result.skipped = True
        result.success = True
        result.project_type = "unknown"
        result.message = "패키지 매니페스트 없음 — 사전 설치 건너뜀"
        log(result.message)
        return result

    # 타입 요약
    type_counts = {}
    for m in manifests:
        lang = m.manifest_type.split("_")[0]
        type_counts[lang] = type_counts.get(lang, 0) + 1

    type_summary = ", ".join(f"{t}: {c}개" for t, c in type_counts.items())
    result.project_type = "monorepo" if len(manifests) > 1 else manifests[0].manifest_type

    log(f"📦 매니페스트 {len(manifests)}개 발견 ({type_summary})")
    for i, m in enumerate(manifests, 1):
        lock_mark = "🔒" if m.is_lock else "📄"
        log(f"  [{i}] {lock_mark} {m.relative_path}/{m.manifest_file} ({m.description})")
    log("")

    # npm 환경 변수
    npm_env = os.environ.copy()
    npm_env.update({
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
    })

    # 각 매니페스트별 설치
    total = len(manifests)
    for idx, manifest in enumerate(manifests, 1):
        log(f"── [{idx}/{total}] {manifest.relative_path} ({manifest.description}) ──")
        ir = _install_one(manifest, result.logs, line_callback, npm_env)
        result.install_results.append(ir)

        if ir.success:
            result.total_installed += 1
            log(f"  ✅ {ir.message}")
        elif "미설치" in ir.message:
            result.total_skipped += 1
            log(f"  ⏭️ {ir.message}")
        else:
            result.total_failed += 1
            log(f"  ❌ {ir.message}")
        log("")

    result.success = result.total_installed > 0 or result.total_skipped == total
    result.message = (
        f"완료: {result.total_installed}개 설치, "
        f"{result.total_failed}개 실패, "
        f"{result.total_skipped}개 건너뜀 "
        f"(총 {total}개 매니페스트)"
    )
    log(f"📊 {result.message}")
    return result
