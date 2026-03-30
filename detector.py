"""
1차 검증: 바이너리 vs 소스코드 판별
프로젝트 경로를 분석하여 바이너리/소스코드 유형을 결정합니다.
"""
import os
from dataclasses import dataclass, field
from typing import List, Tuple

# 바이너리 파일 확장자
BINARY_EXTENSIONS = {
    # 실행 파일
    ".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".axf",
    ".com", ".sys", ".drv", ".ocx", ".scr",
    # 오브젝트/라이브러리
    ".o", ".obj", ".a", ".lib", ".ko",
    # 패키지/아카이브 (이미 빌드된)
    ".jar", ".war", ".ear", ".aar",
    ".whl", ".egg", ".gem",
    ".deb", ".rpm", ".apk", ".ipa", ".msi",
    ".nupkg", ".crate",
    # 컨테이너
    ".tar", ".img", ".iso", ".qcow2", ".vmdk",
    # 펌웨어
    ".hex", ".srec", ".s19", ".fw", ".rom",
    # 기타 바이너리
    ".class", ".pyc", ".pyo", ".beam", ".wasm",
}

# 소스코드 파일 확장자
SOURCE_EXTENSIONS = {
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh",
    ".java", ".kt", ".kts", ".scala", ".groovy", ".gradle",
    ".py", ".pyw", ".pyx",
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".vue", ".svelte",
    ".go", ".rs", ".swift", ".dart",
    ".rb", ".erb", ".php", ".lua", ".pl", ".pm",
    ".cs", ".vb", ".fs",
    ".sh", ".bash", ".bat", ".ps1",
    ".asm", ".s", ".inc",
    ".sql", ".html", ".css", ".scss",
    ".xml", ".json", ".yaml", ".yml", ".toml",
    ".r", ".R", ".jl", ".ex", ".erl", ".hs",
    ".m", ".mm",  # Objective-C
}

# 의존성 매니페스트 파일 (소스코드 확정)
MANIFEST_FILES = {
    # JavaScript / Node.js
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    # Python
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock",
    "setup.py", "setup.cfg",
    # Java
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "gradle.lockfile",
    # Go
    "go.mod", "go.sum",
    # Rust
    "Cargo.toml", "Cargo.lock",
    # Ruby
    "Gemfile", "Gemfile.lock",
    # PHP
    "composer.json", "composer.lock",
    # Dart / Flutter
    "pubspec.yaml", "pubspec.lock",
    # Swift (iOS)
    "Package.swift", "Package.resolved", "Podfile", "Podfile.lock",
    # C / C++
    "CMakeLists.txt", "Makefile", "configure",
    "vcpkg.json", "conanfile.txt", "conanfile.py", "conan.lock",
    # C# (.NET)
    ".csproj", ".vbproj", ".fsproj", "packages.config",
    "packages.lock.json", "project.assets.json",
}


@dataclass
class DetectionResult:
    """검증 결과"""
    input_type: str = "unknown"  # "binary", "source", "mixed", "unknown"
    confidence: float = 0.0
    total_files: int = 0
    binary_files: int = 0
    source_files: int = 0
    manifest_files: int = 0
    binary_list: List[str] = field(default_factory=list)
    source_list: List[str] = field(default_factory=list)
    manifest_list: List[str] = field(default_factory=list)
    recommended_tool: str = ""   # "syft" or "cdxgen"
    details: str = ""


def detect_input_type(path: str, max_scan: int = 5000) -> DetectionResult:
    """
    1차 검증: 입력 경로가 바이너리인지 소스코드인지 판별합니다.

    Args:
        path: 분석할 파일 또는 디렉토리 경로
        max_scan: 최대 스캔 파일 수

    Returns:
        DetectionResult
    """
    result = DetectionResult()

    # 단일 파일인 경우
    if os.path.isfile(path):
        _, ext = os.path.splitext(path)
        ext = ext.lower()
        if ext in BINARY_EXTENSIONS:
            result.input_type = "binary"
            result.confidence = 1.0
            result.binary_files = 1
            result.binary_list = [path]
            result.recommended_tool = "syft"
            result.details = f"단일 바이너리 파일: {os.path.basename(path)}"
        else:
            result.input_type = "source"
            result.confidence = 0.9
            result.source_files = 1
            result.source_list = [path]
            result.recommended_tool = "cdxgen"
            result.details = f"단일 소스 파일: {os.path.basename(path)}"
        result.total_files = 1
        return result

    # 디렉토리인 경우
    if not os.path.isdir(path):
        result.details = f"경로를 찾을 수 없음: {path}"
        return result

    skip_dirs = {
        "node_modules", ".git", ".svn", "__pycache__", ".tox",
        "venv", ".venv", ".gradle", ".idea", ".vscode",
    }

    scanned = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]

        for fname in filenames:
            if scanned >= max_scan:
                break
            scanned += 1

            _, ext = os.path.splitext(fname)
            ext = ext.lower()
            rel = os.path.relpath(os.path.join(dirpath, fname), path)

            if ext in BINARY_EXTENSIONS:
                result.binary_files += 1
                if len(result.binary_list) < 50:
                    result.binary_list.append(rel)
            elif ext in SOURCE_EXTENSIONS or fname in MANIFEST_FILES:
                result.source_files += 1
                if len(result.source_list) < 50:
                    result.source_list.append(rel)

            if fname in MANIFEST_FILES or ext in (".csproj", ".vbproj", ".fsproj"):
                result.manifest_files += 1
                if len(result.manifest_list) < 30:
                    result.manifest_list.append(rel)

    result.total_files = scanned

    # 판정
    total = result.binary_files + result.source_files
    if total == 0:
        result.input_type = "unknown"
        result.confidence = 0.0
        result.details = "인식 가능한 파일을 찾지 못했습니다."
        return result

    binary_ratio = result.binary_files / total if total > 0 else 0

    if binary_ratio > 0.7:
        result.input_type = "binary"
        result.confidence = binary_ratio
        result.recommended_tool = "syft"
        result.details = (f"바이너리 프로젝트 (바이너리 {result.binary_files}개, "
                          f"소스 {result.source_files}개)")
    elif binary_ratio < 0.3:
        result.input_type = "source"
        result.confidence = 1 - binary_ratio
        result.recommended_tool = "cdxgen"
        result.details = (f"소스코드 프로젝트 (소스 {result.source_files}개, "
                          f"매니페스트 {result.manifest_files}개)")
    else:
        result.input_type = "mixed"
        result.confidence = 0.5
        result.recommended_tool = "cdxgen"  # 소스 우선
        result.details = (f"혼합 프로젝트 (바이너리 {result.binary_files}개, "
                          f"소스 {result.source_files}개)")

    return result
