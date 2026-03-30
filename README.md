# 🛡️ SBOM Generator & Vulnerability Scanner

소프트웨어 구성 요소(SBOM)를 자동 생성하고, 알려진 보안 취약점(CVE)을 스캔하는 올인원 도구입니다.

---

## 📋 목차

- [개요](#개요)
- [지원 환경](#지원-환경)
- [설치 방법](#설치-방법)
- [사용 방법](#사용-방법)
- [분석 파이프라인](#분석-파이프라인)
- [사이드바 설정](#사이드바-설정)
- [결과 화면](#결과-화면)
- [파일 구조](#파일-구조)
- [문제 해결](#문제-해결)

---

## 개요

이 도구는 아래 워크플로를 **원클릭**으로 수행합니다.

```
[프로젝트 폴더] → 패키지 설치 → SBOM 생성 → CVE 취약점 스캔 → Excel 보고서
```

### 사용 도구 (자동 설치)

| 도구 | 용도 | 출처 |
|------|------|------|
| **cdxgen** | 소스코드 SBOM 생성 (CycloneDX) | CycloneDX/cdxgen |
| **syft** | 바이너리 SBOM 생성 | Anchore |
| **grype** | CVE 취약점 스캔 (1차 - 권장) | Anchore |
| **osv-scanner** | CVE 취약점 스캔 (2차 - 선택) | Google |

---

## 지원 환경

- **OS**: Windows 10/11 (64bit)
- **Python**: 3.10 이상
- **Node.js**: 18 이상 (cdxgen npm 설치 시 필요, 없으면 독립 exe 사용)

---

## 설치 방법

### 1단계: Python 설치

[python.org](https://www.python.org/downloads/)에서 Python 3.10+ 설치
- 설치 시 **"Add Python to PATH"** 반드시 체크

### 2단계: 원클릭 설치

```
INSTALL.bat 더블클릭
```

INSTALL.bat이 자동으로 수행하는 작업:
1. Python 존재 확인
2. pip 패키지 설치 (streamlit, openpyxl)
3. Node.js 확인 → cdxgen npm 설치 (없으면 건너뜀)
4. GitHub에서 분석 도구 자동 다운로드:
   - `syft.exe` (SBOM 생성)
   - `grype.exe` (CVE 스캔)
   - `osv-scanner.exe` (CVE 스캔)
   - `cdxgen.exe` (Node.js 없을 때 fallback)
5. output, saves 폴더 생성

### 3단계: 확인

설치 완료 후 아래와 같이 표시되면 성공:

```
[OK] Syft
[OK] cdxgen
[OK] grype
[OK] osv-scanner
```

---

## 사용 방법

### 시작

```
START.bat 더블클릭
```

브라우저에 대시보드가 자동으로 열립니다 (http://localhost:8501).

### 분석 실행

1. **경로 입력**: 분석할 프로젝트 폴더 경로를 입력하거나 드래그
2. **🚀 분석 클릭**: 원클릭으로 전체 파이프라인 실행
3. **결과 확인**: 대시보드에서 SBOM 목록, CVE 취약점, 다운로드

### 압축 파일 분석

- ZIP, TAR.GZ, 7Z 등 압축 파일도 직접 분석 가능
- "📦 압축 파일 업로드" 탭에서 파일 선택 후 분석

### 독립 실행 (사전 설치만)

```
PREPARE_SCAN.bat에 프로젝트 폴더를 드래그 앤 드롭
```

패키지 설치만 별도로 수행하고 싶을 때 사용합니다.

---

## 분석 파이프라인

### STEP 0: 사전 패키지 설치

- 프로젝트 하위 디렉토리까지 재귀 탐색하여 매니페스트 자동 발견
- `package-lock.json` → `npm ci` (실패 시 `npm install`로 자동 전환)
- `package.json` → `npm install` + `package-lock.json` 강제 생성
- `requirements.txt` → `pip install`
- 모노레포 지원: 각 서비스 폴더별 개별 설치

### STEP 1: 1차 검증

- 바이너리 vs 소스코드 자동 판별
- 파일 확장자 분석으로 프로젝트 유형 결정
- SBOM 생성 도구 자동 선택 (syft / cdxgen)

### STEP 2: SBOM 생성

- **cdxgen**: 소스코드 프로젝트 (Node.js, Python, Java, Go 등)
- **syft**: 바이너리, 컨테이너 이미지
- 출력: CycloneDX JSON (`.cdx.json`)

### STEP 3: CVE 매핑

- **grype** (1차 - 권장): SBOM을 stdin으로 전달하여 취약점 스캔
  - 자체 VDB 사용 (토큰 불필요)
  - 실행 전 `grype db update` 자동 실행
  - `GRYPE_DB_VALIDATE_AGE=false`로 오래된 DB도 사용 가능
- **osv-scanner** (2차 - 선택): Lock 파일 기반 직접 스캔
- **dep-scan** (3차 - 선택): GITHUB_TOKEN 필요

### STEP 3-B: C/C++ 소스 해시 스캔

C/C++ 프로젝트는 npm, pip 같은 패키지 매니저가 없어 lock 파일이 존재하지 않습니다.
이 단계에서는 소스 파일을 직접 분석합니다:

1. **파일 해시 계산**: 모든 .c/.h/.cpp/.hpp 파일의 SHA-256 해시 계산
2. **라이브러리 시그니처 매칭**: 헤더 파일에서 `#define VERSION` 패턴으로 알려진 라이브러리 식별
3. **OSV API 질의**: 식별된 라이브러리 + 버전으로 Google OSV 취약점 DB 질의

지원 라이브러리 (15종):
OpenSSL, zlib, libpng, libcurl, SQLite, libxml2, libjpeg-turbo,
expat, FreeType, mbedTLS, wolfSSL, protobuf, libevent, Boost, nginx

### STEP 4: SAST 정적 분석 (Semgrep)

소스코드 자체의 코딩 취약점(SQL 인젝션, XSS, 하드코딩된 비밀번호 등)을 검출합니다.
CVE 스캔(STEP 3)이 **라이브러리 취약점**을 찾는 것이라면, SAST는 **작성한 코드의 취약점**을 찾습니다.

- Semgrep CLI로 `semgrep scan --json` 실행
- JSON 결과에서 심각도(HIGH/MEDIUM/LOW), CWE, 파일+라인, 코드 스니펫 추출
- 다국어 지원: JavaScript, Python, Java, Go, C#, Ruby, PHP, TypeScript 등
- 설치: `pip install semgrep` (사이드바에서 ON/OFF 가능)

---

## 사이드바 설정

### 🔧 도구 상태
- 설치된 도구와 버전 표시
- "🔄 도구 최신 버전 확인" 버튼으로 수동 업데이트

### 📋 스캔 옵션
- SBOM 생성 도구 선택 (자동 / syft / cdxgen)
- CVE 매핑 도구 선택:
  - ☑ grype (권장, 기본 ON)
  - ☐ osv-scanner (선택)
  - ☐ dep-scan (GITHUB_TOKEN 필요)

### 📦 사전 준비
- "분석 전 패키지 자동 설치" 체크박스

### 🔑 GitHub Token (선택)
- dep-scan 사용 시 필요
- 한 번 입력하면 `.env` 파일에 자동 저장
- GitHub → Settings → Developer settings → Personal access tokens

---

## 결과 화면

### 📊 대시보드
- 1차 검증 결과 (유형, 도구, 신뢰도)
- SBOM 요약 (컴포넌트 수, 생태계, 소요 시간)
- CVE 요약 (CRITICAL / HIGH / MEDIUM / LOW)

### 📦 SBOM 목록
- 전체 컴포넌트 목록 (이름, 버전, 생태계, 라이선스)
- 생태계별 필터링 + 검색

### 🛡️ CVE 취약점
- 심각도별 필터링 (CRITICAL ~ LOW)
- CVE ID, CVSS 점수, CWE, 수정 버전
- 상세 정보 펼치기

### 📥 다운로드
- SBOM JSON
- Excel 보고서 (.xlsx)
- CVE 목록 CSV

### 📋 로그
- 실시간 실행 로그 (터미널 스타일)
- 로그 텍스트 다운로드

---

## 파일 구조

```
sbom-generator/
├── INSTALL.bat          # 원클릭 설치 스크립트
├── START.bat            # 앱 실행 스크립트
├── PREPARE_SCAN.bat     # 독립 사전 설치 스크립트
├── requirements.txt     # Python 의존성
├── README.md            # 이 파일
├── .gitignore           # Git 제외 설정
│
├── app.py               # 메인 Streamlit 대시보드
├── detector.py          # 1차 검증 (바이너리/소스코드 판별)
├── sbom_generator.py    # 2차 SBOM 생성 (syft/cdxgen)
├── cve_mapper.py        # 3차 CVE 매핑 (grype/osv-scanner/dep-scan)
├── cpp_hash_scanner.py  # C/C++ 소스 해시 기반 취약점 스캔
├── sast_scanner.py      # SAST 정적 분석 (Semgrep)
├── prepare_scan.py      # 사전 패키지 설치 (모노레포 지원)
├── install_tools.py     # 도구 자동 다운로드/업데이트
├── tool_manager.py      # 도구 상태 확인
├── archive_handler.py   # 압축 파일 해제
├── excel_export.py      # Excel 보고서 생성
│
├── tools/               # 분석 도구 (자동 다운로드)
│   ├── syft.exe
│   ├── grype.exe
│   ├── cdxgen.exe
│   ├── osv-scanner.exe
│   └── versions.json
│
├── output/              # 스캔 결과 저장
├── saves/               # 저장된 분석
└── .env                 # GitHub 토큰 등 (자동 생성, Git 제외)
```

---

## 문제 해결

### Q: INSTALL.bat 실행 시 "Python not found"
Python이 PATH에 없습니다. Python 재설치 시 "Add to PATH" 체크하세요.

### Q: cdxgen에서 "composer not recognized" 에러
PHP composer가 없어서 나오는 경고입니다. Node.js 프로젝트 분석에는 영향 없으니 무시하세요.

### Q: grype에서 "database was built N weeks ago"
`grype db update`가 자동 실행됩니다. 방화벽으로 차단된 경우 `GRYPE_DB_VALIDATE_AGE=false`로 강제 진행합니다.

### Q: npm ci 에러 "package.json and package-lock.json are not in sync"
자동으로 `npm install`로 전환하여 lock 파일을 갱신합니다. 정상 동작입니다.

### Q: 분석 도구가 자동 다운로드되지 않음
방화벽에서 `github.com`, `api.github.com` 접근을 허용해주세요.

### Q: dep-scan에서 0건 나옴
GITHUB_TOKEN이 필요합니다. 사이드바 🔑 GitHub Token에 입력하세요.
grype만으로도 충분한 취약점 탐지가 가능합니다.

---

## 라이선스

MIT License

## 버전

v2.2.0 · Syft + cdxgen + Grype + osv-scanner
