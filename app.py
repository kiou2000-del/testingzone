"""
🛡️ SBOM Generator & Vulnerability Scanner
업계 표준 도구 기반 SBOM 생성 + CVE 매핑

워크플로:
  1차 검증: 바이너리 vs 소스코드 판별
  2차 SBOM: syft(바이너리) / cdxgen(소스코드)
  3차 CVE:  osv-scanner(Google) / dep-scan(OWASP)

실행: streamlit run app.py
"""
import streamlit as st
import html as html_mod
import json, os, sys, time
from datetime import datetime

# 프로젝트 내 tools/ 폴더를 PATH에 추가 (INSTALL.bat이 여기에 다운로드)
_app_dir = os.path.dirname(os.path.abspath(__file__))
_tools_dir = os.path.join(_app_dir, "tools")
if os.path.isdir(_tools_dir):
    os.environ["PATH"] = _tools_dir + os.pathsep + os.environ.get("PATH", "")

sys.path.insert(0, _app_dir)

# ── .env 파일에서 환경변수 로드 (토큰 등) ──
_ENV_FILE = os.path.join(_app_dir, ".env")

def _load_env():
    """프로젝트 .env 파일에서 KEY=VALUE 형태의 환경변수를 로드"""
    if not os.path.isfile(_ENV_FILE):
        return
    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and val:
                        os.environ.setdefault(key, val)
    except Exception:
        pass

def _save_env_token(token: str):
    """.env 파일에 GITHUB_TOKEN 저장 (다른 키는 보존)"""
    lines = []
    token_written = False
    if os.path.isfile(_ENV_FILE):
        try:
            with open(_ENV_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("GITHUB_TOKEN"):
                        lines.append(f"GITHUB_TOKEN={token}\n")
                        token_written = True
                    else:
                        lines.append(line)
        except Exception:
            pass
    if not token_written:
        lines.append(f"GITHUB_TOKEN={token}\n")
    try:
        with open(_ENV_FILE, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception:
        pass

_load_env()

from tool_manager import check_all_tools, TOOLS
from detector import detect_input_type
from sbom_generator import generate_sbom, parse_sbom_components
from cve_mapper import run_osv_scanner, run_depscan, run_grype, merge_cve_results, vulns_to_table
from cpp_hash_scanner import scan_cpp_hashes
from sast_scanner import run_sast_scan, check_semgrep
from archive_handler import extract_archive, cleanup_temp_dir
from prepare_scan import prepare_scan, detect_project_type
from install_tools import check_and_update_tools, TOOLS_DIR

# ─────────────────────────────────────────
st.set_page_config(page_title="SBOM & CVE Scanner", page_icon="🛡️", layout="wide")

st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
.main-title{font-size:2.2rem;font-weight:800;background:linear-gradient(135deg,#0f172a,#1e40af 50%,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.2rem}
.sub{font-size:.95rem;color:#64748b;margin-bottom:1.5rem}
.vc{border-radius:12px;padding:1rem;text-align:center;border:1px solid #e2e8f0}
.vc-c{border-left:4px solid #dc2626} .vc-h{border-left:4px solid #ea580c}
.vc-m{border-left:4px solid #d97706} .vc-l{border-left:4px solid #16a34a}
.vn{font-size:2rem;font-weight:800} .vl{font-size:.8rem;color:#64748b}
.live-term{background:#0d1117;color:#c9d1d9;font-family:'JetBrains Mono',monospace;font-size:.78rem;
  line-height:1.55;padding:14px 16px;border-radius:8px;border:1px solid #30363d;
  max-height:420px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
.live-term .t-cmd{color:#79c0ff} .live-term .t-ok{color:#3fb950}
.live-term .t-err{color:#f85149} .live-term .t-warn{color:#d29922}
.live-term .t-step{color:#bc8cff;font-weight:700} .live-term .t-dim{color:#6e7681}
.term-header{display:flex;align-items:center;gap:6px;margin-bottom:6px}
.term-dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.term-dot.r{background:#f85149}.term-dot.y{background:#d29922}.term-dot.g{background:#3fb950}
.term-title{color:#6e7681;font-size:.75rem;font-family:'JetBrains Mono',monospace;margin-left:6px}
</style>""", unsafe_allow_html=True)


# ─────────────────────────────────────────
# 터미널 로그 컬러링 (공통 유틸)
# ─────────────────────────────────────────
def _colorize_line(line: str) -> str:
    """로그 한 줄에 CSS 클래스 span 적용"""
    esc = html_mod.escape(line)
    if esc.startswith("$"):
        return f'<span class="t-cmd">{esc}</span>'
    if esc.startswith("[ERROR]") or esc.startswith("❌"):
        return f'<span class="t-err">{esc}</span>'
    if esc.startswith("✅") or "완료" in esc:
        return f'<span class="t-ok">{esc}</span>'
    if esc.startswith("⚠️") or esc.startswith("[WARN]"):
        return f'<span class="t-warn">{esc}</span>'
    if any(esc.startswith(s) for s in ("📦", "🔍", "🛡️", "🐍", "📂", "──", "🔧", "🌐", "🏷", "⬇", "📡", "📥", "🆕", "⏭", "🔄", "⛔")):
        return f'<span class="t-step">{esc}</span>'
    if esc.lstrip().startswith("📂 cwd:") or esc.lstrip().startswith("⏱"):
        return f'<span class="t-dim">{esc}</span>'
    return esc


def _build_terminal_html(lines: list, title: str = "SBOM Scanner — Live Log", element_id: str = "") -> str:
    """터미널 HTML 조합"""
    body = "\n".join(_colorize_line(l) for l in lines)
    id_attr = f' id="{element_id}"' if element_id else ""
    scroll_js = ""
    if element_id:
        scroll_js = (
            f'<script>var e=document.getElementById("{element_id}");'
            f'if(e)e.scrollTop=e.scrollHeight;</script>'
        )
    return (
        '<div class="term-header">'
        '<span class="term-dot r"></span><span class="term-dot y"></span>'
        '<span class="term-dot g"></span>'
        f'<span class="term-title">{html_mod.escape(title)}</span>'
        '</div>'
        f'<div class="live-term"{id_attr}>{body}</div>'
        f'{scroll_js}'
    )


# ─────────────────────────────────────────
# 시작 시 도구 자동 업데이트 (세션당 1회)
# ─────────────────────────────────────────
# 개선: 도구가 이미 설치되어 있다면 자동 업데이트는 백그라운드에서 하거나 건너뜀
_all_tools = check_all_tools()
_any_installed = any(t.installed for t in _all_tools.values())

if "_tools_checked" not in st.session_state:
    if _any_installed:
        # 이미 도구가 설치되어 있다면 자동 업데이트 생략 (사용자가 버튼으로 실행 가능)
        st.session_state["_tools_checked"] = True
    else:
        # 도구가 하나도 없으면 (최초 실행) 설치 진행
        _startup_container = st.container()
        with _startup_container:
            st.warning("⚠️ 분석 도구가 설치되어 있지 않습니다. 필수 도구를 다운로드합니다.")
            _startup_term = st.empty()
            _startup_lines = []

            def _startup_cb(msg):
                _startup_lines.append(msg)
                _startup_term.markdown(
                    _build_terminal_html(_startup_lines[-40:], "Initial Tool Installation"),
                    unsafe_allow_html=True,
                )

            _update_result = check_and_update_tools(line_callback=_startup_cb)
            st.session_state["_tools_checked"] = True
            st.session_state["_update_result"] = _update_result

            time.sleep(1.0)
            _startup_container.empty()
            st.rerun()

# ─────────────────────────────────────────
# 사이드바: 도구 상태 + 설정
# ─────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ 설정")

    st.markdown("### 🔧 도구 상태")
    tools = check_all_tools()
    for name, status in tools.items():
        icon = "✅" if status.installed else "❌"
        purpose = status.purpose
        st.markdown(f"{icon} **{name}** — {purpose}")
        if status.installed:
            st.caption(f"  {status.version}")
        else:
            tool_info = TOOLS[name]
            with st.expander(f"{name} 설치 방법"):
                # 설치 단계 안내
                steps = tool_info.get("install_steps", [])
                for step in steps:
                    if step:
                        st.markdown(step)
                # 설치 명령어
                cmd = tool_info.get("install_cmd", "")
                if cmd:
                    st.code(cmd, language="bash")
                # 다운로드 링크
                url = tool_info.get("url", "")
                if url:
                    st.markdown(f"[📥 다운로드 페이지]({url})")

    # 도구 업데이트 버튼
    if st.button("🔄 도구 최신 버전 확인", use_container_width=True, key="btn_update"):
        st.session_state.pop("_tools_checked", None)
        st.rerun()

    st.markdown("---")
    st.markdown("### 📋 스캔 옵션")

    sbom_tool_options = ["자동 선택"]
    if tools["syft"].installed:
        sbom_tool_options.append("syft (바이너리)")
    if tools["cdxgen"].installed:
        sbom_tool_options.append("cdxgen (소스코드)")
    sbom_tool_choice = st.selectbox("SBOM 생성 도구", sbom_tool_options)

    cve_tools_selected = []
    if tools["grype"].installed:
        if st.checkbox("grype (Anchore) — 권장", value=True,
                       help="SBOM 네이티브 스캐너. 자체 VDB 사용으로 토큰 불필요. "
                            "syft와 같은 Anchore 생태계. 가장 안정적."):
            cve_tools_selected.append("grype")
    if tools["osv-scanner"].installed:
        if st.checkbox("osv-scanner (Google)", value=False,
                       help="Lock 파일 기반 스캔. 토큰 불필요."):
            cve_tools_selected.append("osv-scanner")
    if tools["depscan"].installed:
        _has_token = bool(os.environ.get("GITHUB_TOKEN"))
        if st.checkbox(
            f"dep-scan (OWASP) {'✅' if _has_token else '⚠️ 토큰 필요'}",
            value=False,
            help="GITHUB_TOKEN이 필요합니다.",
        ):
            cve_tools_selected.append("depscan")

    if not cve_tools_selected:
        st.caption("⚠️ CVE 매핑 도구를 하나 이상 선택하세요")

    st.markdown("---")
    st.markdown("### 📦 사전 준비")
    auto_prepare = st.checkbox(
        "분석 전 패키지 자동 설치",
        value=True,
        help="분석 시작 전에 npm ci / npm install / pip install을 자동 실행합니다.",
    )

    st.markdown("---")
    st.markdown("### 🔬 SAST 분석")
    _semgrep_ok, _semgrep_ver = check_semgrep()
    run_sast = st.checkbox(
        f"Semgrep SAST 스캔 {'✅' if _semgrep_ok else '⚠️ 미설치'}",
        value=_semgrep_ok,
        help="소스코드 정적 분석(SAST). SQL 인젝션, XSS 등 코딩 취약점을 검출합니다. "
             "Semgrep 필요: pip install semgrep",
    )
    if _semgrep_ok:
        st.caption(f"Semgrep {_semgrep_ver}")
    else:
        st.caption("설치: pip install semgrep")

    st.markdown("---")
    st.markdown("### 🔑 GitHub Token")
    st.caption("dep-scan 취약점 DB 다운로드에 필요 (한 번 입력하면 자동 저장)")
    _current_token = os.environ.get("GITHUB_TOKEN", "")
    _gh_token = st.text_input(
        "GITHUB_TOKEN",
        value=_current_token,
        type="password",
        help="GitHub → Settings → Developer settings → Personal access tokens → "
             "Generate new token (public_repo 권한). 입력하면 .env 파일에 자동 저장됩니다.",
        label_visibility="collapsed",
        placeholder="ghp_xxxxxxxxxxxxxxxxxxxx",
    )
    if _gh_token:
        os.environ["GITHUB_TOKEN"] = _gh_token
        # .env에 저장 (다음 실행 시 자동 로드)
        if _gh_token != _current_token:
            _save_env_token(_gh_token)
        st.caption("✅ GITHUB_TOKEN 적용됨 (.env에 저장)")
    else:
        st.caption("⚠️ 미설정 시 dep-scan 취약점 DB 다운로드 실패 가능")

    st.markdown("---")
    st.caption("v2.3.0 · Syft + cdxgen + Grype + osv-scanner + Semgrep")

# ─────────────────────────────────────────
# 메인 헤더
# ─────────────────────────────────────────
st.markdown('<div class="main-title">🛡️ SBOM & Vulnerability Scanner</div>', unsafe_allow_html=True)
st.markdown('<div class="sub">1차 검증(바이너리/소스) → 2차 SBOM 생성(Syft/cdxgen) → CVE 매핑(osv-scanner/dep-scan)</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────
# 입력: 폴더 경로 / 압축 파일 업로드
# ─────────────────────────────────────────
tab_folder, tab_upload = st.tabs(["📁 폴더 경로 입력", "📦 압축 파일 업로드"])

scan_path = ""
start_scan = False

ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".7z")

def _is_archive(path):
    return os.path.isfile(path) and any(path.lower().endswith(e) for e in ARCHIVE_EXTS)

with tab_folder:
    col_p, col_b = st.columns([6, 1])
    with col_p:
        folder_path = st.text_input(
            "경로",
            placeholder="폴더, 압축파일, 바이너리 경로 모두 가능",
            label_visibility="collapsed", key="inp_folder",
        )
    with col_b:
        btn_folder = st.button("🚀 분석", type="primary", use_container_width=True, key="btn_f")
    if btn_folder and folder_path:
        if _is_archive(folder_path):
            # 압축 파일 → 먼저 추출
            with st.spinner(f"📦 {os.path.basename(folder_path)} 압축 해제 중..."):
                extracted, err = extract_archive(file_path=folder_path)
            if err:
                st.error(f"압축 해제 실패: {err}")
                st.stop()
            scan_path = extracted
            start_scan = True
            st.session_state["_tmp"] = extracted
            st.session_state["_extracted_path"] = extracted  # rerun 시 유지
            st.success(f"✅ 추출 완료 → `{os.path.basename(extracted)}`")
        elif os.path.isfile(folder_path):
            scan_path = folder_path
            start_scan = True
        elif os.path.isdir(folder_path):
            scan_path = folder_path
            start_scan = True
        else:
            st.error(f"⚠️ 경로를 찾을 수 없습니다: {folder_path}")

    # Streamlit rerun 시 추출 경로 복원
    if not start_scan and "_extracted_path" in st.session_state:
        ep = st.session_state["_extracted_path"]
        if os.path.isdir(ep):
            scan_path = ep

with tab_upload:
    st.caption("ZIP, TAR.GZ, TGZ, 7Z 지원")
    uploaded = st.file_uploader("압축 파일 선택", type=["zip","tar","gz","tgz","bz2","xz","7z"], key="upl")
    if uploaded:
        st.info(f"📦 {uploaded.name} ({uploaded.size/(1024*1024):.1f} MB)")
        if st.button("🚀 압축 해제 & 분석", type="primary", use_container_width=True, key="btn_u"):
            with st.spinner("📦 압축 해제 중..."):
                path, err = extract_archive(file_bytes=uploaded.getvalue(), file_name=uploaded.name)
            if err:
                st.error(err); st.stop()
            scan_path = path
            start_scan = True
            st.session_state["_tmp"] = path

if "_cleanup" in st.session_state:
    cleanup_temp_dir(st.session_state.pop("_cleanup"))


# ─────────────────────────────────────────
# 분석 파이프라인
# ─────────────────────────────────────────
if start_scan:
    if not scan_path or not os.path.exists(scan_path):
        st.error("⚠️ 유효한 경로를 입력하세요."); st.stop()

    all_logs = []

    # ── 프로그레스 UI (완료 후 제거됨) ──
    progress_container = st.container()
    with progress_container:
        progress_bar = st.progress(0)
        col_pct, col_step = st.columns([1, 5])
        pct_display = col_pct.empty()
        step_display = col_step.empty()
        step_detail = st.empty()

    # ── 실시간 터미널 (완료 후에도 유지) ──
    term_container = st.container()
    with term_container:
        term_expander = st.expander("🖥️ 실시간 실행 로그", expanded=True)
        with term_expander:
            live_term = st.empty()

    # 터미널 라인 버퍼 (최대 500줄 유지)
    _term_lines = []
    _MAX_TERM_LINES = 500

    def _render_terminal():
        """터미널 HTML 렌더링 (실시간용)"""
        lines = _term_lines[-_MAX_TERM_LINES:]
        live_term.markdown(
            _build_terminal_html(lines, "SBOM Scanner — Live Log", "live-term"),
            unsafe_allow_html=True,
        )

    def update_progress(pct: int, step: str, detail: str = ""):
        progress_bar.progress(min(pct, 100))
        pct_display.markdown(f"<div style='font-size:2.2rem;font-weight:800;color:#1e40af;text-align:center'>{pct}%</div>", unsafe_allow_html=True)
        step_display.markdown(f"<div style='font-size:1.1rem;font-weight:600;padding-top:0.6rem'>{step}</div>", unsafe_allow_html=True)
        if detail:
            step_detail.caption(detail)

    def log(msg):
        """분석 단계 로그 (all_logs + 터미널에 추가)"""
        all_logs.append(msg)
        _term_lines.append(msg)
        _render_terminal()

    def live_line(line):
        """실시간 명령어 출력 라인 (터미널에 표시 + all_logs에 기록)"""
        all_logs.append(line)
        _term_lines.append(line)
        _render_terminal()

    # ── STEP 0: 사전 패키지 설치 (0~10%) ──
    log("── STEP 0: 사전 패키지 설치 ──────────────────")
    if auto_prepare:
        update_progress(2, "📦 사전 패키지 설치", "매니페스트 탐색 중 (하위 디렉토리 포함)...")

        def prep_progress(msg):
            if "완료" in msg or "실패" in msg:
                update_progress(10, "📦 사전 설치 완료", msg.strip())

        prep_result = prepare_scan(scan_path, progress=prep_progress, line_callback=live_line)

        if prep_result.skipped:
            log(f"[사전 설치] {prep_result.message}")
        elif prep_result.success:
            update_progress(10, f"✅ 사전 설치 완료", prep_result.message)
            log(f"[사전 설치] {prep_result.message}")
        else:
            update_progress(10, f"⚠️ 사전 설치 실패", prep_result.message)
            log(f"[사전 설치] 실패: {prep_result.message}")
            st.warning(f"⚠️ 사전 패키지 설치 실패: {prep_result.message}\n분석은 계속 진행합니다.")
    else:
        log("[사전 설치] 비활성화됨 — 건너뜀")

    # ── STEP 1: 1차 검증 (10~20%) ──
    log("")
    log("── STEP 1: 1차 검증 (바이너리/소스코드) ─────")
    update_progress(12, "🔍 1차 검증", "바이너리/소스코드 판별 중...")
    detection = detect_input_type(scan_path)
    log(f"[1차 검증] 유형: {detection.input_type} (신뢰도 {detection.confidence:.0%})")
    log(f"  {detection.details}")
    log(f"  총 파일: {detection.total_files}, 바이너리: {detection.binary_files}, "
        f"소스: {detection.source_files}, 매니페스트: {detection.manifest_files}")
    update_progress(15, f"✅ 1차 검증 완료",
                    f"{detection.input_type.upper()} 프로젝트 → {detection.recommended_tool} 사용")

    # 도구 결정
    if sbom_tool_choice == "syft (바이너리)":
        chosen_tool = "syft"
    elif sbom_tool_choice == "cdxgen (소스코드)":
        chosen_tool = "cdxgen"
    else:
        chosen_tool = detection.recommended_tool

    if not chosen_tool:
        st.error("사용 가능한 SBOM 도구가 없습니다. Syft 또는 cdxgen을 설치해주세요.")
        with st.expander("설치 가이드"):
            for name in ["syft", "cdxgen"]:
                st.markdown(f"**{name}**: {TOOLS[name]['url']}")
        st.stop()

    # ── STEP 2: SBOM 생성 (15~60%) ──
    log("")
    log("── STEP 2: SBOM 생성 ─────────────────────")
    update_progress(18, f"📦 2차 SBOM 생성", f"{chosen_tool} 실행 중...")

    def sbom_progress(msg):
        log(msg)
        if "시작" in msg:
            update_progress(25, f"📦 {chosen_tool} SBOM 생성 중...", msg.strip())
        elif "명령" in msg:
            update_progress(30, f"📦 {chosen_tool} 실행 중...", msg.strip())
        elif "완료" in msg:
            update_progress(55, f"✅ SBOM 생성 완료", msg.strip())

    t0 = time.time()
    sbom_result = generate_sbom(
        scan_path, tool=chosen_tool, input_type=detection.input_type,
        progress=sbom_progress, line_callback=live_line
    )
    sbom_elapsed = time.time() - t0

    if not sbom_result.success:
        update_progress(100, "❌ SBOM 생성 실패", sbom_result.error[:200])
        st.error(f"SBOM 생성 실패: {sbom_result.error}")
        with st.expander("로그"):
            st.code("\n".join(all_logs))
        st.stop()

    components = parse_sbom_components(sbom_result.sbom_json)
    log(f"[SBOM] {chosen_tool}: {len(components)}개 컴포넌트 ({sbom_elapsed:.1f}초)")
    update_progress(60, f"✅ SBOM 완료: {len(components)}개 컴포넌트",
                    f"{chosen_tool} · {sbom_elapsed:.1f}초 소요")

    # ── STEP 3: CVE 매핑 (60~98%) ──
    log("")
    log("── STEP 3: CVE 매핑 ──────────────────────")
    cve_results = []
    if cve_tools_selected and sbom_result.sbom_path:
        cve_total_tools = len(cve_tools_selected)
        cve_done = 0

        if "grype" in cve_tools_selected:
            pct_base = 60 + int(cve_done / cve_total_tools * 35)
            update_progress(pct_base + 5, "🔍 Grype 실행 중...",
                            f"Anchore VDB에서 CVE 조회 중 (SBOM 네이티브 스캔)...")

            def grype_progress(msg):
                log(msg)
                if "완료" in msg:
                    update_progress(pct_base + 30, "✅ Grype 완료", msg.strip())

            grype_r = run_grype(
                sbom_result.sbom_path, grype_progress,
                line_callback=live_line,
            )
            cve_results.append(grype_r)
            cve_done += 1
            log(f"[grype] {grype_r.total_vulns}건 ({grype_r.duration:.1f}초)")

        if "osv-scanner" in cve_tools_selected:
            pct_base = 60 + int(cve_done / cve_total_tools * 35)
            update_progress(pct_base + 5, "🔍 osv-scanner 실행 중...",
                            f"Google OSV 데이터베이스에서 CVE 조회 중...")

            def osv_progress(msg):
                log(msg)
                if "완료" in msg:
                    update_progress(pct_base + 30, "✅ osv-scanner 완료", msg.strip())

            osv_r = run_osv_scanner(
                sbom_result.sbom_path, osv_progress,
                line_callback=live_line, scan_path=scan_path,
            )
            cve_results.append(osv_r)
            cve_done += 1
            log(f"[osv-scanner] {osv_r.total_vulns}건 ({osv_r.duration:.1f}초)")

        if "depscan" in cve_tools_selected:
            pct_base = 60 + int(cve_done / cve_total_tools * 35)
            update_progress(pct_base + 5, "🛡️ dep-scan 실행 중...",
                            f"OWASP 데이터베이스에서 CVE 조회 중...")

            def dep_progress(msg):
                log(msg)
                if "완료" in msg:
                    update_progress(pct_base + 30, "✅ dep-scan 완료", msg.strip())

            dep_r = run_depscan(sbom_path=sbom_result.sbom_path, progress=dep_progress, line_callback=live_line)
            cve_results.append(dep_r)
            cve_done += 1
            log(f"[dep-scan] {dep_r.total_vulns}건 ({dep_r.duration:.1f}초)")

    # ── STEP 3-B: C/C++ 소스 해시 기반 스캔 ──
    # C/C++ 소스 파일이 있으면 해시 기반 라이브러리 식별 + OSV API 질의
    _cpp_exts = {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh"}
    has_cpp = any(
        os.path.splitext(f)[1].lower() in _cpp_exts
        for _, _, files in os.walk(scan_path)
        for f in files
    ) if os.path.isdir(scan_path) else False

    if has_cpp:
        log("")
        log("── STEP 3-B: C/C++ 소스 해시 스캔 ────────")
        update_progress(92, "🔍 C/C++ 해시 스캔 중...", "소스코드 해시 계산 + 라이브러리 식별")

        cpp_result = scan_cpp_hashes(scan_path, line_callback=live_line)

        if cpp_result.identified_libs:
            # 식별된 라이브러리를 SBOM 컴포넌트 목록에 추가 (UI 표시용)
            for lib in cpp_result.identified_libs:
                # 중복 확인 후 추가
                exists = any(c.get("name") == lib.name for c in components)
                if not exists:
                    components.append({
                        "name": lib.name,
                        "version": lib.version,
                        "ecosystem": "C/C++ (Hash)",
                        "purl": f"pkg:generic/{lib.name}@{lib.version}",
                        "path": lib.matched_file
                    })
            log(f"[C/C++ 해시] {len(cpp_result.identified_libs)}개 라이브러리 식별 및 SBOM 추가")

        if cpp_result.osv_results:
            from cve_mapper import CVEMapResult, _compute_stats
            cpp_cve = CVEMapResult(tool_used="osv-hash", success=True)
            cpp_cve.vulns = cpp_result.osv_results
            cpp_cve.duration = cpp_result.duration
            _compute_stats(cpp_cve)
            cve_results.append(cpp_cve)
            log(f"[C/C++ 해시] {cpp_cve.total_vulns}건 ({cpp_cve.duration:.1f}초)")
        else:
            log(f"[C/C++ 해시] 파일 해시: {len(cpp_result.file_hashes)}개 분석 완료")

    # ── STEP 4: SAST 정적 분석 (Semgrep) ──
    sast_result = None
    if run_sast and os.path.isdir(scan_path):
        log("")
        log("── STEP 4: SAST 정적 분석 (Semgrep) ───────")
        update_progress(95, "🔬 SAST 스캔 중...", "Semgrep으로 소스코드 취약점 분석 중...")

        def sast_progress(msg):
            log(msg)
            if "완료" in msg or "실패" in msg:
                update_progress(98, "🔬 SAST 완료", msg.strip())

        sast_result = run_sast_scan(
            scan_path, progress=sast_progress, line_callback=live_line,
        )

        if sast_result.success:
            log(f"[SAST] {sast_result.total_findings}건 "
                f"(🔴{sast_result.high_count} 🟡{sast_result.medium_count} "
                f"🔵{sast_result.low_count}) [{sast_result.duration:.1f}초]")

    # 결과 병합
    merged_cve = merge_cve_results(*cve_results) if cve_results else None
    vuln_table = vulns_to_table(merged_cve.vulns) if merged_cve else []

    vuln_count = merged_cve.total_vulns if merged_cve else 0
    sast_count = sast_result.total_findings if sast_result and sast_result.success else 0
    total_elapsed = time.time() - t0

    log("")
    log("── 완료 ───────────────────────────────────")
    log(f"✅ 분석 완료! {len(components)}개 컴포넌트 · "
        f"CVE {vuln_count}건 · SAST {sast_count}건 · {total_elapsed:.1f}초 소요")
    update_progress(100, "✅ 분석 완료!", "")
    time.sleep(0.8)

    # 프로그레스 UI 제거
    progress_container.empty()

    # 완료 메시지
    parts = [f"**{len(components)}**개 컴포넌트", f"CVE **{vuln_count}**건"]
    if sast_count:
        parts.append(f"SAST **{sast_count}**건")
    st.success(f"✅ 분석 완료! {' · '.join(parts)} · {total_elapsed:.1f}초 소요")

    # 세션 저장
    st.session_state.update({
        "detection": detection, "sbom_result": sbom_result,
        "components": components, "merged_cve": merged_cve,
        "vuln_table": vuln_table, "all_logs": all_logs,
        "sbom_elapsed": sbom_elapsed, "chosen_tool": chosen_tool,
        "_scan_path": scan_path, "_cve_results": cve_results,
        "_sast_result": sast_result,
        "_term_lines": list(_term_lines),
    })
    if "_tmp" in st.session_state:
        st.session_state["_cleanup"] = st.session_state.pop("_tmp")


# ─────────────────────────────────────────
# 결과 표시
# ─────────────────────────────────────────
if "sbom_result" in st.session_state:
    detection = st.session_state["detection"]
    sbom_result = st.session_state["sbom_result"]
    components = st.session_state["components"]
    merged_cve = st.session_state.get("merged_cve")
    vuln_table = st.session_state.get("vuln_table", [])
    all_logs = st.session_state.get("all_logs", [])
    chosen_tool = st.session_state.get("chosen_tool", "")
    sast_result = st.session_state.get("_sast_result")

    st.markdown("---")

    tabs = st.tabs(["📊 대시보드", "📦 SBOM 목록", "🛡️ CVE 취약점", "🔬 SAST 분석", "📥 다운로드", "📋 로그"])

    # ═══ TAB 1: 대시보드 ═══
    with tabs[0]:
        # 1차 검증 결과
        st.markdown("### 🔍 1차 검증")
        d1, d2, d3 = st.columns(3)
        d1.metric("유형", detection.input_type.upper())
        d2.metric("SBOM 도구", chosen_tool)
        d3.metric("신뢰도", f"{detection.confidence:.0%}")
        st.caption(detection.details)

        # SBOM 요약
        st.markdown("### 📦 SBOM 요약")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("컴포넌트", len(components))
        # 생태계 통계
        eco_counts = {}
        for c in components:
            eco = c.get("ecosystem", "-")
            eco_counts[eco] = eco_counts.get(eco, 0) + 1
        m2.metric("생태계", len(eco_counts))
        m3.metric("SBOM 도구", chosen_tool)
        m4.metric("소요 시간", f"{st.session_state.get('sbom_elapsed', 0):.1f}초")

        if eco_counts:
            eco_sorted = sorted(eco_counts.items(), key=lambda x: -x[1])
            cols = st.columns(min(len(eco_sorted), 6))
            for i, (eco, cnt) in enumerate(eco_sorted[:6]):
                with cols[i]:
                    st.metric(eco, cnt)

        # CVE 요약
        if merged_cve:
            st.markdown("### 🛡️ CVE 요약")
            v1, v2, v3, v4, v5 = st.columns(5)
            with v1:
                st.markdown(f'<div class="vc"><div class="vn">{merged_cve.total_vulns}</div><div class="vl">총 취약점</div></div>', unsafe_allow_html=True)
            with v2:
                st.markdown(f'<div class="vc vc-c"><div class="vn" style="color:#dc2626">{merged_cve.critical}</div><div class="vl">🔴 CRITICAL</div></div>', unsafe_allow_html=True)
            with v3:
                st.markdown(f'<div class="vc vc-h"><div class="vn" style="color:#ea580c">{merged_cve.high}</div><div class="vl">🟠 HIGH</div></div>', unsafe_allow_html=True)
            with v4:
                st.markdown(f'<div class="vc vc-m"><div class="vn" style="color:#d97706">{merged_cve.medium}</div><div class="vl">🟡 MEDIUM</div></div>', unsafe_allow_html=True)
            with v5:
                st.markdown(f'<div class="vc vc-l"><div class="vn" style="color:#16a34a">{merged_cve.low}</div><div class="vl">🟢 LOW</div></div>', unsafe_allow_html=True)

        # SAST 요약
        if sast_result and sast_result.success and sast_result.total_findings > 0:
            st.markdown("### 🔬 SAST 요약 (소스코드 취약점)")
            s1, s2, s3, s4 = st.columns(4)
            with s1:
                st.markdown(f'<div class="vc"><div class="vn">{sast_result.total_findings}</div><div class="vl">총 SAST 취약점</div></div>', unsafe_allow_html=True)
            with s2:
                st.markdown(f'<div class="vc vc-c"><div class="vn" style="color:#dc2626">{sast_result.high_count}</div><div class="vl">🔴 HIGH</div></div>', unsafe_allow_html=True)
            with s3:
                st.markdown(f'<div class="vc vc-m"><div class="vn" style="color:#d97706">{sast_result.medium_count}</div><div class="vl">🟡 MEDIUM</div></div>', unsafe_allow_html=True)
            with s4:
                st.markdown(f'<div class="vc vc-l"><div class="vn" style="color:#2563eb">{sast_result.low_count}</div><div class="vl">🔵 LOW</div></div>', unsafe_allow_html=True)

            if sast_result.top_cwes:
                st.markdown("**🔥 Top 취약점 유형 (CWE):**")
                for cwe in sast_result.top_cwes[:5]:
                    name = cwe.name or "알 수 없음"
                    st.markdown(f"- **{cwe.cwe_id}**: {name} ({cwe.count}건)")

    # ═══ TAB 2: SBOM 목록 ═══
    with tabs[1]:
        st.markdown(f"### 📦 SBOM 컴포넌트 ({len(components)}개)")
        if components:
            fc1, fc2 = st.columns([1, 1])
            with fc1:
                eco_filter = st.multiselect("생태계", sorted(eco_counts.keys()),
                                             default=sorted(eco_counts.keys()), key="eco_f")
            with fc2:
                search = st.text_input("🔎 검색", key="comp_s")

            filtered = [c for c in components
                        if c.get("ecosystem", "-") in eco_filter
                        and (not search or search.lower() in c.get("name", "").lower())]

            st.dataframe(
                filtered, use_container_width=True, height=500,
                column_config={"purl": st.column_config.TextColumn(width="large")}
            )

    # ═══ TAB 3: CVE 취약점 ═══
    with tabs[2]:
        if vuln_table:
            st.markdown(f"### 🛡️ CVE 취약점 ({len(vuln_table)}건)")
            fc1, fc2 = st.columns([1, 1])
            with fc1:
                sev_f = st.multiselect("심각도", ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"],
                                        default=["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"], key="sev_f")
            with fc2:
                vs = st.text_input("🔎 CVE/패키지 검색", key="vuln_s")

            fv = [v for v in vuln_table
                  if v["심각도"] in sev_f
                  and (not vs or vs.lower() in v["CVE ID"].lower() or vs.lower() in v["패키지"].lower())]

            st.dataframe(
                fv, use_container_width=True, height=500,
                column_config={
                    "CVSS": st.column_config.ProgressColumn(min_value=0, max_value=10, format="%.1f"),
                    "참조": st.column_config.LinkColumn(width="small", display_text="링크"),
                }
            )

            # 상세 정보
            for v in fv[:20]:
                sev = v["심각도"]
                emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(sev, "⚪")
                with st.expander(f"{emoji} {v['CVE ID']} — {v['패키지']}@{v['현재 버전']}"):
                    c1, c2 = st.columns([2, 1])
                    with c1:
                        st.markdown(f"**{v['설명']}**")
                    with c2:
                        st.markdown(f"**심각도:** {sev}  \n**CVSS:** {v['CVSS']}  \n"
                                    f"**CWE:** {v['CWE']}  \n**출처:** {v['출처']}")
                        if v["수정 버전"] != "-":
                            st.success(f"수정: {v['수정 버전']}")
        elif merged_cve and merged_cve.total_vulns == 0:
            st.success("🎉 알려진 취약점이 없습니다!")
        else:
            st.info("CVE 매핑 도구를 선택하고 분석을 실행하세요.")

    # ═══ TAB 4: SAST 분석 ═══
    with tabs[3]:
        if sast_result and sast_result.success and sast_result.total_findings > 0:
            st.markdown(f"### 🔬 SAST 취약점 ({sast_result.total_findings}건)")
            st.caption(f"Semgrep {sast_result.semgrep_version} · "
                       f"{sast_result.files_scanned}개 파일 스캔 · "
                       f"{sast_result.rules_used}개 규칙 · {sast_result.duration:.1f}초")

            # 필터
            fc1, fc2 = st.columns([1, 1])
            with fc1:
                sast_sev = st.multiselect("심각도", ["HIGH", "MEDIUM", "LOW"],
                                          default=["HIGH", "MEDIUM", "LOW"], key="sast_sev")
            with fc2:
                sast_search = st.text_input("🔎 규칙/파일 검색", key="sast_s")

            ffindings = [f for f in sast_result.findings
                         if f.severity in sast_sev
                         and (not sast_search
                              or sast_search.lower() in f.rule_id.lower()
                              or sast_search.lower() in f.file_path.lower())]

            # 테이블
            sast_table = []
            for f in ffindings:
                sast_table.append({
                    "심각도": f.severity,
                    "규칙": f.rule_id.split(".")[-1] if "." in f.rule_id else f.rule_id,
                    "파일": f.file_path,
                    "라인": f"{f.line_start}" + (f"-{f.line_end}" if f.line_end != f.line_start else ""),
                    "CWE": ", ".join(f.cwe_ids) if f.cwe_ids else "-",
                    "설명": f.message[:100],
                })

            st.dataframe(sast_table, use_container_width=True, height=400)

            # 상세 정보 (상위 30개)
            for f in ffindings[:30]:
                sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.severity, "⚪")
                with st.expander(f"{sev_icon} {f.file_path}:{f.line_start} — {f.rule_id.split('.')[-1]}"):
                    st.markdown(f"**{f.message}**")
                    if f.code_snippet:
                        st.code(f.code_snippet, language="c")
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(f"**심각도:** {f.severity}  \n"
                                    f"**CWE:** {', '.join(f.cwe_ids) if f.cwe_ids else '-'}  \n"
                                    f"**규칙:** `{f.rule_id}`")
                    with c2:
                        if f.owasp_ids:
                            st.markdown(f"**OWASP:** {', '.join(f.owasp_ids[:3])}")
                        if f.reference_url:
                            st.markdown(f"[📖 참조]({f.reference_url})")
                        if f.fix_suggestion:
                            st.info(f"💡 수정: {f.fix_suggestion}")

            # Top 영향받은 파일
            if sast_result.file_finding_counts:
                st.markdown("### 📁 영향받은 파일 (취약점 수 기준)")
                file_data = [{"파일": k, "취약점 수": v}
                             for k, v in list(sast_result.file_finding_counts.items())[:15]]
                st.dataframe(file_data, use_container_width=True)

        elif sast_result and sast_result.success:
            st.success("🎉 SAST 취약점이 발견되지 않았습니다!")
        elif sast_result and sast_result.error:
            st.error(f"SAST 스캔 실패: {sast_result.error}")
        else:
            st.info("🔬 SAST 분석을 실행하려면 사이드바에서 'Semgrep SAST 스캔'을 활성화하세요.")

    # ═══ TAB 5: 다운로드 ═══
    with tabs[4]:
        st.markdown("### 📥 다운로드")
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        # SBOM JSON
        if sbom_result.raw_output:
            st.download_button(
                f"⬇️ SBOM JSON ({chosen_tool})",
                sbom_result.raw_output,
                f"sbom-{chosen_tool}-{ts}.json", "application/json",
                use_container_width=True, key="dl_sbom"
            )

        # Excel
        try:
            from excel_export import generate_excel
            cve_tool_names = ", ".join(
                r.tool_used for r in (st.session_state.get("_cve_results") or [])
                if r and r.success
            ) or "-"
            xlsx = generate_excel(components, vuln_table, {
                "tool": chosen_tool,
                "scan_path": st.session_state.get("_scan_path", "-"),
                "input_type": detection.input_type,
                "elapsed": st.session_state.get("sbom_elapsed", 0),
                "cve_tools": cve_tool_names,
            })
            st.download_button(
                "📗 Excel 보고서 (.xlsx)", xlsx,
                f"sbom-report-{ts}.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True, key="dl_xlsx"
            )
        except Exception as e:
            st.caption(f"Excel: {e}")

        # CVE CSV
        if vuln_table:
            csv_lines = ["심각도,CVSS,CVE,CWE,패키지,현재버전,수정버전,출처,설명"]
            for v in vuln_table:
                csv_lines.append(",".join([
                    v["심각도"], str(v["CVSS"]), v["CVE ID"],
                    f'"{v["CWE"]}"', f'"{v["패키지"]}"',
                    v["현재 버전"], v["수정 버전"], v["출처"],
                    f'"{v["설명"]}"'
                ]))
            st.download_button(
                "⬇️ CVE 목록 CSV", "\n".join(csv_lines),
                f"cve-{ts}.csv", "text/csv",
                use_container_width=True, key="dl_csv"
            )

    # ═══ TAB 6: 로그 ═══
    with tabs[5]:
        st.markdown("### 📋 분석 로그")

        # 터미널 스타일 로그
        saved_term = st.session_state.get("_term_lines", [])
        if saved_term:
            st.markdown(
                _build_terminal_html(saved_term, "SBOM Scanner — Full Log"),
                unsafe_allow_html=True,
            )
        else:
            st.code("\n".join(all_logs) or "(로그 없음)")

        # 로그 다운로드
        log_text = "\n".join(saved_term if saved_term else all_logs)
        if log_text:
            st.download_button(
                "⬇️ 로그 텍스트 다운로드",
                log_text,
                f"scan-log-{ts}.txt", "text/plain",
                use_container_width=True, key="dl_log",
            )

        # 1차 검증 상세
        with st.expander("1차 검증 상세"):
            st.json({
                "type": detection.input_type,
                "confidence": detection.confidence,
                "total_files": detection.total_files,
                "binary_files": detection.binary_files,
                "source_files": detection.source_files,
                "manifest_files": detection.manifest_files,
                "recommended_tool": detection.recommended_tool,
                "manifests": detection.manifest_list[:20],
            })
