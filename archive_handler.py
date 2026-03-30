"""
아카이브 핸들러 — ZIP, TAR.GZ, 7Z 추출
"""
import os, zipfile, tarfile, shutil, tempfile, io
from typing import Optional, Tuple


def extract_archive(file_path="", file_bytes=None, file_name="") -> Tuple[Optional[str], str]:
    if not file_name and file_path:
        file_name = os.path.basename(file_path)
    nl = file_name.lower()
    tmp = tempfile.mkdtemp(prefix="sbom_scan_")
    try:
        if nl.endswith(".zip"):
            src = io.BytesIO(file_bytes) if file_bytes else file_path
            with zipfile.ZipFile(src) as zf:
                for i in zf.infolist():
                    if not i.filename.startswith("/") and ".." not in i.filename:
                        zf.extract(i, tmp)
            return _root(tmp), ""
        elif any(nl.endswith(e) for e in (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
            mode = "r:gz" if nl.endswith((".gz", ".tgz")) else "r:bz2" if nl.endswith(".bz2") else "r:xz" if nl.endswith(".xz") else "r"
            kw = {"fileobj": io.BytesIO(file_bytes), "mode": mode} if file_bytes else {"name": file_path, "mode": mode}
            with tarfile.open(**kw) as tf:
                safe = [m for m in tf.getmembers() if not m.name.startswith("/") and ".." not in m.name]
                tf.extractall(tmp, members=safe)
            return _root(tmp), ""
        elif nl.endswith(".7z"):
            try:
                import py7zr
            except ImportError:
                shutil.rmtree(tmp, True)
                return None, "7Z: pip install py7zr"
            src = io.BytesIO(file_bytes) if file_bytes else file_path
            with py7zr.SevenZipFile(src, "r") as z:
                z.extractall(tmp)
            return _root(tmp), ""
        else:
            shutil.rmtree(tmp, True)
            return None, f"지원하지 않는 형식: {file_name}"
    except Exception as e:
        shutil.rmtree(tmp, True)
        return None, str(e)


def cleanup_temp_dir(p):
    if p and os.path.isdir(p) and "sbom_scan_" in p:
        shutil.rmtree(p, True)


def _root(tmp):
    entries = [e for e in os.listdir(tmp) if not e.startswith((".", "__"))]
    if len(entries) == 1 and os.path.isdir(os.path.join(tmp, entries[0])):
        return os.path.join(tmp, entries[0])
    return tmp
