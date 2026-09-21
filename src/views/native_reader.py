"""
Native concurrent view readers: drive the Go and Java ``v_*`` view readers.

This is the "reads" counterpart of :mod:`src.router.planes` (which drives the Go
and Java *analysis* planes). The Go program (``src/views/go/main.go``) and the
Java program (``src/views/java/RepositoryReader.java``) can each read every
installed analysis view concurrently, strictly read-only, and -- with the
``-json`` flag -- emit a single machine-readable object of ``{view: {columns,
rows}}``. This module:

    * builds each reader on demand (``go build`` / ``javac``), like RouterPlanes,
    * partitions the view set across the two languages (even -> Go, odd -> Java),
    * runs both at the same wall-clock time (real cross-language parallelism),
    * merges the JSON results, and
    * falls back to an in-process Python read for any view whose language reader
      failed, so the returned mapping is always complete.

If neither the Go nor the Java toolchain is available, :func:`read_views_native`
returns ``None`` and the caller should use the pure-Python reader instead.

Read-only: both native readers open the database ``mode=ro`` + ``PRAGMA
query_only`` and abort on a write-canary; this module never writes.
"""

from __future__ import annotations

import concurrent.futures
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

# src/views/native_reader.py -> parents[2] == repository root (holds src/).
_READERS_ROOT = Path(__file__).resolve().parents[2]
_GO_DIR = _READERS_ROOT / "src" / "views" / "go"
_JAVA_DIR = _READERS_ROOT / "src" / "views" / "java"


# ---------------------------------------------------------------------------
# View discovery + pure-Python fallback read (read-only)
# ---------------------------------------------------------------------------
def _installed_views(db_path: str) -> List[str]:
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        conn.execute("PRAGMA query_only = ON")
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name"
        )
        return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()


def _read_python(db_path: str, views: List[str], limit: int) -> Dict[str, Dict[str, Any]]:
    """Read the given views in-process, read-only. Errors are captured per view."""
    out: Dict[str, Dict[str, Any]] = {}
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        conn.execute("PRAGMA query_only = ON")
        for name in views:
            try:
                sql = f'SELECT * FROM "{name.replace(chr(34), chr(34) * 2)}"'
                if limit and limit > 0:
                    sql += f" LIMIT {int(limit)}"
                cur = conn.execute(sql)
                cols = [d[0] for d in cur.description] if cur.description else []
                rows = [list(r) for r in cur.fetchall()]
                out[name] = {"columns": cols, "rows": rows}
            except Exception as exc:  # keep going; report per view
                out[name] = {"error": str(exc)}
    finally:
        conn.close()
    return out


# ---------------------------------------------------------------------------
# Toolchain build (on demand) -- mirrors src/router/planes.py
# ---------------------------------------------------------------------------
def _go_binary(log: List[str]) -> Optional[Path]:
    if shutil.which("go") is None:
        return None
    exe = _GO_DIR / ("repo-reader.exe" if os.name == "nt" else "repo-reader")
    try:
        proc = subprocess.run(
            ["go", "build", "-o", exe.name, "."],
            cwd=_GO_DIR, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            log.append(f"[native-read] go build failed:\n{proc.stderr}")
            return None
        return exe
    except OSError as err:
        log.append(f"[native-read] go build error: {err}")
        return None


def _java_classpath(log: List[str]) -> Optional[str]:
    """Compile RepositoryReader on demand; return the run classpath, or None."""
    if shutil.which("javac") is None or shutil.which("java") is None:
        return None
    jars = [Path(p).name for p in glob.glob(str(_JAVA_DIR / "*.jar"))]
    if not jars:
        log.append("[native-read] java: no JDBC/SLF4J jars found in src/views/java")
        return None
    out_dir = _JAVA_DIR / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    compile_cp = os.pathsep.join(jars)
    try:
        proc = subprocess.run(
            ["javac", "-cp", compile_cp, "-d", "out", "RepositoryReader.java"],
            cwd=_JAVA_DIR, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            log.append(f"[native-read] javac failed:\n{proc.stderr}")
            return None
    except OSError as err:
        log.append(f"[native-read] javac error: {err}")
        return None
    # Run classpath: compiled classes (out/) plus the jars, relative to _JAVA_DIR.
    return os.pathsep.join(["out"] + jars)


# ---------------------------------------------------------------------------
# Reader runners (subprocess -> JSON)
# ---------------------------------------------------------------------------
def _run_reader(cmd: List[str], cwd: Path, log: List[str], timeout: int) -> Optional[Dict[str, Any]]:
    """Run one native reader in -json mode; return its parsed object or None."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        log.append(f"[native-read] {cmd[0]} launch/timeout error: {err}")
        return None
    if proc.returncode != 0:
        log.append(f"[native-read] {cmd[0]} exit {proc.returncode}: {proc.stderr.strip()[:500]}")
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as err:
        log.append(f"[native-read] {cmd[0]} produced non-JSON stdout: {err}")
        return None


def _go_cmd(exe: Path, db_path: str, views: List[str], limit: int, workers: int) -> List[str]:
    return [
        str(exe), "-source", db_path, "-json",
        "-views", ",".join(views), "-limit", str(limit), "-workers", str(workers),
    ]


def _java_cmd(cp: str, db_path: str, views: List[str], limit: int, workers: int) -> List[str]:
    return [
        "java", "-cp", cp, "RepositoryReader", "-source", db_path, "-json",
        "-views", ",".join(views), "-limit", str(limit), "-workers", str(workers),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def read_views_native(
    db_path: str,
    views: Optional[List[str]] = None,
    limit: int = 50,
    workers: Optional[int] = None,
    timeout: int = 120,
) -> Optional[Dict[str, Any]]:
    """Read installed views with the Go + Java concurrent readers.

    Partitions the view set across the two languages and runs both concurrently.
    Any view whose language reader failed is transparently re-read in-process, so
    the returned ``views`` mapping is always complete.

    Returns ``{"engine": "go+java"|"go"|"java", "used": {"go": n, "java": n},
    "views": {name: {"columns", "rows"} | {"error"}}, "log": [...]}`` -- or
    ``None`` if neither the Go nor the Java toolchain is available (caller should
    fall back to a pure-Python read).
    """
    targets = list(views) if views is not None else _installed_views(db_path)
    if not targets:
        return {"engine": "none", "used": {"go": 0, "java": 0}, "views": {}, "log": []}

    log: List[str] = []
    go_exe = _go_binary(log)
    java_cp = _java_classpath(log)
    if go_exe is None and java_cp is None:
        return None  # no native toolchain -> caller uses pure Python

    workers = workers or max(1, (os.cpu_count() or 2))

    # Partition: both present -> even/odd split; only one present -> it takes all.
    if go_exe is not None and java_cp is not None:
        go_views = [v for i, v in enumerate(targets) if i % 2 == 0]
        java_views = [v for i, v in enumerate(targets) if i % 2 == 1]
    elif go_exe is not None:
        go_views, java_views = targets, []
    else:
        go_views, java_views = [], targets

    merged: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()

    def _collect(result: Optional[Dict[str, Any]], subset: List[str], cwd_note: str) -> None:
        if result is None:
            # Whole reader failed -> fill this subset from pure Python so the
            # response is still complete.
            log.append(f"[native-read] {cwd_note} failed; python fallback for {len(subset)} views")
            data = _read_python(db_path, subset, limit)
            with lock:
                merged.update(data)
            return
        views_obj = result.get("views", {}) or {}
        errors_obj = result.get("errors", {}) or {}
        with lock:
            for name, payload in views_obj.items():
                merged[name] = payload
            for name, msg in errors_obj.items():
                merged[name] = {"error": msg}

    def go_runner() -> None:
        if not go_views:
            return
        res = _run_reader(_go_cmd(go_exe, db_path, go_views, limit, workers), _GO_DIR, log, timeout)
        _collect(res, go_views, "go reader")

    def java_runner() -> None:
        if not java_views:
            return
        res = _run_reader(_java_cmd(java_cp, db_path, java_views, limit, workers), _JAVA_DIR, log, timeout)
        _collect(res, java_views, "java reader")

    threads = []
    if go_views:
        threads.append(threading.Thread(target=go_runner, name="go-view-reader"))
    if java_views:
        threads.append(threading.Thread(target=java_runner, name="java-view-reader"))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if go_exe is not None and java_cp is not None:
        engine = "go+java"
    elif go_exe is not None:
        engine = "go"
    else:
        engine = "java"

    return {
        "engine": engine,
        "used": {"go": len(go_views), "java": len(java_views)},
        "views": merged,
        "log": log,
    }


def read_views_python(
    db_path: str,
    views: Optional[List[str]] = None,
    limit: int = 50,
    workers: Optional[int] = None,
) -> Dict[str, Any]:
    """Concurrent pure-Python read -- the toolchain-free fallback.

    Chunks the view set across a thread pool (SQLite reads release the GIL, so
    this overlaps I/O) and merges the results. Always available -- unlike
    :func:`read_views_native` it needs no Go/Java toolchain -- so it is what the
    caller falls back to when ``read_views_native`` returns ``None``.

    Returns the same shape as :func:`read_views_native` with ``engine`` set to
    ``"python"``.
    """
    targets = list(views) if views is not None else _installed_views(db_path)
    if not targets:
        return {"engine": "python", "used": {"python": 0}, "views": {}, "log": []}

    n = max(1, min(workers or (os.cpu_count() or 2), len(targets)))
    # Round-robin chunks keep the per-thread connection count == n.
    chunks = [targets[i::n] for i in range(n)]
    merged: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        futures = [ex.submit(_read_python, db_path, c, limit) for c in chunks]
        for fut in concurrent.futures.as_completed(futures):
            data = fut.result()
            with lock:
                merged.update(data)
    return {
        "engine": "python",
        "used": {"python": len(targets)},
        "views": merged,
        "log": [],
    }
