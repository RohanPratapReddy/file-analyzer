"""
file_analyzer.client.native_reader -- the client wheel's own concurrent view reader.

This is the *client-local* counterpart of the engine wheel's
:mod:`file_analyzer.views.native_reader`. It makes ``file-analyzer-client``
self-sufficient for concurrent bulk view reads: it drives the client's own Go
reader (``file_analyzer/client/go/reader.go``) -- a fixed goroutine pool that
reads every requested ``v_*`` view strictly read-only and emits one JSON object of
``{view: {columns, rows}}`` -- without needing the analyzer fleet (engine wheel)
installed.

Two paths, exactly like every other Go-accelerated stage in the platform:

* the fast path is the **Go reader**, built on demand with ``go build`` and simply
  skipped when the Go toolchain is not on ``PATH``;
* the fallback is a **concurrent pure-Python read** (``ThreadPoolExecutor`` over
  read-only ``sqlite3`` connections), so the read works on a bare interpreter with
  nothing but the standard library -- the client wheel's contract.

Read-only: the Go reader opens the database ``mode=ro`` + ``PRAGMA query_only`` and
aborts on a write-canary; the Python path sets ``PRAGMA query_only`` too. Neither
ever writes. This module imports only the standard library.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import sqlite3
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

# file_analyzer/client/native_reader.py -> the client package's own go/ tree.
_GO_DIR = Path(__file__).resolve().parent / "go"


# ---------------------------------------------------------------------------
# View discovery + pure-Python read (read-only)
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


def _read_python(
    db_path: str, views: List[str], limit: int
) -> Dict[str, Dict[str, Any]]:
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
# Toolchain build (on demand)
# ---------------------------------------------------------------------------
def _go_binary(log: List[str]) -> Optional[Path]:
    if shutil.which("go") is None:
        return None
    exe = _GO_DIR / ("client-reader.exe" if os.name == "nt" else "client-reader")
    try:
        proc = subprocess.run(
            ["go", "build", "-o", exe.name, "."],
            cwd=_GO_DIR,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            log.append(f"[client-read] go build failed:\n{proc.stderr}")
            return None
        return exe
    except OSError as err:
        log.append(f"[client-read] go build error: {err}")
        return None


def _run_reader(
    cmd: List[str], cwd: Path, log: List[str], timeout: int
) -> Optional[Dict[str, Any]]:
    """Run the native reader in -json mode; return its parsed object or None."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        log.append(f"[client-read] {cmd[0]} launch/timeout error: {err}")
        return None
    if proc.returncode != 0:
        log.append(
            f"[client-read] {cmd[0]} exit {proc.returncode}: {proc.stderr.strip()[:500]}"
        )
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as err:
        log.append(f"[client-read] {cmd[0]} produced non-JSON stdout: {err}")
        return None


def _go_cmd(
    exe: Path, db_path: str, views: List[str], limit: int, workers: int
) -> List[str]:
    return [
        str(exe),
        "-source",
        db_path,
        "-json",
        "-views",
        ",".join(views),
        "-limit",
        str(limit),
        "-workers",
        str(workers),
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
    """Read installed views with the client's own concurrent Go reader.

    Hands the full view set to the Go reader, which fans out across a goroutine
    pool sized by ``workers``. Any view the Go reader failed to return is
    transparently re-read in-process, so the returned ``views`` mapping is always
    complete.

    Returns ``{"engine": "go", "used": {"go": n}, "views": {name: {...}},
    "log": [...]}`` -- or ``None`` if the Go toolchain is not available (caller
    should fall back to a pure-Python read).
    """
    targets = list(views) if views is not None else _installed_views(db_path)
    if not targets:
        return {"engine": "none", "used": {"go": 0}, "views": {}, "log": []}

    log: List[str] = []
    go_exe = _go_binary(log)
    if go_exe is None:
        return None  # no Go toolchain -> caller uses pure Python

    workers = workers or max(1, (os.cpu_count() or 2))

    merged: Dict[str, Dict[str, Any]] = {}
    result = _run_reader(
        _go_cmd(go_exe, db_path, targets, limit, workers), _GO_DIR, log, timeout
    )
    if result is None:
        log.append(
            f"[client-read] go reader failed; python fallback for {len(targets)} views"
        )
        merged.update(_read_python(db_path, targets, limit))
    else:
        views_obj = result.get("views", {}) or {}
        errors_obj = result.get("errors", {}) or {}
        for name, payload in views_obj.items():
            merged[name] = payload
        for name, msg in errors_obj.items():
            merged[name] = {"error": msg}
        missing = [v for v in targets if v not in merged]
        if missing:
            log.append(
                f"[client-read] go reader omitted {len(missing)} views; python backfill"
            )
            merged.update(_read_python(db_path, missing, limit))

    return {
        "engine": "go",
        "used": {"go": len(targets)},
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
    this overlaps I/O) and merges the results. Always available, needing no Go
    toolchain, so it is what the caller falls back to when
    :func:`read_views_native` returns ``None``. Returns the same shape as
    :func:`read_views_native` with ``engine`` set to ``"python"``.
    """
    targets = list(views) if views is not None else _installed_views(db_path)
    if not targets:
        return {"engine": "python", "used": {"python": 0}, "views": {}, "log": []}

    n = max(1, min(workers or (os.cpu_count() or 2), len(targets)))
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
