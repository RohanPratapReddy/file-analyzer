"""
Process-wide registry of running monitors + read helpers.

The MCP server (and any long-lived host) can run several :class:`RepositoryMonitor`
daemons at once -- one per watched repository. This module keeps a single global
registry keyed by the resolved root path, so ``start_monitor`` is idempotent and
``stop_monitor`` / ``status`` can find the live instance. An ``atexit`` hook stops
every registered monitor on interpreter shutdown, so no daemon thread (or its
worker children) is left dangling.

Reading recent changes never requires an in-process monitor: the diff database is
opened strictly read-only via :func:`connect_readonly`, so an agent can inspect a
repo watched by a *separate* ``python -m file_analyzer`` process just as easily as one it
started itself.
"""

from __future__ import annotations

import atexit
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .change_log import ChangeLogStore
from .diff_db import connect_readonly
from .monitor import RepositoryMonitor
from .session_log import SessionSummaryStore

_LOCK = threading.RLock()
_MONITORS: Dict[str, RepositoryMonitor] = {}
_ATEXIT_REGISTERED = False


def _key(root) -> str:
    return str(Path(root).resolve())


def _ensure_atexit() -> None:
    global _ATEXIT_REGISTERED
    if not _ATEXIT_REGISTERED:
        atexit.register(stop_all)
        _ATEXIT_REGISTERED = True


def start_monitor(root, **kwargs: Any) -> RepositoryMonitor:
    """Start (or return the already-running) monitor for ``root``."""
    key = _key(root)
    with _LOCK:
        existing = _MONITORS.get(key)
        if existing is not None:
            return existing
        mon = RepositoryMonitor(root, **kwargs)
        mon.start()
        _MONITORS[key] = mon
        _ensure_atexit()
        return mon


def get_monitor(root) -> Optional[RepositoryMonitor]:
    with _LOCK:
        return _MONITORS.get(_key(root))


def stop_monitor(root, timeout: float = 10.0) -> bool:
    """Stop and deregister the monitor for ``root``. Returns True if one was running."""
    key = _key(root)
    with _LOCK:
        mon = _MONITORS.pop(key, None)
    if mon is None:
        return False
    mon.close()
    return True


def stop_all() -> None:
    with _LOCK:
        monitors = list(_MONITORS.values())
        _MONITORS.clear()
    for mon in monitors:
        try:
            mon.close()
        except Exception:
            pass


def list_monitors() -> List[str]:
    with _LOCK:
        return sorted(_MONITORS)


# ---------------------------------------------------------------------------
# Read helpers (work whether or not this process owns the monitor)
# ---------------------------------------------------------------------------
def _resolve_db_path(root=None, diff_db_path=None) -> Path:
    if diff_db_path:
        return Path(diff_db_path).resolve()
    if root:
        return Path(root).resolve() / ".file-analyzer" / "monitor" / "changes.db"
    raise ValueError("either root or diff_db_path is required")


def read_recent_changes(
    root=None, diff_db_path=None, limit: int = 16
) -> Dict[str, Any]:
    db_path = _resolve_db_path(root, diff_db_path)
    conn = connect_readonly(str(db_path))
    try:
        rows = conn.execute(
            "SELECT * FROM change_events ORDER BY seq DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
        meta = {
            r["key"]: r["value"]
            for r in conn.execute("SELECT key, value FROM monitor_meta").fetchall()
        }
    finally:
        conn.close()
    return {
        "database": str(db_path),
        "root": meta.get("root"),
        "running": meta.get("running"),
        "capacity": meta.get("capacity"),
        "count": len(rows),
        "changes": [dict(r) for r in rows],
    }


def _default_change_log_path(root) -> str:
    return str(Path(root).resolve() / ".file-analyzer" / "monitor" / "changes_log.db")


def _default_session_path(root) -> str:
    return str(Path(root).resolve() / ".file-analyzer" / "monitor" / "sessions.db")


# ---------------------------------------------------------------------------
# Durable change log (superset of the FIFO ring; local or remote)
# ---------------------------------------------------------------------------
def read_change_log(
    root, url: Optional[str] = None, limit: int = 50, rel_path: Optional[str] = None
) -> Dict[str, Any]:
    """Read the continuous change log for ``root`` (local SQLite or remote URL)."""
    store = ChangeLogStore(
        repo=_key(root), url=url, default_path=_default_change_log_path(root)
    ).initialize()
    try:
        if rel_path:
            rows = store.history_for_path(rel_path, limit=limit)
        else:
            rows = store.recent(limit=limit)
        total = store.count()
    finally:
        store.close()
    return {
        "repo": _key(root),
        "backend": store.display,
        "dialect": store.dialect,
        "total_archived": total,
        "count": len(rows),
        "changes": rows,
    }


# ---------------------------------------------------------------------------
# Session summaries (task / files / work / sentiment / improvements)
# ---------------------------------------------------------------------------
def record_session(
    root,
    task_given: str,
    work_done: str,
    files_changed=None,
    improvements: str = "",
    url: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Record one session summary for ``root``. Returns the stored row."""
    store = SessionSummaryStore(
        repo=_key(root), url=url, default_path=_default_session_path(root)
    ).initialize()
    try:
        sid = store.record_session(
            task_given=task_given,
            work_done=work_done,
            files_changed=files_changed,
            improvements=improvements,
            **kwargs,
        )
        return store.get_session(sid) or {"session_id": sid}
    finally:
        store.close()


def assess_last_session(
    root,
    next_prompt: str,
    url: Optional[str] = None,
    user_sentiment: Optional[str] = None,
    improvements: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Classify ``next_prompt`` against the most recent pending session for ``root``."""
    store = SessionSummaryStore(
        repo=_key(root), url=url, default_path=_default_session_path(root)
    ).initialize()
    try:
        return store.assess_last_session(
            next_prompt, user_sentiment=user_sentiment, improvements=improvements
        )
    finally:
        store.close()


def read_sessions(root, url: Optional[str] = None, limit: int = 20) -> Dict[str, Any]:
    """Read recent session summaries for ``root``."""
    store = SessionSummaryStore(
        repo=_key(root), url=url, default_path=_default_session_path(root)
    ).initialize()
    try:
        rows = store.recent_sessions(limit=limit)
        total = store.count()
    finally:
        store.close()
    return {
        "repo": _key(root),
        "backend": store.display,
        "dialect": store.dialect,
        "total_sessions": total,
        "count": len(rows),
        "sessions": rows,
    }


def read_status(root=None, diff_db_path=None) -> Dict[str, Any]:
    db_path = _resolve_db_path(root, diff_db_path)
    conn = connect_readonly(str(db_path))
    try:
        meta = {
            r["key"]: r["value"]
            for r in conn.execute("SELECT key, value FROM monitor_meta").fetchall()
        }
        buffered = conn.execute("SELECT COUNT(*) AS n FROM change_events").fetchone()[
            "n"
        ]
        by_type = {
            r["change_type"]: r["events"]
            for r in conn.execute(
                "SELECT change_type, COUNT(*) AS events FROM change_events "
                "GROUP BY change_type"
            ).fetchall()
        }
    finally:
        conn.close()
    return {
        "database": str(db_path),
        "root": meta.get("root"),
        "pid": meta.get("pid"),
        "running": meta.get("running"),
        "mode": meta.get("mode"),
        "interval": meta.get("interval"),
        "capacity": meta.get("capacity"),
        "buffered_events": buffered,
        "total_changes": meta.get("change_count"),
        "last_scan_ts": meta.get("last_scan_ts"),
        "last_error": meta.get("last_error"),
        "by_change_type": by_type,
        "in_process": (
            _key(meta.get("root") or db_path.parent) in list_monitors()
            if meta.get("root")
            else False
        ),
    }
