"""
Read helpers over the installed analysis views (the "reads" side of file_analyzer.views).

These mirror what the Go/Java worker programs do, in Python: open the database
strictly read-only, enumerate the installed VIEW objects, and SELECT from them.
No query SQL is embedded here beyond ``SELECT * FROM "<view>"`` -- the views
themselves (built from [[catalog]]) carry the analytical SQL.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union


def _connect_ro(db_path: Union[str, Path]) -> sqlite3.Connection:
    """Open a SQLite database read-only (query_only enforced)."""
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only = ON")
    return conn


def list_views(db_path: Union[str, Path]) -> List[str]:
    """Return the names of the VIEW objects present in the database, sorted."""
    conn = _connect_ro(db_path)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name"
        )
        return [row[0] for row in cur.fetchall()]
    finally:
        conn.close()


def read_view(
    db_path: Union[str, Path],
    view_name: str,
    limit: int = 50,
) -> Tuple[List[str], List[Tuple[Any, ...]]]:
    """
    Read one view. Returns (column_names, rows). ``limit`` caps returned rows
    (<= 0 means no cap). The view name is validated against the installed views
    to keep the interpolated identifier safe.
    """
    installed = set(list_views(db_path))
    if view_name not in installed:
        raise KeyError(f"no such view: {view_name!r}")
    conn = _connect_ro(db_path)
    try:
        sql = f'SELECT * FROM "{view_name}"'
        if limit and limit > 0:
            sql += f" LIMIT {int(limit)}"
        cur = conn.execute(sql)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchall()
        return cols, rows
    finally:
        conn.close()


def read_all_views(
    db_path: Union[str, Path],
    limit: int = 50,
) -> Dict[str, Dict[str, Any]]:
    """
    Read every installed view. Returns {view_name: {"columns": [...], "rows": [...]}}.
    A view that errors at query time is captured as {"error": "..."} rather than
    aborting the whole read.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for name in list_views(db_path):
        try:
            cols, rows = read_view(db_path, name, limit=limit)
            out[name] = {"columns": cols, "rows": rows}
        except Exception as exc:  # keep going; report per-view
            out[name] = {"error": str(exc)}
    return out
