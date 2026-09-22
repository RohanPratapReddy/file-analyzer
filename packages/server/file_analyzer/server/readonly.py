"""
Read-only SQLite query guard, shared by the host and the control plane.

This is the same single-statement read-only contract enforced by the MCP server
and the SDK's :class:`~file_analyzer.sdk.FileAnalyzerDatabase`: a query must be a
single ``SELECT`` or ``WITH`` statement, run against a connection opened in
read-only mode with ``query_only`` pinned on. It is replicated here (rather than
imported from ``mcp_server``) so the hosting server never pulls in the optional
``mcp`` dependency.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, Sequence, Union

PathLike = Union[str, "Path"]


def is_readonly_select(sql: str) -> bool:
    """True only for a single ``SELECT``/``WITH`` statement (no extra ``;``)."""
    if not sql or not sql.strip():
        return False
    stripped = sql.strip().rstrip(";")
    # Reject anything with an embedded statement separator (multi-statement).
    if ";" in stripped:
        return False
    head = stripped.lstrip().split(None, 1)[0].lower() if stripped.strip() else ""
    return head in ("select", "with")


def connect_readonly(db_path: PathLike) -> sqlite3.Connection:
    """Open ``db_path`` read-only with ``query_only`` enforced."""
    p = Path(db_path)
    if not p.is_file():
        raise FileNotFoundError(f"no such database: {p}")
    uri = f"file:{p.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def run_readonly_query(
    db_path: PathLike, sql: str, params: Sequence[Any] = (), limit: int = 100
) -> Dict[str, Any]:
    """Execute a validated read-only query and return a column/row payload.

    Returns ``{"columns", "rows", "row_count", "truncated"}``. ``limit`` caps the
    number of rows returned (``None`` or a non-positive value means no cap); one
    extra row is fetched to report ``truncated`` honestly.
    """
    if not is_readonly_select(sql):
        raise ValueError("only a single read-only SELECT/WITH query is allowed")
    conn = connect_readonly(db_path)
    try:
        cur = conn.execute(sql, tuple(params))
        columns = [d[0] for d in cur.description] if cur.description else []
        if limit and limit > 0:
            fetched = cur.fetchmany(limit + 1)
            truncated = len(fetched) > limit
            rows = [list(r) for r in fetched[:limit]]
        else:
            rows = [list(r) for r in cur.fetchall()]
            truncated = False
    finally:
        conn.close()
    return {
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "truncated": truncated,
    }
