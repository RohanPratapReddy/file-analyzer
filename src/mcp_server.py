"""
file-analyzer MCP server -- expose the analysis engine to AI agents.

This wraps the same in-process engine the CLI drives (``src.core.AnalysisEngine``
and the ``--component`` building blocks) behind the Model Context Protocol, so any
MCP-speaking agent (Claude Code/Desktop, opencode, Cursor, Cline, Windsurf,
Antigravity, ...) can:

    * analyze_repository(path)  -- turn a repo into a queryable SQLite database
    * query(sql, db_path)       -- ask questions of that database with plain SELECTs
    * list_views(db_path)       -- discover the ready-made v_* analysis views
    * describe_schema(db_path)   -- read tables/columns + the view catalog as context
    * run_component(name, path) -- run one analyzer block in isolation
    * list_components()         -- enumerate the runnable building blocks

The differentiator is `query`: the engine ships denormalized ``v_*`` views, so the
agent writes ordinary SQL instead of being handed a wall of text.

Run it (stdio transport):

    python -m src.mcp_server

Register it with an agent, e.g. Claude Code:

    claude mcp add file-analyzer -- python -m src.mcp_server

Requires the MCP SDK:  pip install "mcp[cli]"

--------------------------------------------------------------------------------
Read-only & protocol safety
--------------------------------------------------------------------------------
* The MCP stdio transport speaks JSON-RPC over *stdout*. The engine and the
  per-language analyzers print incidental progress to stdout, which would corrupt
  that stream, so every engine call here runs under ``redirect_stdout(sys.stderr)``.
* ``query`` opens the database strictly read-only (``mode=ro`` + ``PRAGMA
  query_only``) and rejects anything that is not a single SELECT/WITH statement.
  The engine never executes the code it analyzes and never stores raw payloads.
"""
from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make ``import src`` resolve no matter how this module was launched.
_READERS_ROOT = Path(__file__).resolve().parents[1]
if str(_READERS_ROOT) not in sys.path:
    sys.path.insert(0, str(_READERS_ROOT))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from src.views import VIEW_CATALOG, list_views as _list_views  # noqa: E402

mcp = FastMCP(
    "file-analyzer",
    instructions=(
        "Static, read-only code-intelligence for a repository. First call "
        "analyze_repository(path) to build a SQLite database of the repo (files, "
        "symbols, imports, DB schemas, data profiles). It returns a 'database' "
        "path. Then explore with list_views/describe_schema and answer questions "
        "with query(sql, db_path) -- prefer the ready-made v_* views (e.g. "
        "'SELECT * FROM v_extension_distribution'). The database is read-only; "
        "only SELECT/WITH queries are accepted."
    ),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def _hushed():
    """Run engine code with its incidental stdout chatter routed to stderr.

    Mandatory around anything that touches the analyzers: the MCP stdio transport
    owns stdout for JSON-RPC, and the engine prints progress lines to stdout.
    """
    with contextlib.redirect_stdout(sys.stderr):
        yield


def _connect_ro(db_path: str) -> sqlite3.Connection:
    """Open a SQLite database read-only (query_only enforced)."""
    p = Path(db_path)
    if not p.is_file():
        raise FileNotFoundError(f"database not found: {db_path}")
    conn = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only = ON")
    return conn


def _is_readonly_select(sql: str) -> bool:
    """True only for a single SELECT/WITH statement (belt-and-suspenders on ro)."""
    s = sql.strip().rstrip(";").lstrip()
    if not s:
        return False
    # Reject multiple statements (a stray ';' between two statements).
    if ";" in s:
        return False
    head = s[:6].lower()
    return head.startswith("select") or head.startswith("with")


def _rows_as_dicts(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cur.description] if cur.description else []
    return [dict(zip(cols, row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def analyze_repository(
    path: str,
    out_dir: Optional[str] = None,
    dialect: str = "sqlite",
    no_git: bool = False,
    workers: Optional[int] = None,
) -> Dict[str, Any]:
    """Analyze a repository and build a queryable database of everything in it.

    Walks the source tree (code, schemas, data files, archives, binaries, configs,
    docs), never executing it, and emits a SQLite database plus a SQL dump, both
    carrying the ready-made ``v_*`` analysis views. Returns a JSON summary that
    includes the ``database`` path to pass to ``query``/``list_views``.

    Args:
        path: Directory to analyze. Must be a git repository unless no_git=True.
        out_dir: Where to write artifacts. Default: ``<path>/.file-analyzer``.
        dialect: SQL dump dialect -- "sqlite" (default) or "postgresql".
        no_git: Census every file on disk instead of only git-tracked files.
        workers: Worker count for the concurrent stages (default: CPU count).
    """
    from src.core.analysis_engine import AnalysisEngine

    source = Path(path).expanduser().resolve()
    if not source.is_dir():
        raise NotADirectoryError(f"source is not a directory: {source}")

    out = Path(out_dir).expanduser().resolve() if out_dir else source / ".file-analyzer"
    out.mkdir(parents=True, exist_ok=True)
    db_path = out / "repository.db"
    sql_path = out / "repository_schema.sql"

    engine = AnalysisEngine(
        dir_path=source,
        db_path=db_path,
        sql_path=sql_path,
        temp_dir=out / "temp",
        sql_dialect=dialect,
        git_tracked=not no_git,
        workers=workers,
    )
    with _hushed():
        summary = dict(engine.run())
    summary["database"] = str(db_path)
    summary["sql_dump"] = str(sql_path)
    return summary


@mcp.tool()
def query(sql: str, db_path: str, limit: int = 100) -> Dict[str, Any]:
    """Run a read-only SQL query against an analyzed repository database.

    Only a single SELECT/WITH statement is accepted; the database is opened
    read-only. Prefer the ready-made ``v_*`` views (see list_views) -- e.g.
    ``SELECT * FROM v_import_edges`` or ``SELECT * FROM v_symbols_by_kind`` --
    or query the base tables directly (see describe_schema).

    Args:
        sql: A single SELECT or WITH query.
        db_path: Path to the repository.db produced by analyze_repository.
        limit: Max rows to return (<= 0 means no cap). A LIMIT you write in the
            SQL is respected; this caps anything larger.
    """
    if not _is_readonly_select(sql):
        raise ValueError("only a single read-only SELECT/WITH query is allowed")
    conn = _connect_ro(db_path)
    try:
        cur = conn.execute(sql)
        rows = _rows_as_dicts(cur)
    finally:
        conn.close()
    truncated = False
    if limit and limit > 0 and len(rows) > limit:
        rows = rows[:limit]
        truncated = True
    return {"row_count": len(rows), "truncated": truncated, "rows": rows}


@mcp.tool()
def list_views(db_path: str) -> Dict[str, Any]:
    """List the analysis views installed in a repository database.

    Each ``v_*`` view is a ready-made answer (extension distribution, import
    edges, symbol counts, schema foreign keys, data profiles, ...) you can read
    with ``SELECT * FROM <view>`` via the query tool.
    """
    names = _list_views(db_path)
    catalog = {v.object_name: list(v.tables) for v in VIEW_CATALOG}
    return {
        "count": len(names),
        "views": [
            {"name": n, "base_tables": catalog.get(n, [])} for n in names
        ],
    }


@mcp.tool()
def describe_schema(db_path: str, include_views: bool = True) -> Dict[str, Any]:
    """Describe the tables (and views) of a repository database.

    Returns each base table with its columns and types, so an agent can write
    precise SQL against the raw relational output when the ``v_*`` views don't
    cover a question. With include_views, also returns the installed views and
    the catalog SQL behind each one.
    """
    conn = _connect_ro(db_path)
    try:
        tnames = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        tables = []
        for t in tnames:
            cols = conn.execute(f'PRAGMA table_info("{t}")').fetchall()
            tables.append(
                {
                    "name": t,
                    "columns": [
                        {"name": c[1], "type": c[2] or "", "pk": bool(c[5])}
                        for c in cols
                    ],
                }
            )
        result: Dict[str, Any] = {"table_count": len(tables), "tables": tables}
        if include_views:
            installed = set(_list_views(db_path))
            result["views"] = [
                {
                    "name": v.object_name,
                    "base_tables": list(v.tables),
                    "select": v.select,
                }
                for v in VIEW_CATALOG
                if v.object_name in installed
            ]
        return result
    finally:
        conn.close()


@mcp.tool()
def run_component(
    component: str,
    path: str,
    out_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a single analyzer building block over a repo and return its tables.

    Use this for targeted analysis without the full pipeline: a language analyzer
    ("PythonAnalyzer", "RustAnalyzer", ...), a plane ("code", "schema", "data",
    "config", "text", "markup", "document", "database", "misc"), or "census".
    Call list_components for valid names. Returns the component's summary and the
    path to the emitted tables JSON.

    Args:
        component: Component name (case-insensitive). See list_components.
        path: Directory to analyze.
        out_dir: Where to write the emitted JSON (default: ``<path>/.file-analyzer``).
    """
    from src.main import build_parser, run_component as _run_component

    source = Path(path).expanduser().resolve()
    if not source.is_dir():
        raise NotADirectoryError(f"source is not a directory: {source}")
    out = Path(out_dir).expanduser().resolve() if out_dir else source / ".file-analyzer"
    out.mkdir(parents=True, exist_ok=True)
    emit = out / f"{component}_analysis.json"

    args = build_parser().parse_args(
        [str(source), "--component", component, "--out", str(out), "--emit", str(emit)]
    )
    with _hushed():
        rc = _run_component(args)
    if rc != 0:
        raise RuntimeError(f"component {component!r} failed (exit {rc})")

    payload: Dict[str, Any] = {"component": component, "emit_path": str(emit)}
    try:
        import json

        payload["tables"] = json.loads(emit.read_text(encoding="utf-8"))
    except Exception:  # the summary path is still useful without inlined tables
        pass
    return payload


@mcp.tool()
def list_components() -> Dict[str, Any]:
    """Enumerate the analyzer building blocks runnable via run_component."""
    from src.main import list_components as _list_components

    with _hushed():
        return _list_components()


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------
@mcp.resource("file-analyzer://views")
def views_catalog() -> str:
    """The catalog of v_* analysis views (name, base tables, SQL) as JSON."""
    import json

    payload = {
        "count": len(VIEW_CATALOG),
        "views": [
            {"name": v.object_name, "base_tables": list(v.tables), "select": v.select}
            for v in VIEW_CATALOG
        ],
    }
    return json.dumps(payload, indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
