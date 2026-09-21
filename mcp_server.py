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

    python -m mcp_server          # or: file-analyzer-mcp  (installed console script)

Register it with an agent, e.g. Claude Code:

    claude mcp add file-analyzer -- python -m mcp_server

Requires the MCP SDK:  pip install "mcp[cli]"

This module deliberately sits at the repository root rather than under ``src``:
importing anything inside the ``src`` package runs ``src/__init__.py``, which
eagerly loads the whole analyzer fleet (~360 ms). Keeping the server outside the
package lets the stdio handshake come up fast and defers that cost to the first
tool call that actually needs the engine.

To avoid paying that ~360 ms on the *first* tool call, ``main()`` fires a
background warm-up thread (:func:`warm_cache`) at startup that bytecode-compiles
``src/`` and imports the fleet while the agent is still handshaking. Set
``FILE_ANALYZER_MCP_NO_WARM=1`` to disable it, or run the one-shot

    python -m mcp_server --precompile      # compile + import, then exit

once at install / MCP-registration time (e.g. in a Dockerfile or postinstall) so
the very first server launch is already warm.

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
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

# This module lives at the repository root (NOT inside the ``src`` package) so
# that importing it does not trigger ``src/__init__.py`` -- see the note below.
# Make ``import src`` resolve no matter how this module was launched.
_READERS_ROOT = Path(__file__).resolve().parent
if str(_READERS_ROOT) not in sys.path:
    sys.path.insert(0, str(_READERS_ROOT))

from mcp.server.fastmcp import FastMCP  # noqa: E402

# NOTE: the views layer (``src.views``) is imported lazily, inside the tools that
# need it -- see ``_views()`` below. Importing anything under ``src`` runs
# ``src/__init__.py``, which eagerly loads the entire analyzer fleet (~360 ms,
# dominated by src.prog_lang). None of that is needed to stand the server up, so
# deferring it keeps the stdio handshake fast; the cost is paid on first use.

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


def _toolchains() -> Dict[str, bool]:
    """Report which native language toolchains are on PATH.

    The analysis planes (``src.router``) and the view readers (``src.views``) both
    speed up with Go and/or Java present and transparently fall back to concurrent
    Python when absent. Surfacing this lets an agent know whether it actually got
    the cross-language fast path.
    """
    import shutil

    return {
        "go": shutil.which("go") is not None,
        "java": shutil.which("java") is not None and shutil.which("javac") is not None,
    }


def _views():
    """Lazily import the views layer (see the import note near the top).

    Returns ``(VIEW_CATALOG, list_views)``. After the first call Python has the
    modules cached, so this is a cheap dict lookup on subsequent calls.
    """
    from src.views import VIEW_CATALOG, list_views

    return VIEW_CATALOG, list_views


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
    plane_workers: Optional[int] = None,
    injection_workers: Optional[int] = None,
) -> Dict[str, Any]:
    """Analyze a repository and build a queryable database of everything in it.

    Walks the source tree (code, schemas, data files, archives, binaries, configs,
    docs), never executing it, and emits a SQLite database plus a SQL dump, both
    carrying the ready-made ``v_*`` analysis views. Returns a JSON summary that
    includes the ``database`` path to pass to ``query``/``list_views``.

    The analysis planes fan out across Go and Java workers when those toolchains
    are on PATH (falling back to concurrent Python otherwise); ``plane_workers``
    and ``injection_workers`` tune that stage, and the returned ``toolchains``
    field reports which native fast paths were actually available.

    Args:
        path: Directory to analyze. Must be a git repository unless no_git=True.
        out_dir: Where to write artifacts. Default: ``<path>/.file-analyzer``.
        dialect: SQL dump dialect -- "sqlite" (default) or "postgresql".
        no_git: Census every file on disk instead of only git-tracked files.
        workers: Worker count for the concurrent census/analysis stages (default: CPU count).
        plane_workers: Concurrency for the Go/Java analysis planes (default: CPU count).
        injection_workers: Concurrency for the DB injection stage (default: CPU count).
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
        plane_workers=plane_workers,
        injection_workers=injection_workers,
    )
    with _hushed():
        summary = dict(engine.run())
    summary["database"] = str(db_path)
    summary["sql_dump"] = str(sql_path)
    summary["toolchains"] = _toolchains()
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
    view_catalog, _list_views = _views()
    names = _list_views(db_path)
    catalog = {v.object_name: list(v.tables) for v in view_catalog}
    return {
        "count": len(names),
        "views": [
            {"name": n, "base_tables": catalog.get(n, [])} for n in names
        ],
    }


@mcp.tool()
def read_views(
    db_path: str,
    views: Optional[str] = None,
    limit: int = 50,
    engine: str = "auto",
    workers: Optional[int] = None,
) -> Dict[str, Any]:
    """Bulk-read the ``v_*`` analysis views in one call, using Go + Java concurrently.

    Reads many views at once instead of issuing a ``query`` per view. With
    ``engine="auto"`` (default) it partitions the views across the native Go and
    Java readers and runs them at the same wall-clock time -- real cross-language
    parallelism -- transparently falling back to a concurrent pure-Python read
    when neither toolchain is on PATH. Every read is strictly read-only.

    Args:
        db_path: Path to the repository.db produced by analyze_repository.
        views: Comma-separated view names to read (default: every installed view).
        limit: Max rows per view (<= 0 means no cap).
        engine: "auto" (native, else Python), "native" (Go/Java, error if absent),
            or "python" (concurrent in-process, no toolchain needed).
        workers: Per-language worker count (default: CPU count).

    Returns ``{"engine", "used", "view_count", "views": {name: {columns, rows} |
    {error}}}``. ``engine`` reports what actually ran (e.g. "go+java", "go",
    "java", or "python").
    """
    from src.views.native_reader import read_views_native, read_views_python

    view_list: Optional[List[str]] = None
    if views:
        view_list = [v.strip() for v in views.split(",") if v.strip()]

    eng = engine.lower().strip()
    result: Optional[Dict[str, Any]] = None
    with _hushed():
        if eng in ("auto", "native"):
            result = read_views_native(
                db_path, views=view_list, limit=limit, workers=workers
            )
            if result is None and eng == "native":
                raise RuntimeError(
                    "native readers unavailable: neither the Go nor the Java "
                    "toolchain is on PATH (use engine='auto' or 'python')"
                )
        if result is None:  # eng == "python", or auto with no toolchain
            result = read_views_python(
                db_path, views=view_list, limit=limit, workers=workers
            )

    return {
        "engine": result["engine"],
        "used": result["used"],
        "view_count": len(result["views"]),
        "views": result["views"],
    }


@mcp.tool()
def describe_schema(db_path: str, include_views: bool = True) -> Dict[str, Any]:
    """Describe the tables (and views) of a repository database.

    Returns each base table with its columns and types, so an agent can write
    precise SQL against the raw relational output when the ``v_*`` views don't
    cover a question. With include_views, also returns the installed views and
    the catalog SQL behind each one.
    """
    view_catalog, _list_views = _views()
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
                for v in view_catalog
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

    view_catalog, _ = _views()
    payload = {
        "count": len(view_catalog),
        "views": [
            {"name": v.object_name, "base_tables": list(v.tables), "select": v.select}
            for v in view_catalog
        ],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# Warm-up: pay the deferred fleet-load cost off the critical path
# ---------------------------------------------------------------------------
# Keeping the server outside the ``src`` package makes the stdio handshake fast,
# but it pushes the ~360 ms fleet-load onto whichever tool call fires first. This
# warm-up does that work up front -- bytecode-compiling ``src/`` (so ``.pyc`` is
# cached) and executing the heavy imports -- either in a background thread while
# the agent is still handshaking/idle, or synchronously as a one-shot at install
# / registration time. By the time the first analyze/query arrives, ``src`` is
# already resident in ``sys.modules`` and the call runs at full speed.
_ENV_NO_WARM = "FILE_ANALYZER_MCP_NO_WARM"


def warm_cache() -> None:
    """Bytecode-compile ``src/`` and import the analyzer fleet (best-effort).

    Safe to call more than once and from any thread: Python's import lock makes
    the heavy imports idempotent, and a concurrent first tool call simply blocks
    on that same lock instead of re-executing anything. Any failure (e.g. a
    read-only install dir that rejects ``.pyc`` writes) is swallowed -- the tools
    still import ``src`` lazily on demand, so warm-up is a pure optimization.

    stdout is routed to stderr throughout: the MCP stdio transport owns stdout for
    JSON-RPC, and neither ``compileall`` nor an import must be allowed to write to
    it.
    """
    try:
        with _hushed():
            import compileall

            compileall.compile_dir(
                str(_READERS_ROOT / "src"), quiet=1, optimize=0
            )
            # Execute the bodies so they land in sys.modules before any tool runs.
            import src  # noqa: F401  (runs src/__init__.py -> the whole fleet)
            import src.core.analysis_engine  # noqa: F401  (analyze_repository path)
            import src.main  # noqa: F401  (run_component / list_components path)
    except Exception:  # warm-up is best-effort; lazy imports remain the fallback
        pass


def _start_warm_cache() -> Optional[threading.Thread]:
    """Kick off :func:`warm_cache` in a daemon thread unless disabled by env."""
    if os.environ.get(_ENV_NO_WARM):
        return None
    t = threading.Thread(target=warm_cache, name="fa-warm-cache", daemon=True)
    t.start()
    return t


def main() -> None:
    # ``python -m mcp_server --precompile`` / ``file-analyzer-mcp --precompile``:
    # do the warm-up synchronously and exit, without starting the server. Run this
    # once at install or MCP-registration time (Dockerfile, postinstall, CI) so the
    # first real server the agent launches is already warm.
    if "--precompile" in sys.argv[1:]:
        warm_cache()
        return
    _start_warm_cache()
    mcp.run()


if __name__ == "__main__":
    main()
