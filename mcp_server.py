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


def _package_version() -> str:
    """Recover the file-analyzer version WITHOUT importing the analyzer fleet.

    Kept fleet-import-free for the same reason the tools import ``src`` lazily:
    ``import src`` runs ``src/__init__.py`` and pulls in the whole analyzer fleet,
    which would slow the stdio handshake this function feeds. So it prefers the
    installed distribution's metadata (``importlib.metadata``) and, when the
    package is not installed (e.g. running from a source checkout), falls back to
    statically parsing ``src/_version.py`` -- the single source of truth, a bare
    literal assignment -- rather than importing it. Never raises; returns a
    ``0+unknown`` sentinel only if every path fails.
    """
    with contextlib.suppress(Exception):
        from importlib.metadata import PackageNotFoundError
        from importlib.metadata import version as _dist_version

        try:
            return _dist_version("file-analyzer")
        except PackageNotFoundError:
            pass
    with contextlib.suppress(Exception):
        import re

        text = (_READERS_ROOT / "src" / "_version.py").read_text(encoding="utf-8")
        m = re.search(r"""__version__\s*=\s*["']([^"']+)["']""", text)
        if m:
            return m.group(1)
    return "0+unknown"


__version__ = _package_version()

mcp = FastMCP(
    "file-analyzer",
    instructions=(
        "Repository-intelligence platform. It never executes the analyzed code: "
        "it parses a source tree into a queryable SQLite database (files, symbols, "
        "imports, DB schemas, data profiles) and can also watch the repo live and "
        "enrich files via an agent tier. First call analyze_repository(path) to "
        "build the database -- it returns a 'database' path. Then explore with "
        "list_views/describe_schema and answer questions with query(sql, db_path) "
        "-- prefer the ready-made v_* views (e.g. 'SELECT * FROM "
        "v_extension_distribution'). The query interface opens the database "
        "read-only and accepts only SELECT/WITH statements. Call server_info() to "
        "see this server's version and available native toolchains."
    ),
)

# Advertise the package version on the MCP handshake: FastMCP has no ``version``
# constructor argument, but the low-level server it wraps carries a ``version``
# that surfaces in the initialize response's ``serverInfo.version`` -- so a
# connecting agent sees exactly which file-analyzer build is answering. Guarded
# because the private attribute is not part of FastMCP's public API.
with contextlib.suppress(Exception):
    mcp._mcp_server.version = __version__


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
def server_info() -> Dict[str, Any]:
    """Identify this server: its file-analyzer version and native toolchains.

    Handy right after connecting to confirm which build is answering (the same
    version advertised on the MCP handshake as ``serverInfo.version``) and whether
    the Go/Java cross-language fast paths are available on this host (they fall
    back to concurrent Python when absent).
    """
    return {
        "name": "file-analyzer",
        "version": __version__,
        "toolchains": _toolchains(),
    }


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
        "views": [{"name": n, "base_tables": catalog.get(n, [])} for n in names],
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
    from src.main import build_parser
    from src.main import run_component as _run_component

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
# Repository monitor (background incremental-update layer)
# ---------------------------------------------------------------------------
# These expose the always-on monitor: it watches a repository and keeps a rolling
# 16-deep FIFO of what changed (created/modified/deleted), re-analyzing each
# changed file with the correct analyzer as it happens. An agent can start a
# monitor for the repo it is working in and then ask "what changed?" at any time.
#
# In-server safety: a monitor started here forces ALL re-analysis through the
# subprocess worker pool (inline_threshold=0), whose child stdout is captured, so
# analyzer chatter never corrupts the MCP JSON-RPC stream on stdout.


@mcp.tool()
def start_monitor(
    path: str,
    interval: float = 2.0,
    capacity: int = 16,
    out_dir: Optional[str] = None,
    max_workers: int = 128,
    min_workers: int = 16,
    reanalyze: bool = True,
    change_log: bool = True,
    change_log_url: Optional[str] = None,
    enable_agents: bool = False,
    agents_include: Optional[List[str]] = None,
    agents_exclude: Optional[List[str]] = None,
    discover_agents: bool = True,
    agent_roster: Optional[str] = None,
) -> Dict[str, Any]:
    """Start a background monitor that tracks and re-analyzes changes to a repo.

    Watches ``path`` on a daemon thread; every ``interval`` seconds it detects
    files created/modified/deleted (by you, the user, or any tool) and records the
    last ``capacity`` (default 16) changes into a FIFO diff database, re-analyzing
    changed files across the Go/Python worker pool. Idempotent: calling it again
    for the same path returns the already-running monitor. Read what changed with
    ``recent_changes`` / ``monitor_status``.

    Args:
        path: Repository directory to watch.
        interval: Seconds between scan cycles.
        capacity: FIFO depth -- how many consecutive changes are retained.
        out_dir: Artifact dir (default: ``<path>/.file-analyzer``).
        max_workers: Worker-pool ceiling for large change sets (~100-200).
        min_workers: Worker-pool floor for large change sets (~10-20).
        reanalyze: Re-run analyzers on changed files (else record changes only).
        change_log: Keep the durable append-only change log (default True). Set
            False for a FIFO-ring-only monitor with no durable archive.
        change_log_url: Optional remote SQL URL (postgresql://... / mysql://...) or
            SQLite path for the durable append-only change log (a superset of the
            FIFO ring that never deletes evicted changes). Defaults to a local
            SQLite file under ``<out_dir>/monitor/changes_log.db``.
        enable_agents: Run the soft MCP agent tier on every re-analyzed file
            (summary, quality/security findings, symbol docs). Off by default; a
            no-op unless an MCP provider is reachable.
        agents_include: Allow-list of provider names (only these are eligible).
        agents_exclude: Deny-list of provider names (applied after the allow-list).
        discover_agents: Resolve providers from desktop/CLI-configured MCP servers.
        agent_roster: Preferred provider name for the agent tier.
    """
    from src.monitor.control import start_monitor as _start

    source = Path(path).expanduser().resolve()
    if not source.is_dir():
        raise NotADirectoryError(f"source is not a directory: {source}")
    with _hushed():
        mon = _start(
            source,
            interval=interval,
            capacity=capacity,
            out_dir=out_dir,
            max_workers=max_workers,
            min_workers=min_workers,
            reanalyze=reanalyze,
            inline_threshold=0,  # never analyze inline in the server thread
            enable_change_log=change_log,
            change_log_url=change_log_url,
            enable_agents=enable_agents,
            agents_include=agents_include,
            agents_exclude=agents_exclude,
            discover_agents=discover_agents,
            agent_roster=agent_roster,
        )
        summary = mon.summary()
    summary["diff_database"] = str(mon.diff_db_path)
    summary["change_log"] = getattr(mon, "change_log_url", None) or str(
        mon.change_log_path
    )
    summary["agents"] = mon.enable_agents
    summary["started"] = True
    return summary


@mcp.tool()
def stop_monitor(path: str) -> Dict[str, Any]:
    """Stop the background monitor watching ``path`` (if any)."""
    from src.monitor.control import stop_monitor as _stop

    source = Path(path).expanduser().resolve()
    with _hushed():
        stopped = _stop(source)
    return {"path": str(source), "stopped": stopped}


@mcp.tool()
def monitor_status(
    path: Optional[str] = None, diff_db: Optional[str] = None
) -> Dict[str, Any]:
    """Report a monitor's status (running?, buffered changes, totals, last scan).

    Reads the diff database read-only, so it works whether the monitor runs in
    this server or as a separate ``python -m src`` process. Give either ``path``
    (the watched repo) or ``diff_db`` (the database path directly).
    """
    from src.monitor.control import read_status

    return read_status(root=path, diff_db_path=diff_db)


@mcp.tool()
def recent_changes(
    path: Optional[str] = None, diff_db: Optional[str] = None, limit: int = 16
) -> Dict[str, Any]:
    """Return the most recent changes the monitor recorded (newest first).

    Each entry is a created/modified/deleted event with the analyzer that claimed
    the file, byte/line deltas, a bounded unified-diff snippet (text files) and the
    re-analysis outcome. Reads the FIFO diff database read-only. Give either
    ``path`` (the watched repo) or ``diff_db`` (the database path directly).
    """
    from src.monitor.control import read_recent_changes

    return read_recent_changes(root=path, diff_db_path=diff_db, limit=limit)


@mcp.tool()
def scan_now(path: str) -> Dict[str, Any]:
    """Force one immediate scan cycle for a monitor already watching ``path``.

    Useful right after making edits, instead of waiting for the next interval.
    Requires that ``start_monitor`` was called for ``path`` in this server.
    """
    from src.monitor.control import get_monitor

    source = Path(path).expanduser().resolve()
    mon = get_monitor(source)
    if mon is None:
        raise RuntimeError(
            f"no monitor is running for {source}; call start_monitor first"
        )
    with _hushed():
        return mon.scan_once()


@mcp.tool()
def change_history(
    path: str,
    limit: int = 50,
    rel_path: Optional[str] = None,
    change_log_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Read the durable, continuous change log for a repo (newest first).

    Unlike ``recent_changes`` (the 16-deep FIFO ring), this is the permanent
    archive: every change ever recorded, so changes evicted from the ring still
    appear here. Backed by a local SQLite file by default, or a remote SQL server
    when ``change_log_url`` (postgresql://... / mysql://...) is given.

    Args:
        path: The watched repository directory.
        limit: Max rows to return.
        rel_path: If given, restrict to the change history of that one file.
        change_log_url: Remote SQL URL or SQLite path (defaults to the local file).
    """
    from src.monitor.control import read_change_log

    source = Path(path).expanduser().resolve()
    with _hushed():
        return read_change_log(
            source, url=change_log_url, limit=limit, rel_path=rel_path
        )


@mcp.tool()
def log_session(
    path: str,
    task_given: str,
    work_done: str,
    files_changed: Optional[List[str]] = None,
    improvements: str = "",
    user_sentiment: Optional[str] = None,
    next_prompt: Optional[str] = None,
    summary_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Record one session summary for a repo (task, files, work, sentiment, fixes).

    Stores a durable row an agent can refer back to at any time: the task the user
    gave, the files changed, what was done, the user's inferred sentiment
    (satisfied/dissatisfied/annoyed/neutral/confused -- from ``next_prompt`` if
    given, or ``user_sentiment`` to set it explicitly), and a short 3-5 sentence
    ``improvements`` note. Local SQLite by default; ``summary_url``
    (postgresql://... / mysql://...) redirects it to a remote SQL server.

    Args:
        path: The repository this session worked on.
        task_given: What the user asked for.
        work_done: What was actually done.
        files_changed: Paths the session touched.
        improvements: Short (3-5 sentence) note on what to do better next time.
        user_sentiment: Explicit sentiment override (skips the heuristic).
        next_prompt: The user's next message, classified into a sentiment.
        summary_url: Remote SQL URL or SQLite path (defaults to the local file).
    """
    from src.monitor.control import record_session

    source = Path(path).expanduser().resolve()
    with _hushed():
        return record_session(
            source,
            task_given=task_given,
            work_done=work_done,
            files_changed=files_changed,
            improvements=improvements,
            user_sentiment=user_sentiment,
            next_prompt=next_prompt,
            url=summary_url,
        )


@mcp.tool()
def assess_last_session(
    path: str,
    next_prompt: str,
    user_sentiment: Optional[str] = None,
    improvements: Optional[str] = None,
    summary_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Attach a sentiment to the most recent still-unassessed session for a repo.

    The user's reaction to a session is whatever they say next, so call this at the
    start of a new turn with the user's ``next_prompt``: it finds the latest pending
    session and classifies the prompt into satisfied/dissatisfied/annoyed/neutral/
    confused (or applies ``user_sentiment`` verbatim). Returns the updated row, or
    an empty result if there is no pending session.
    """
    from src.monitor.control import assess_last_session as _assess

    source = Path(path).expanduser().resolve()
    with _hushed():
        row = _assess(
            source,
            next_prompt=next_prompt,
            user_sentiment=user_sentiment,
            improvements=improvements,
            url=summary_url,
        )
    return row or {"assessed": False, "reason": "no pending session"}


@mcp.tool()
def recent_sessions(
    path: str, limit: int = 20, summary_url: Optional[str] = None
) -> Dict[str, Any]:
    """Return recent session summaries for a repo (newest first).

    Each row carries the task, files changed, work done, inferred user sentiment
    (with confidence + rationale) and the improvements note. Reads the local
    SQLite summary dump by default, or a remote SQL server via ``summary_url``.
    """
    from src.monitor.control import read_sessions

    source = Path(path).expanduser().resolve()
    with _hushed():
        return read_sessions(source, url=summary_url, limit=limit)


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

            compileall.compile_dir(str(_READERS_ROOT / "src"), quiet=1, optimize=0)
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
    argv = sys.argv[1:]
    # ``--version``: print the version and exit without standing up the server
    # (mirrors the src.main / python -m src CLIs). No fleet import needed.
    if "--version" in argv:
        print(f"file-analyzer {__version__}")
        return
    # ``python -m mcp_server --precompile`` / ``file-analyzer-mcp --precompile``:
    # do the warm-up synchronously and exit, without starting the server. Run this
    # once at install or MCP-registration time (Dockerfile, postinstall, CI) so the
    # first real server the agent launches is already warm.
    if "--precompile" in argv:
        warm_cache()
        return
    _start_warm_cache()
    mcp.run()


if __name__ == "__main__":
    main()
