"""
Tests for the high-level object-oriented SDK surface (``file_analyzer.sdk``).

These run on a bare interpreter (pure stdlib + the pure-stdlib analyzer core), so
they match the CI runner. They pin the load-bearing SDK contracts against the REAL
machinery -- there are no stubs here:

* the SDK classes are importable from the package top level and listed in __all__;
* ``FileAnalyzerClient.analyze`` runs the real pipeline end-to-end and returns an
  ``AnalysisResult`` whose ``.open()`` gives a working read-only database handle;
* ``FileAnalyzerDatabase`` enforces the single read-only SELECT/WITH contract and
  reads the installed analysis views;
* ``FileAnalyzerClient.run_component`` drives the real component code path;
* ``FileAnalyzerAgent`` builds a real provider registry and picks honestly;
* ``FileAnalyzerMonitor`` wraps the real monitor control layer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make ``import file_analyzer`` resolve when pytest is run from the repo root.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import file_analyzer.engine as fae  # noqa: E402  (the engine wheel's public API)
from file_analyzer.client.database import _is_readonly_select  # noqa: E402
from file_analyzer.engine import (  # noqa: E402
    AnalysisResult,
    FileAnalyzerAgent,
    FileAnalyzerClient,
    FileAnalyzerDatabase,
    FileAnalyzerMCPServer,
    FileAnalyzerMonitor,
    open_database,
)
from file_analyzer.server import FileAnalyzerServer  # noqa: E402  (server wheel)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _tiny_repo(tmp_path: Path) -> Path:
    """A minimal source tree the engine can analyze without git."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text(
        "import os\n\n\ndef greet(name):\n    return f'hi {name}'\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# demo\n\nA tiny repo.\n", encoding="utf-8")
    return tmp_path


def _light_client() -> FileAnalyzerClient:
    return FileAnalyzerClient()


_LIGHT = dict(
    no_git=True,
    enable_document_databases=False,
    enable_archives=False,
    enable_binary=False,
    enable_conversions=False,
    enable_unified_database=False,
)


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
def test_sdk_classes_are_exported():
    # The engine wheel's public API (file_analyzer.engine) carries the analysis
    # SDK surface. FileAnalyzerServer is NOT here -- it ships in the server wheel.
    for name in (
        "FileAnalyzerClient",
        "FileAnalyzerMCPServer",
        "FileAnalyzerAgent",
        "FileAnalyzerMonitor",
        "FileAnalyzerDatabase",
        "AnalysisResult",
        "analyze",
        "open_database",
    ):
        assert name in fae.__all__, f"{name} missing from engine __all__"
        assert hasattr(fae, name), f"{name} not importable"
    assert "FileAnalyzerServer" not in fae.__all__


def test_hosting_server_lives_in_server_wheel():
    # The database-hosting server is a separate wheel (file_analyzer.server).
    import file_analyzer.server as fas

    assert "FileAnalyzerServer" in fas.__all__
    assert hasattr(fas, "FileAnalyzerServer")


def test_client_version_matches_package():
    assert FileAnalyzerClient().version == fae.__version__


# --------------------------------------------------------------------------- #
# Read-only query guard
# --------------------------------------------------------------------------- #
def test_readonly_select_guard():
    assert _is_readonly_select("SELECT 1")
    assert _is_readonly_select("  with x as (select 1) select * from x  ")
    assert not _is_readonly_select("DELETE FROM t")
    assert not _is_readonly_select("SELECT 1; DROP TABLE t")  # multi-statement
    assert not _is_readonly_select("")


# --------------------------------------------------------------------------- #
# End-to-end pipeline via the client
# --------------------------------------------------------------------------- #
def test_analyze_end_to_end(tmp_path):
    src = _tiny_repo(tmp_path / "repo")
    out = tmp_path / "artifacts"

    result = _light_client().analyze(src, out_dir=out, **_LIGHT)

    assert isinstance(result, AnalysisResult)
    assert result.file_count >= 2
    db_path = Path(result.database)
    assert db_path.is_file()
    assert Path(result.sql_dump).is_file()
    # dict passthrough works
    assert result["file_count"] == result.file_count
    assert "repository_root" in dict(result)

    # The result opens a live, working read-only database handle.
    db = result.open()
    assert isinstance(db, FileAnalyzerDatabase)
    views = db.list_views()
    assert isinstance(views, list)
    tables = db.tables()
    assert tables, "expected at least one base table"

    # Every installed view is readable and read_view returns columns.
    if views:
        one = db.read_view(views[0])
        assert isinstance(one["columns"], list)
        bulk = db.read_views(engine="python")
        assert bulk["engine"] == "python"
        assert set(bulk["views"]) == set(views)


def test_module_level_analyze_helper(tmp_path):
    src = _tiny_repo(tmp_path / "repo")
    out = tmp_path / "artifacts"
    result = fae.analyze(src, out_dir=out, **_LIGHT)
    assert isinstance(result, AnalysisResult)
    assert Path(result.database).is_file()


def test_database_query_contract(tmp_path):
    src = _tiny_repo(tmp_path / "repo")
    out = tmp_path / "artifacts"
    result = _light_client().analyze(src, out_dir=out, **_LIGHT)
    db = _light_client().open(result.database)

    got = db.query("SELECT name FROM sqlite_master WHERE type='table'", limit=5)
    assert got["columns"] == ["name"]
    assert got["row_count"] >= 1

    with pytest.raises(ValueError):
        db.query("DELETE FROM sqlite_master")
    with pytest.raises(ValueError):
        db.query("SELECT 1; SELECT 2")


def test_database_missing_file_raises(tmp_path):
    db = FileAnalyzerDatabase(tmp_path / "nope.db")
    with pytest.raises(FileNotFoundError):
        db.query("SELECT 1")


# --------------------------------------------------------------------------- #
# Component mode
# --------------------------------------------------------------------------- #
def test_run_component_census(tmp_path):
    src = _tiny_repo(tmp_path / "repo")
    out = tmp_path / "component-out"
    res = _light_client().run_component("census", src, out_dir=out, no_git=True)

    assert res["summary"]["component"] == "RepositoryAnalyzer"
    assert res["tables"] is not None
    assert "files" in res["tables"]
    assert Path(res["emit_path"]).is_file()


def test_list_components():
    comps = _light_client().list_components()
    assert "planes" in comps and "special" in comps
    assert "census" in comps["special"]


# --------------------------------------------------------------------------- #
# Agent facade -- real registry, no network required
# --------------------------------------------------------------------------- #
def test_agent_registry_is_real():
    agent = FileAnalyzerClient().agent()
    providers = agent.providers()
    assert isinstance(providers, list) and providers, "expected built-in specs"
    probes = agent.probe()
    assert isinstance(probes, list) and len(probes) == len(providers)
    # available() is environment-dependent but must be a subset of providers.
    assert set(agent.available()) <= set(providers)


def test_agent_include_exclude_filter():
    agent = FileAnalyzerClient().agent()
    all_names = agent.providers()
    if len(all_names) >= 2:
        keep = all_names[0]
        filtered = FileAnalyzerClient().agent(include=[keep])
        assert filtered.providers() == [keep]


def test_agent_pick_raises_when_none_reachable(monkeypatch):
    agent = FileAnalyzerAgent()
    monkeypatch.setattr(agent, "available", lambda: [])
    from file_analyzer.document.agent_mcp import ProviderUnavailable

    with pytest.raises(ProviderUnavailable):
        agent._pick()


# --------------------------------------------------------------------------- #
# Monitor facade -- real control layer
# --------------------------------------------------------------------------- #
def test_monitor_wraps_control_layer(tmp_path):
    mon = FileAnalyzerClient().monitor(tmp_path)
    assert isinstance(mon, FileAnalyzerMonitor)
    assert mon.running is False
    # scan_now before start is an honest error, not a silent no-op.
    with pytest.raises(RuntimeError):
        mon.scan_now()


def test_monitor_start_scan_stop(tmp_path):
    src = _tiny_repo(tmp_path / "repo")
    mon = FileAnalyzerClient().monitor(src, reanalyze=False)
    mon.start()
    try:
        assert mon.running is True
        report = mon.scan_now()
        assert isinstance(report, dict)
        status = mon.status()
        assert Path(status["database"]).is_file()
    finally:
        assert mon.stop() is True
    assert mon.running is False


# --------------------------------------------------------------------------- #
# MCP server facade -- shape without requiring the optional mcp package
# --------------------------------------------------------------------------- #
def test_mcp_server_tool_names():
    server = FileAnalyzerMCPServer()
    tools = server.tools()
    for expected in ("analyze_repository", "query", "list_views", "run_component"):
        assert expected in tools
    with pytest.raises(ValueError):
        server.call("not_a_tool")


def test_mcp_server_call_query_in_process(tmp_path):
    """If mcp is installed, calling a tool in-process runs the real function."""
    pytest.importorskip("mcp")
    src = _tiny_repo(tmp_path / "repo")
    out = tmp_path / "artifacts"
    result = _light_client().analyze(src, out_dir=out, **_LIGHT)

    server = FileAnalyzerMCPServer()
    got = server.call(
        "query",
        sql="SELECT name FROM sqlite_master WHERE type='table' LIMIT 1",
        db_path=result.database,
    )
    assert isinstance(got, dict)


# --------------------------------------------------------------------------- #
# Hosting server facade -- the new FileAnalyzerServer wraps DatabaseServer
# --------------------------------------------------------------------------- #
def test_hosting_server_facade_shape():
    server = FileAnalyzerServer()
    # Lazy DatabaseServer construction must not require the mcp package and must
    # expose the hosting surface, not the MCP tool surface.
    assert not hasattr(server, "tools")
    for method in ("start", "serve", "stop", "status", "host_database", "connect"):
        assert callable(getattr(server, method))
    for method in ("is_running", "wait_ready"):
        assert callable(getattr(server, method))
    assert server.version == fae.__version__


# --------------------------------------------------------------------------- #
# Database utility helpers -- dict rows, streaming, counting, DDL, export
# --------------------------------------------------------------------------- #
def _analyzed_db(tmp_path) -> FileAnalyzerDatabase:
    src = _tiny_repo(tmp_path / "repo")
    out = tmp_path / "artifacts"
    result = _light_client().analyze(src, out_dir=out, **_LIGHT)
    return open_database(result.database)


def test_open_database_helper(tmp_path):
    db = _analyzed_db(tmp_path)
    assert isinstance(db, FileAnalyzerDatabase)
    assert db.exists() is True
    assert db.size_bytes > 0
    missing = open_database(tmp_path / "nope.db")
    assert missing.exists() is False
    assert missing.size_bytes == 0


def test_query_dicts_one_and_scalar(tmp_path):
    db = _analyzed_db(tmp_path)
    rows = db.query_dicts(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", limit=5
    )
    assert isinstance(rows, list) and rows
    assert all(isinstance(r, dict) and "name" in r for r in rows)

    one = db.query_one("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
    assert isinstance(one, dict) and "name" in one

    n = db.scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
    assert isinstance(n, int) and n >= 1
    assert db.query_one("SELECT 1 WHERE 0=1") is None
    assert db.scalar("SELECT 1 WHERE 0=1", default=-1) == -1

    # The read-only guard applies to the dict helpers too.
    with pytest.raises(ValueError):
        db.query_dicts("DELETE FROM files")
    with pytest.raises(ValueError):
        db.scalar("SELECT 1; SELECT 2")


def test_iter_rows_streams_every_row(tmp_path):
    db = _analyzed_db(tmp_path)
    tables = db.tables()
    assert tables
    target = "files" if "files" in tables else tables[0]

    total = db.count(target)
    streamed = list(db.iter_rows(f'SELECT * FROM "{target}"', batch_size=1))
    assert len(streamed) == total
    if streamed:
        assert isinstance(streamed[0], dict)

    with pytest.raises(ValueError):
        list(db.iter_rows("DELETE FROM files"))
    with pytest.raises(ValueError):
        list(db.iter_rows("SELECT 1", batch_size=0))


def test_count_and_table_counts(tmp_path):
    db = _analyzed_db(tmp_path)
    counts = db.table_counts()
    assert isinstance(counts, dict) and counts
    for name, n in counts.items():
        assert n == db.count(name)
    # Unknown identifiers are rejected, not interpolated.
    with pytest.raises(ValueError):
        db.count("no_such_table")


def test_sql_of_returns_ddl(tmp_path):
    db = _analyzed_db(tmp_path)
    name = db.tables()[0]
    ddl = db.sql_of(name)
    assert isinstance(ddl, str) and "CREATE" in ddl.upper()
    with pytest.raises(ValueError):
        db.sql_of("definitely_not_here")


def test_export_csv_json_jsonl(tmp_path):
    import csv as _csv
    import json as _json

    db = _analyzed_db(tmp_path)
    name = db.tables()[0]
    sql = f'SELECT * FROM "{name}"'
    expected = db.count(name)

    csv_path = tmp_path / "out.csv"
    n_csv = db.export(sql, csv_path, fmt="csv")
    assert n_csv == expected
    with csv_path.open(encoding="utf-8", newline="") as fh:
        assert len(list(_csv.DictReader(fh))) == expected

    json_path = tmp_path / "out.json"
    n_json = db.export(sql, json_path, fmt="json")
    assert n_json == expected
    assert len(_json.loads(json_path.read_text(encoding="utf-8"))) == expected

    jsonl_path = tmp_path / "out.jsonl"
    n_jsonl = db.export(sql, jsonl_path, fmt="jsonl")
    assert n_jsonl == expected
    lines = [ln for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln]
    assert len(lines) == expected

    with pytest.raises(ValueError):
        db.export(sql, tmp_path / "x.txt", fmt="parquet")


# --------------------------------------------------------------------------- #
# AnalysisResult helpers
# --------------------------------------------------------------------------- #
def test_result_save_and_database_path(tmp_path):
    src = _tiny_repo(tmp_path / "repo")
    out = tmp_path / "artifacts"
    result = _light_client().analyze(src, out_dir=out, **_LIGHT)

    assert isinstance(result.database_path, Path)
    assert result.database_path.is_file()

    dest = tmp_path / "summary.json"
    written = result.save(dest)
    assert written == dest and dest.is_file()
    import json as _json

    loaded = _json.loads(dest.read_text(encoding="utf-8"))
    assert loaded["file_count"] == result.file_count


# --------------------------------------------------------------------------- #
# Client environment / policy / batch helpers
# --------------------------------------------------------------------------- #
def test_client_environment_probe():
    env = _light_client().environment()
    assert isinstance(env, dict)
    for key in ("platform", "virtualized", "override", "signals"):
        assert key in env
    assert isinstance(env["virtualized"], bool)


def test_client_acceptable_use_banner():
    banner = _light_client().acceptable_use()
    assert isinstance(banner, str) and banner.strip()


def test_analyze_many(tmp_path):
    a = _tiny_repo(tmp_path / "a")
    b = _tiny_repo(tmp_path / "b")
    out = tmp_path / "multi"
    results = _light_client().analyze_many([a, b], out_dir=out, **_LIGHT)
    assert len(results) == 2
    dbs = {Path(r.database).resolve() for r in results}
    assert len(dbs) == 2, "each repo must produce a distinct database"
    for r in results:
        assert isinstance(r, AnalysisResult)
        assert Path(r.database).is_file()
