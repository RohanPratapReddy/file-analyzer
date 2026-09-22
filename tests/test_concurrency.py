"""
Tests for the Go-backed worker concurrency added to all three wheels.

Every genuinely-concurrent workload in the platform has two interchangeable
execution paths: a Go worker pool (the fast path, built on demand with
``go build`` and skipped when the toolchain is absent) and a pure-Python
concurrent fallback. These tests pin ``use_go=False`` so they deterministically
exercise the **fallback** -- which is exactly what runs in the CI container
(python:3.10-slim has no Go). The Go path is a drop-in accelerator that produces
identical results; it is compile-checked separately.

Covered, one honest concurrent workload per wheel:

* **engine** -- ``file_analyzer.core.inject_pool``: the concurrent SQLite injector
  that loads the generated per-table ``INSERT`` blocks into the ``.db``;
* **client** -- ``file_analyzer.client.native_reader``: the concurrent, strictly
  read-only bulk view reader (and its wiring through ``Database.read_views``);
* **server** -- ``file_analyzer.server.backup``: concurrent per-database backups
  with per-key locking + a restore round-trip.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

# Make ``import file_analyzer`` resolve when pytest is run from the repo root
# (harmless when the wheels are installed; site-packages wins either way).
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _structure_db(path: Path) -> None:
    """A tiny schema with two views (for the reader) and one table (for injects)."""
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT, n INTEGER)")
        conn.execute("CREATE VIEW v_items AS SELECT id, name FROM items")
        conn.execute(
            "CREATE VIEW v_counts AS SELECT n, COUNT(*) c FROM items GROUP BY n"
        )
        conn.commit()
    finally:
        conn.close()


def _insert_blocks(n_blocks: int, per_block: int):
    """``[(label, sql_text), ...]`` of independent INSERT blocks + the total rows."""
    blocks = []
    k = 0
    for b in range(n_blocks):
        stmts = []
        for _ in range(per_block):
            stmts.append(f"INSERT INTO items(name, n) VALUES('item{k}', {k % 5});")
            k += 1
        blocks.append((f"block{b}", "\n".join(stmts)))
    return blocks, k


# --------------------------------------------------------------------------- #
# Engine: concurrent SQLite injector
# --------------------------------------------------------------------------- #
def test_engine_injector_python_fallback_loads_all_blocks(tmp_path):
    from file_analyzer.core.inject_pool import inject_blocks

    db = tmp_path / "repo.db"
    _structure_db(db)
    blocks, total = _insert_blocks(n_blocks=8, per_block=25)

    report = inject_blocks(str(db), blocks, workers=6, use_go=False)

    assert report["engine"] == "python"
    assert report["failures"] == []
    assert report["blocks"] == 8
    conn = sqlite3.connect(str(db))
    try:
        count = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    finally:
        conn.close()
    # Exactly the rows we staged -- no drops, and crucially no double-inserts from
    # the two paths both running.
    assert count == total == 200


def test_engine_injector_reports_bad_block_as_failure(tmp_path):
    from file_analyzer.core.inject_pool import inject_blocks

    db = tmp_path / "repo.db"
    _structure_db(db)
    good, _ = _insert_blocks(n_blocks=2, per_block=5)
    bad = [("broken", "INSERT INTO no_such_table(x) VALUES(1);")]

    report = inject_blocks(str(db), good + bad, workers=4, use_go=False)

    assert report["engine"] == "python"
    labels = [label for label, _ in report["failures"]]
    assert "broken" in labels
    assert len(report["failures"]) == 1


def test_engine_injector_empty_is_noop(tmp_path):
    from file_analyzer.core.inject_pool import inject_blocks

    db = tmp_path / "repo.db"
    _structure_db(db)
    report = inject_blocks(str(db), [], use_go=False)
    assert report["engine"] == "none"
    assert report["failures"] == []
    assert report["blocks"] == 0


# --------------------------------------------------------------------------- #
# Client: concurrent, read-only bulk view reader
# --------------------------------------------------------------------------- #
def _seed_views(tmp_path) -> Path:
    from file_analyzer.core.inject_pool import inject_blocks_python

    db = tmp_path / "views.db"
    _structure_db(db)
    blocks, _ = _insert_blocks(n_blocks=4, per_block=30)
    failures = inject_blocks_python(str(db), blocks, workers=4)
    assert failures == []
    return db


def test_client_reader_python_is_concurrent_and_complete(tmp_path):
    from file_analyzer.client.native_reader import read_views_python

    db = _seed_views(tmp_path)
    result = read_views_python(str(db), ["v_items", "v_counts"], limit=10, workers=4)

    assert result["engine"] == "python"
    assert set(result["views"]) == {"v_items", "v_counts"}
    assert result["views"]["v_items"]["columns"] == ["id", "name"]
    assert len(result["views"]["v_items"]["rows"]) == 10  # honoured the limit


def test_client_reader_is_strictly_readonly(tmp_path):
    from file_analyzer.client.native_reader import _read_python

    db = _seed_views(tmp_path)
    before = (
        sqlite3.connect(str(db)).execute("SELECT COUNT(*) FROM items").fetchone()[0]
    )
    _read_python(str(db), ["v_items"], limit=5)
    after = sqlite3.connect(str(db)).execute("SELECT COUNT(*) FROM items").fetchone()[0]
    assert before == after  # the reader never mutates the database


def test_client_database_read_views_python_engine(tmp_path):
    # The public Database API must route engine="python" to the concurrent reader.
    from file_analyzer.client.database import open_database

    db = _seed_views(tmp_path)
    with open_database(str(db)) as handle:
        bulk = handle.read_views(engine="python")
    assert bulk["engine"] == "python"
    assert {"v_items", "v_counts"} <= set(bulk["views"])


# --------------------------------------------------------------------------- #
# Server: concurrent per-database backups + restore round-trip
# --------------------------------------------------------------------------- #
def _host_with_dbs(tmp_path, n=5):
    from file_analyzer.server.catalog import SessionCatalog
    from file_analyzer.server.dbhost import DatabaseHost

    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("hello")  # stable fingerprint
    catalog = SessionCatalog(tmp_path / "catalog")
    session = catalog.get_or_create_session(root)
    host = DatabaseHost(
        root=str(root),
        token=session["token"],
        data_dir=tmp_path / "data",
        catalog=catalog,
    )
    for i in range(n):
        src = tmp_path / f"src_{i}.db"
        conn = sqlite3.connect(str(src))
        conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
        conn.executemany(
            "INSERT INTO t(v) VALUES(?)", [(f"r{j}",) for j in range(100 + i)]
        )
        conn.commit()
        conn.close()
        host.host(src, f"db{i}")
    return host


def test_server_backup_all_python_fallback(tmp_path):
    from file_analyzer.server.backup import BackupManager

    host = _host_with_dbs(tmp_path, n=5)
    manager = BackupManager(host, backup_dir=tmp_path / "backups", keep=5)

    results = manager.backup_all(use_go=False)

    assert len(results) == 5
    assert all("error" not in r for r in results), results
    # Every hosted key got its own backup set.
    keys = {h.storage_key for h in host.list()}
    assert {r["storage_key"] for r in results} == keys


def test_server_backup_restore_round_trip(tmp_path):
    from file_analyzer.server.backup import BackupManager

    host = _host_with_dbs(tmp_path, n=3)
    manager = BackupManager(host, backup_dir=tmp_path / "backups", keep=5)
    manager.backup_all(use_go=False)

    key = host.list()[0].storage_key
    sets = manager.list_backups(key)
    assert sets, "no backup listed for key"
    timestamp = sets[-1]["timestamp"]
    dest = tmp_path / "restored.db"
    manager.restore(key, timestamp, dest)

    conn = sqlite3.connect(str(dest))
    try:
        count = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
    finally:
        conn.close()
    assert count == 100  # db0 was seeded with 100 rows


def test_server_per_key_locks_are_distinct(tmp_path):
    from file_analyzer.server.backup import BackupManager

    host = _host_with_dbs(tmp_path, n=3)
    manager = BackupManager(host, backup_dir=tmp_path / "backups")
    keys = [h.storage_key for h in host.list()]
    lock_paths = {manager._key_lock_path(k) for k in keys}
    # Distinct keys -> distinct lock files (so they never serialize on one lock).
    assert len(lock_paths) == len(keys)
    for k in keys:
        assert manager._key_lock_path(k).parent.name == k


def test_server_backup_all_empty_host(tmp_path):
    from file_analyzer.server.backup import BackupManager
    from file_analyzer.server.catalog import SessionCatalog
    from file_analyzer.server.dbhost import DatabaseHost

    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("x")
    catalog = SessionCatalog(tmp_path / "catalog")
    session = catalog.get_or_create_session(root)
    host = DatabaseHost(
        root=str(root),
        token=session["token"],
        data_dir=tmp_path / "data",
        catalog=catalog,
    )
    manager = BackupManager(host, backup_dir=tmp_path / "backups")
    assert manager.backup_all(use_go=False) == []


def test_server_job_spec_round_trips(tmp_path):
    from file_analyzer.server.backup import BackupManager

    host = _host_with_dbs(tmp_path, n=2)
    manager = BackupManager(host, backup_dir=tmp_path / "backups", keep=3)
    spec = manager.job_spec()
    rebuilt = BackupManager.from_job_spec(spec)

    assert rebuilt.keep == manager.keep
    assert rebuilt.part_bytes == manager.part_bytes
    assert rebuilt.host.token == host.token
    assert str(rebuilt.backup_dir) == str(manager.backup_dir)
    # The rebuilt manager sees the same hosted databases (shared catalog).
    assert {h.storage_key for h in rebuilt.host.list()} == {
        h.storage_key for h in host.list()
    }
