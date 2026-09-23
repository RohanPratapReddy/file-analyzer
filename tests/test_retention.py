"""
Tests for the database server's time- and space-based retention
(``file_analyzer.server.retention``).

Everything runs against the real SQLite backend. Idleness is simulated by
backdating catalog timestamps, and backup sets are laid down as
``<backup_dir>/<key>/<YYYYmmdd-HHMMSS>/`` directories so their creation time is
exact -- no sleeping.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from file_analyzer.server import (  # noqa: E402
    DatabaseServer,
    RetentionPolicy,
    ServerClient,
    parse_size,
)
from file_analyzer.server.retention import DAY  # noqa: E402


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _sample_db(path: Path, n: int = 50) -> Path:
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE t (name TEXT, value INTEGER)")
        conn.executemany(
            "INSERT INTO t VALUES (?, ?)", [(f"n{i}", i) for i in range(n)]
        )
        conn.commit()
    finally:
        conn.close()
    return path


def _server(tmp_path: Path, **kw) -> DatabaseServer:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    kw.setdefault("backup_interval", 0)
    kw.setdefault("retention_interval", 0)
    return DatabaseServer(
        repo,
        data_dir=tmp_path / "data",
        catalog_dir=tmp_path / "catalog",
        **kw,
    )


def _host(srv: DatabaseServer, tmp_path: Path, name: str) -> str:
    src = _sample_db(tmp_path / f"{name}-src.db")
    return srv.host_database(src, name)["storage_key"]


def _fake_set(
    srv: DatabaseServer, key: str, when: float, size: int = 1000, complete=True
) -> Path:
    label = time.strftime("%Y%m%d-%H%M%S", time.gmtime(when))
    d = srv.backups.backup_dir / key / label
    d.mkdir(parents=True)
    (d / "part-0000.gz").write_bytes(b"x" * size)
    if complete:
        (d / "manifest.json").write_text(json.dumps({"timestamp": label}))
    return d


def _set_active_at(srv: DatabaseServer, key: str, when: float) -> None:
    """Backdate a hosted database's last host/read time in the catalog."""
    conn = sqlite3.connect(srv.catalog.target)
    try:
        conn.execute(
            "UPDATE databases SET updated_at = ? WHERE storage_key = ?", (when, key)
        )
        conn.execute("DELETE FROM database_access WHERE storage_key = ?", (key,))
        conn.commit()
    finally:
        conn.close()


def _keys(srv: DatabaseServer):
    return sorted(d["storage_key"] for d in srv.databases())


# --------------------------------------------------------------------------- #
# parse_size / policy
# --------------------------------------------------------------------------- #
def test_parse_size_units():
    assert parse_size("512") == 512
    assert parse_size("1K") == 1024
    assert parse_size("512MB") == 512 * 1024**2
    assert parse_size("20g") == 20 * 1024**3
    assert parse_size(2048) == 2048
    assert parse_size(None) is None
    assert parse_size("0") is None
    with pytest.raises(ValueError):
        parse_size("12 parsecs")


def test_policy_zero_disables_limits():
    pol = RetentionPolicy(max_age=0, backup_max_age=-1, max_total_bytes=0)
    assert pol.max_age is None
    assert pol.backup_max_age is None
    assert pol.max_total_bytes is None


# --------------------------------------------------------------------------- #
# Time-based retention
# --------------------------------------------------------------------------- #
def test_idle_database_is_evicted_with_its_backups(tmp_path):
    srv = _server(tmp_path, retention_max_age=30 * DAY)
    old = _host(srv, tmp_path, "old")
    fresh = _host(srv, tmp_path, "fresh")
    now = time.time()
    _set_active_at(srv, old, now - 40 * DAY)
    _fake_set(srv, old, now - 1 * DAY)
    old_file = Path(srv.catalog.get_database(old)["location"])

    report = srv.enforce_retention()
    assert [e["storage_key"] for e in report["evicted"]] == [old]
    assert report["evicted"][0]["reason"] == "idle"
    assert _keys(srv) == [fresh]
    assert not old_file.exists()
    assert not (srv.backups.backup_dir / old).exists()
    assert report["freed_bytes"] > 0


def test_read_access_keeps_database_alive(tmp_path):
    srv = _server(tmp_path, retention_max_age=30 * DAY)
    key = _host(srv, tmp_path, "used")
    _set_active_at(srv, key, time.time() - 40 * DAY)
    # A query records an access, which counts as activity.
    srv.dbhost.query(key, "SELECT COUNT(*) FROM t")
    report = srv.enforce_retention()
    assert report["evicted"] == []
    assert _keys(srv) == [key]


def test_dry_run_changes_nothing(tmp_path):
    srv = _server(tmp_path, retention_max_age=30 * DAY)
    key = _host(srv, tmp_path, "old")
    _set_active_at(srv, key, time.time() - 40 * DAY)
    report = srv.enforce_retention(dry_run=True)
    assert report["dry_run"] is True
    assert [e["storage_key"] for e in report["evicted"]] == [key]
    assert _keys(srv) == [key]


def test_old_backups_pruned_but_newest_kept(tmp_path):
    srv = _server(tmp_path, backup_max_age=7 * DAY)
    key = _host(srv, tmp_path, "db")
    now = time.time()
    oldest = _fake_set(srv, key, now - 20 * DAY)
    older = _fake_set(srv, key, now - 10 * DAY)
    report = srv.enforce_retention()
    # Both sets are past 7 days, but the newer one is the database's only
    # remaining restore point and survives.
    assert [s["timestamp"] for s in report["pruned_backups"]] == [oldest.name]
    assert not oldest.exists()
    assert older.exists()

    recent = _fake_set(srv, key, now - 1 * DAY)
    srv.enforce_retention()
    assert not older.exists()
    assert recent.exists()


def test_orphan_backups_age_out_completely(tmp_path):
    srv = _server(tmp_path, backup_max_age=7 * DAY)
    now = time.time()
    gone = "proj-tok-vanished"
    a = _fake_set(srv, gone, now - 20 * DAY)
    b = _fake_set(srv, gone, now - 9 * DAY)
    srv.enforce_retention()
    assert not a.exists() and not b.exists()


def test_debris_is_cleaned(tmp_path):
    srv = _server(tmp_path)
    key = _host(srv, tmp_path, "db")
    now = time.time()
    partial = srv.dbhost.data_dir / ".half.db.incoming"
    partial.write_bytes(b"x" * 100)
    os.utime(partial, (now - 2 * 3600, now - 2 * 3600))
    crashed = _fake_set(srv, key, now - 2 * 3600, complete=False)
    young = srv.dbhost.data_dir / ".young.db.incoming"
    young.write_bytes(b"y")

    report = srv.enforce_retention()
    assert not partial.exists()
    assert not crashed.exists()
    assert young.exists()  # may still be an upload in progress
    assert [s["reason"] for s in report["stray_removed"]] == ["partial-upload"]


def test_sqlite_remove_only_deletes_its_own_file(tmp_path):
    srv = _server(tmp_path)
    key = _host(srv, tmp_path, "db")
    neighbour = srv.dbhost.data_dir / "unrelated.db"
    neighbour.write_bytes(b"keep me")
    rec = srv.catalog.get_database(key)
    assert Path(rec["location"]).name == f"{key}.db"

    srv.dbhost.remove(key)
    assert srv.catalog.get_database(key) is None
    assert not Path(rec["location"]).exists()
    assert neighbour.read_bytes() == b"keep me"


# --------------------------------------------------------------------------- #
# Space-based retention
# --------------------------------------------------------------------------- #
def test_space_budget_prunes_backups_before_databases(tmp_path):
    srv = _server(tmp_path, retention_max_age=None, backup_max_age=None)
    key = _host(srv, tmp_path, "db")
    now = time.time()
    s1 = _fake_set(srv, key, now - 3 * DAY, size=50_000)
    s2 = _fake_set(srv, key, now - 2 * DAY, size=50_000)
    s3 = _fake_set(srv, key, now - 1 * DAY, size=50_000)
    hosted = srv.retention.usage()["hosted_bytes"]
    # Room for the database plus about one backup set.
    srv.retention.policy.max_total_bytes = hosted + 60_000

    report = srv.enforce_retention()
    assert _keys(srv) == [key]
    assert not s1.exists() and not s2.exists()
    assert s3.exists()
    assert {s["reason"] for s in report["pruned_backups"]} == {"space"}
    assert report["over_budget"] is False


def test_space_budget_evicts_least_recently_active(tmp_path):
    srv = _server(tmp_path, retention_max_age=None, backup_max_age=None)
    now = time.time()
    a = _host(srv, tmp_path, "a")
    b = _host(srv, tmp_path, "b")
    c = _host(srv, tmp_path, "c")
    _set_active_at(srv, a, now - 3 * DAY)
    _set_active_at(srv, b, now - 2 * DAY)
    _set_active_at(srv, c, now - 1 * DAY)
    per_db = srv.retention.usage()["hosted_bytes"] // 3
    srv.retention.policy.max_total_bytes = per_db * 2

    report = srv.enforce_retention()
    assert [e["storage_key"] for e in report["evicted"]] == [a]
    assert report["evicted"][0]["reason"] == "space"
    assert _keys(srv) == sorted([b, c])
    assert report["over_budget"] is False


def test_space_budget_never_evicts_most_recent(tmp_path):
    srv = _server(tmp_path, retention_max_age=None, backup_max_age=None)
    key = _host(srv, tmp_path, "only")
    srv.retention.policy.max_total_bytes = 1
    report = srv.enforce_retention()
    assert _keys(srv) == [key]
    assert report["over_budget"] is True


# --------------------------------------------------------------------------- #
# Server wiring: HTTP, detached argv, CLI
# --------------------------------------------------------------------------- #
def test_http_retention_routes(tmp_path):
    srv = _server(tmp_path, retention_max_age=30 * DAY)
    key = _host(srv, tmp_path, "old")
    _set_active_at(srv, key, time.time() - 40 * DAY)
    thread = threading.Thread(target=lambda: srv.serve(contained=False), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not srv.endpoint_file.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        client = ServerClient(srv.url, srv.token)

        status = client.retention()
        assert status["policy"]["max_age"] == 30 * DAY
        assert status["usage"]["databases"] == 1

        preview = client.enforce_retention(dry_run=True)
        assert [e["storage_key"] for e in preview["evicted"]] == [key]
        assert [d["storage_key"] for d in client.databases()] == [key]

        done = client.enforce_retention()
        assert [e["storage_key"] for e in done["evicted"]] == [key]
        assert client.databases() == []
        assert client.retention()["last_run"]["evicted"] == 1
    finally:
        if srv._httpd is not None:
            srv._httpd.shutdown()
        thread.join(timeout=10)


def test_detached_argv_carries_policy(tmp_path):
    srv = _server(
        tmp_path,
        retention_interval=120,
        retention_max_age=10 * DAY,
        backup_max_age=None,
        retention_max_bytes=parse_size("1G"),
    )
    argv = srv._retention_argv()
    flags = dict(zip(argv[::2], argv[1::2]))
    assert float(flags["--retention-interval"]) == 120
    assert float(flags["--retention-days"]) == 10
    assert float(flags["--backup-retention-days"]) == 0
    assert parse_size(flags["--max-total-size"]) == 1024**3


def test_cli_parses_retention_flags(tmp_path):
    from file_analyzer.server.__main__ import _build_server, build_parser

    args = build_parser().parse_args(
        [
            "run",
            str(tmp_path),
            "--catalog-dir",
            str(tmp_path / "catalog"),
            "--retention-days",
            "2",
            "--backup-retention-days",
            "0",
            "--max-total-size",
            "5G",
            "--retention-interval",
            "0",
        ]
    )
    srv = _build_server(args)
    pol = srv.retention.policy
    assert pol.max_age == 2 * DAY
    assert pol.backup_max_age is None
    assert pol.max_total_bytes == 5 * 1024**3
    assert srv.retention_interval == 0
