"""
Tests for the hosting server's self-healing maintenance
(``file_analyzer.server.autopilot`` + ``file_analyzer.server.supervisor``).

Everything runs against the real machinery -- real SQLite files, real backup
sets, real catalog, real detached processes -- and damage is inflicted the way
it happens in practice: flipped bytes, truncation, deleted files, a clobbered
catalog, a lost catalog row, a corrupted backup part, a lost Reed-Solomon
shard, a killed or frozen server process.
"""

from __future__ import annotations

import json
import os
import signal
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
    Autopilot,
    AutopilotPolicy,
    DatabaseServer,
    FileAnalyzerServer,
    ServerClient,
    ServerError,
    ServerSupervisor,
    SnapshotIntegrityError,
)
from file_analyzer.server.autopilot import (  # noqa: E402
    CORRUPT,
    DRIFTED,
    MISSING,
    PROBLEM_STATUSES,
    sqlite_header_problems,
    sqlite_integrity,
)
from file_analyzer.server.locking import FileLock  # noqa: E402

N_ROWS = 3000
OLD = time.time() - 10 * 86400  # an mtime far past every debris/grace age


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _sample_db(path: Path, n: int = N_ROWS) -> Path:
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE t (name TEXT, value INTEGER)")
        conn.executemany(
            "INSERT INTO t VALUES (?, ?)", [(f"row-{i:06d}", i) for i in range(n)]
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
    kw.setdefault("data_dir", tmp_path / "data")
    return DatabaseServer(repo, catalog_dir=tmp_path / "catalog", **kw)


def _host(srv: DatabaseServer, tmp_path: Path, name: str = "repository", n=N_ROWS):
    src = _sample_db(tmp_path / f"{name}-{n}-src.db", n)
    rec = srv.host_database(src, name)
    return rec["storage_key"], Path(rec["location"])


def _rows(path: Path) -> int:
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
    finally:
        conn.close()


def _flip(path: Path, offsets) -> None:
    data = bytearray(path.read_bytes())
    for off in offsets:
        data[off] ^= 0xFF
    path.write_bytes(bytes(data))


def _truncate_half(path: Path) -> None:
    size = path.stat().st_size
    with open(path, "r+b") as fh:
        fh.truncate((size // 2) // 4096 * 4096)


def _heal_results(report):
    return report["tasks"]["heal"]["results"]


def _status_of(report, key):
    for p in report["problems"]:
        if p["storage_key"] == key:
            return p["status"]
    return None


def _age(path: Path) -> None:
    os.utime(path, (OLD, OLD))


# --------------------------------------------------------------------------- #
# Primitive checks
# --------------------------------------------------------------------------- #
def test_header_and_integrity_primitives(tmp_path):
    db = _sample_db(tmp_path / "a.db")
    assert sqlite_header_problems(db) == []
    assert sqlite_integrity(db) == ("ok", [])

    trunc = tmp_path / "trunc.db"
    trunc.write_bytes(db.read_bytes()[: 3 * 4096])
    assert any("truncated" in p for p in sqlite_header_problems(trunc))

    ragged = tmp_path / "ragged.db"
    ragged.write_bytes(db.read_bytes() + b"x" * 7)
    assert any("multiple of the page size" in p for p in sqlite_header_problems(ragged))

    junk = tmp_path / "junk.db"
    junk.write_bytes(b"definitely not sqlite" * 400)
    assert sqlite_header_problems(junk) == ["not a SQLite database (bad header magic)"]
    assert sqlite_integrity(junk)[0] == "corrupt"

    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    assert sqlite_header_problems(empty) == []


def test_policy_validation():
    with pytest.raises(ValueError):
        AutopilotPolicy(drift_action="ignore")
    pol = AutopilotPolicy(check_interval=-5, backup_max_age=0, catalog_snapshots=-1)
    assert pol.check_interval == 0.0
    assert pol.backup_max_age is None
    assert pol.catalog_snapshots == 0
    assert pol.task_interval("check") == 0.0
    assert pol.to_dict()["drift_action"] == "restore"


# --------------------------------------------------------------------------- #
# check + backup
# --------------------------------------------------------------------------- #
def test_healthy_check_then_first_backup_then_steady_state(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)

    rep = srv.check_health()
    assert rep["healthy"] is True
    assert set(rep["tasks"]) == {"catalog", "check"}
    assert rep["tasks"]["check"]["by_status"] == {"healthy": 1}

    rep = srv.run_maintenance()
    assert rep["healthy"] is True
    done = rep["tasks"]["backup"]["backed_up"]
    assert [(d["storage_key"], d["reason"]) for d in done] == [(key, "no-backups")]
    sets = srv.backups.list_backups(key)
    assert len(sets) == 1
    assert sets[0]["source_sha256"] == srv.catalog.get_database(key)["sha256"]

    # An exact, fresh-enough backup exists: nothing more to do.
    rep = srv.run_maintenance()
    assert rep["tasks"]["backup"]["backed_up"] == []
    assert len(srv.backups.list_backups(key)) == 1

    st = srv.autopilot_status()
    assert st["databases"][key]["status"] == "healthy"
    assert st["enabled"] is True
    assert set(st["tasks"]) >= {"catalog", "check", "heal", "backup"}


def test_stale_backup_is_refreshed(tmp_path):
    srv = _server(tmp_path)
    key, _ = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    srv.autopilot.policy.backup_max_age = 0.5
    time.sleep(1.1)
    rep = srv.run_maintenance(tasks=["check", "backup"])
    assert [d["reason"] for d in rep["tasks"]["backup"]["backed_up"]] == ["stale"]


# --------------------------------------------------------------------------- #
# heal
# --------------------------------------------------------------------------- #
def test_flipped_bytes_are_detected_and_restored_with_quarantine(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    good_sha = srv.catalog.get_database(key)["sha256"]

    size = loc.stat().st_size
    _flip(loc, [size // 2, size // 2 + 1, size // 2 + 4000])
    rep = srv.check_health()
    assert rep["healthy"] is False
    assert _status_of(rep, key) in PROBLEM_STATUSES
    # A damaged key is flagged suspect: it can never be backed up over the
    # good sets (by this process or any other reading the suspect file).
    assert key in srv.backups.suspect_keys
    assert key in json.loads(srv.autopilot.suspect_path.read_text())["keys"]
    with pytest.raises(SnapshotIntegrityError):
        srv.backups.backup_database(key)

    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert rep["healthy"] is True
    (res,) = _heal_results(rep)
    assert res["result"] == "restored"
    assert _rows(loc) == N_ROWS
    assert sqlite_integrity(loc, quick=False) == ("ok", [])
    # The backup is a logical (online-API) snapshot, so its bytes may differ
    # from the originally hosted file; the catalog follows the installed file
    # and remembers both as the same lineage.
    from file_analyzer.server.autopilot import _sha256_file

    rec = srv.catalog.get_database(key)
    assert rec["sha256"] == _sha256_file(loc)
    lineage = srv.autopilot._load_state()["lineage"][key]["shas"]
    assert good_sha in lineage and rec["sha256"] in lineage
    # The damaged copy is preserved, with the reason.
    qdir = Path(res["quarantined"])
    reason = json.loads((qdir / "reason.json").read_text())
    assert reason["storage_key"] == key
    assert (qdir / loc.name).is_file()
    # ...and the key is no longer suspect.
    assert key not in srv.backups.suspect_keys
    assert json.loads(srv.autopilot.suspect_path.read_text())["keys"] == []
    kinds = [e["kind"] for e in srv.autopilot_status()["events"]]
    assert "health-changed" in kinds and "restored" in kinds


def test_deleted_file_is_restored(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    loc.unlink()
    rep = srv.check_health()
    assert _status_of(rep, key) == MISSING
    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert _heal_results(rep)[0]["result"] == "restored"
    assert _rows(loc) == N_ROWS


def test_truncated_file_is_corrupt_and_restored(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    _truncate_half(loc)
    rep = srv.check_health()
    assert _status_of(rep, key) == CORRUPT
    assert any("truncated" in p for p in rep["problems"][0]["problems"])
    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert rep["healthy"] and _rows(loc) == N_ROWS


def _drift(loc: Path) -> None:
    conn = sqlite3.connect(str(loc))
    try:
        conn.execute("INSERT INTO t VALUES ('drift', -1)")
        conn.commit()
    finally:
        conn.close()


def test_drift_restore_adopt_and_report(tmp_path):
    # restore (default): the hosted content comes back.
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    _drift(loc)
    rep = srv.check_health()
    assert _status_of(rep, key) == DRIFTED
    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert _heal_results(rep)[0]["result"] == "restored"
    assert _rows(loc) == N_ROWS

    # report: detected, left alone.
    srv.autopilot.policy.drift_action = "report"
    _drift(loc)
    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert _heal_results(rep)[0]["result"] == "reported"
    assert rep["healthy"] is False and _status_of(rep, key) == DRIFTED
    assert _rows(loc) == N_ROWS + 1

    # adopt: the new content becomes the truth and gets backed up.
    srv.autopilot.policy.drift_action = "adopt"
    rep = srv.run_maintenance(tasks=["check", "heal", "backup"])
    assert _heal_results(rep)[0]["result"] == "adopted"
    assert rep["healthy"] is True
    assert _rows(loc) == N_ROWS + 1
    rec = srv.catalog.get_database(key)
    assert rec["size_bytes"] == loc.stat().st_size
    backed = rep["tasks"]["backup"]["backed_up"]
    assert [(b["storage_key"], b["reason"]) for b in backed] == [(key, "requested")]
    assert srv.backups.list_backups(key)[-1]["source_sha256"] == rec["sha256"]


def test_rollback_to_older_backup_only_when_allowed(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path, n=N_ROWS)
    srv.run_maintenance(tasks=["check", "backup"])  # backup of v1
    # Re-host v2 (a new lineage) and damage it before any backup of it exists.
    _host(srv, tmp_path, n=N_ROWS + 500)
    srv.check_health()
    _truncate_half(loc)

    srv.autopilot.policy.allow_rollback = False
    rep = srv.run_maintenance(tasks=["check", "heal"])
    (res,) = _heal_results(rep)
    assert res["result"] == "unrecoverable"
    assert [c["kind"] for c in res["candidates"]] == []
    assert _status_of(rep, key) == CORRUPT

    srv.autopilot.policy.allow_rollback = True
    rep = srv.run_maintenance(tasks=["check", "heal"])
    (res,) = _heal_results(rep)
    assert res["result"] == "rolled-back"
    assert rep["healthy"] is True
    assert _rows(loc) == N_ROWS  # v1's content
    kinds = [e["kind"] for e in srv.autopilot_status()["events"]]
    assert "rolled-back" in kinds and "unrecoverable" in kinds


def test_lost_database_without_backups_is_dropped_after_grace(tmp_path):
    srv = _server(tmp_path, auto_backup=False)
    key, loc = _host(srv, tmp_path)
    srv.check_health()
    loc.unlink()
    rep = srv.run_maintenance(tasks=["check", "heal"])
    (res,) = _heal_results(rep)
    assert res["result"] == "lost-pending" and res["drop_in"] > 0
    assert srv.catalog.get_database(key) is not None

    srv.autopilot.policy.lost_grace = 0
    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert _heal_results(rep)[0]["result"] == "dropped"
    assert srv.catalog.get_database(key) is None
    assert rep["healthy"] is True


def test_corrupt_backup_candidate_is_skipped(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    older = srv.backups.list_backups(key)[0]["timestamp"]
    time.sleep(1.1)  # distinct set timestamp
    srv.backups.backup_database(key)
    sets = srv.backups.list_backups(key)
    assert len(sets) == 2
    newest = sets[-1]["timestamp"]
    for part in (srv.backups.backup_dir / key / newest).glob("*.gz.part*"):
        _flip(part, [part.stat().st_size // 2])
    _truncate_half(loc)
    rep = srv.run_maintenance(tasks=["check", "heal"])
    (res,) = _heal_results(rep)
    assert res["result"] == "restored"
    assert res["timestamp"] == older
    assert [c["timestamp"] for c in res["skipped_candidates"]] == [newest]
    assert _rows(loc) == N_ROWS


def test_heal_disabled_only_reports(tmp_path):
    srv = _server(tmp_path, auto_heal=False)
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    _truncate_half(loc)
    # A normal (unforced) tick checks but must not heal.
    srv.autopilot.policy.check_interval = 0.01
    time.sleep(0.05)
    rep = srv.autopilot.run_once()
    assert "heal" not in rep["tasks"]
    assert _status_of(rep, key) == CORRUPT


def test_background_loop_heals_on_its_own(tmp_path):
    srv = _server(
        tmp_path, autopilot_startup_delay=0, check_interval=0.5, autopilot_interval=0.5
    )
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    srv.autopilot.policy.interval = 0.5
    _truncate_half(loc)
    srv.autopilot.start()
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            st = srv.autopilot_status()
            if st["databases"].get(key, {}).get("status") == "healthy" and any(
                e["kind"] == "restored" for e in st["events"]
            ):
                break
            time.sleep(0.2)
        else:
            pytest.fail("the background autopilot never healed the database")
        assert srv.autopilot.running
    finally:
        srv.autopilot.stop()
    assert not srv.autopilot.running
    assert _rows(loc) == N_ROWS


def test_remote_backend_heal(tmp_path):
    """Chunked-content backend (the Postgres/MySQL code path, emulated with a
    SQLite URL): lost chunks are detected and the chunks are rewritten."""
    srv = _server(tmp_path)
    srv.dbhost.backend = f"sqlite:///{(tmp_path / 'content.db').as_posix()}"
    srv.dbhost.dialect = "postgresql"
    srv.dbhost.chunk_bytes = 64 * 1024
    key, _ = _host(srv, tmp_path)
    rec = srv.catalog.get_database(key)
    assert rec["dialect"] == "postgresql" and rec["n_chunks"] >= 2
    srv.run_maintenance(tasks=["check", "backup"])

    conn = sqlite3.connect(str(tmp_path / "content.db"))
    conn.execute("DELETE FROM hosted_chunks WHERE storage_key = ? AND seq = 1", (key,))
    conn.commit()
    conn.close()
    assert srv.dbhost.chunk_stats(key)["n_chunks"] == rec["n_chunks"] - 1

    rep = srv.check_health()
    assert _status_of(rep, key) in (CORRUPT, DRIFTED)
    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert _heal_results(rep)[0]["result"] == "restored"
    assert rep["healthy"] is True
    out = srv.dbhost.materialize(key, tmp_path / "back.db")
    assert _rows(out) == N_ROWS


# --------------------------------------------------------------------------- #
# catalog
# --------------------------------------------------------------------------- #
def test_catalog_snapshots_rotate(tmp_path):
    srv = _server(tmp_path)
    srv.autopilot.policy.catalog_snapshot_interval = 0
    srv.autopilot.policy.catalog_snapshots = 2
    for _ in range(4):
        rep = srv.run_maintenance(tasks=["catalog"])
        assert rep["tasks"]["catalog"]["status"] == "ok"
        time.sleep(1.05)
    snaps = srv.autopilot._snapshots()
    assert len(snaps) == 2
    assert all(sqlite_integrity(s)[0] == "ok" for s in snaps)


@pytest.mark.parametrize("damage", ["garbage", "deleted"])
def test_catalog_is_rebuilt_from_snapshot(tmp_path, damage):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    rep = srv.run_maintenance(tasks=["catalog"])
    assert rep["tasks"]["catalog"].get("snapshot")
    cat = Path(srv.catalog.target)
    if damage == "garbage":
        cat.write_bytes(b"\x00garbage" * 5000)
    else:
        cat.unlink()

    rep = srv.run_maintenance(tasks=["catalog", "check"])
    assert rep["tasks"]["catalog"]["status"] == "recovered"
    assert rep["healthy"] is True
    assert srv.catalog.get_database(key)["location"] == str(loc)
    # The session (and so every storage key) survived.
    assert srv.catalog.get_or_create_session(srv.root)["token"] == srv.token
    if damage == "garbage":
        qroot = Path(srv.catalog.dir) / "quarantine"
        assert any(qroot.iterdir())
    assert "catalog-recovered" in [e["kind"] for e in srv.autopilot_status()["events"]]


def test_catalog_rebuilt_without_snapshot_readopts_orphans(tmp_path):
    """No snapshot at all: the catalog is recreated empty (plus our session)
    and the sweep re-registers the still-sound hosted file."""
    srv = _server(tmp_path)
    srv.autopilot.policy.catalog_snapshots = 0
    key, loc = _host(srv, tmp_path)
    Path(srv.catalog.target).write_bytes(b"junk" * 10000)
    _age(loc)
    rep = srv.run_maintenance(tasks=["catalog", "sweep", "check"])
    assert rep["tasks"]["catalog"]["status"] == "recovered"
    assert rep["tasks"]["sweep"]["orphans"]["adopted"] == [{"storage_key": key}]
    rec = srv.catalog.get_database(key)
    assert rec is not None and rec["db_name"] == "repository"
    assert rep["healthy"] is True


# --------------------------------------------------------------------------- #
# scrub
# --------------------------------------------------------------------------- #
def test_unrecoverable_backup_set_dropped_after_grace_and_rebacked(tmp_path):
    srv = _server(tmp_path)
    key, _ = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    ts = srv.backups.list_backups(key)[0]["timestamp"]
    for part in (srv.backups.backup_dir / key / ts).glob("*.gz.part*"):
        _flip(part, [part.stat().st_size // 2])

    rep = srv.run_maintenance(tasks=["scrub"])
    assert rep["tasks"]["scrub"]["unrecoverable_pending"] == [f"{key}/{ts}"]
    assert srv.backups.list_backups(key)  # still inside the grace period

    srv.autopilot.policy.unrecoverable_grace = 0
    time.sleep(1.1)  # so the replacement set gets a distinct timestamp
    rep = srv.run_maintenance(tasks=["scrub", "check", "backup"])
    assert [d["timestamp"] for d in rep["tasks"]["scrub"]["dropped"]] == [ts]
    backed = rep["tasks"]["backup"]["backed_up"]
    assert [(b["storage_key"], b["reason"]) for b in backed] == [(key, "requested")]
    sets = srv.backups.list_backups(key)
    assert len(sets) == 1 and sets[0]["timestamp"] != ts
    assert srv.backups.verify_backups(key)["by_status"] == {"healthy": 1}


def test_scrub_repairs_lost_reed_solomon_shard(tmp_path):
    srv = _server(tmp_path, rs_data_shards=2, rs_parity_shards=1)
    key, _ = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    m = srv.backups.list_backups(key)[0]
    shard_files = sorted(
        p
        for root in srv.backups._roots()
        for p in root.rglob("*")
        if p.is_file() and m["timestamp"] in str(p) and "shard" in p.name
    )
    assert shard_files, "no shard files found"
    shard_files[0].unlink()
    rep = srv.run_maintenance(tasks=["scrub"])
    assert rep["tasks"]["scrub"]["repaired"] == 1
    assert srv.backups.verify_backups(key)["by_status"] == {"healthy": 1}
    assert "backup-set-repaired" in [
        e["kind"] for e in srv.autopilot_status()["events"]
    ]


# --------------------------------------------------------------------------- #
# sweep
# --------------------------------------------------------------------------- #
def test_sweep_removes_old_debris_but_not_fresh_files(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    data = srv.data_dir
    old_heal = data / f".{key}.db.healing"
    old_tmp = data / ".x.check.1.tmp"
    fresh = data / ".y.check.2.tmp"
    for p in (old_heal, old_tmp, fresh):
        p.write_bytes(b"x" * 100)
    _age(old_heal)
    _age(old_tmp)
    bset = srv.backups.backup_dir / key / "20000101-000000"
    bset.mkdir(parents=True)
    stray = bset / "_tmp.gz"
    stray.write_bytes(b"y" * 50)
    _age(stray)
    qold = srv.autopilot.quarantine_dir / "k.20000101-000000.corrupt"
    qold.mkdir(parents=True)
    (qold / "reason.json").write_text("{}")
    _age(qold)
    qnew = srv.autopilot.quarantine_dir / "k.new.corrupt"
    qnew.mkdir(parents=True)

    # Dead servers' files; never our own.
    dead_ep = srv.run_dir / "endpoint-deadbeef.json"
    dead_ep.write_text(json.dumps({"pid": 2**22 + 12345}))
    dead_pid = srv.run_dir / "server-deadbeef.pid"
    dead_pid.write_text(str(2**22 + 12345))
    own_ep = srv.endpoint_file
    own_ep.write_text(json.dumps({"pid": 2**22 + 999}))
    for p in (dead_ep, dead_pid, own_ep):
        _age(p)

    dry = srv.run_maintenance(tasks=["sweep"], dry_run=True)
    assert len(dry["tasks"]["sweep"]["removed"]) >= 5
    assert old_heal.exists() and dead_ep.exists()

    rep = srv.run_maintenance(tasks=["sweep"])
    sweep = rep["tasks"]["sweep"]
    for gone in (old_heal, old_tmp, stray, qold, dead_ep, dead_pid):
        assert not gone.exists(), gone
    for kept in (fresh, qnew, own_ep, loc):
        assert kept.exists(), kept
    assert sweep["dead_servers"] == ["deadbeef"]
    assert sweep["freed_bytes"] >= 250


def test_sweep_orphans_adopt_sound_quarantine_corrupt_ignore_foreign(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    srv.catalog.remove_database(key)  # the row is lost, the file is not
    ghost_key = srv.storage_key_for("ghost")
    ghost = srv.data_dir / f"{ghost_key}.db"
    ghost.write_bytes(loc.read_bytes()[:8192] + b"\xde\xad" * 4096)
    foreign = srv.data_dir / "someone-else.db"
    _sample_db(foreign, 5)
    for p in (loc, ghost, foreign):
        _age(p)

    rep = srv.run_maintenance(tasks=["sweep"])
    orphans = rep["tasks"]["sweep"]["orphans"]
    assert orphans["adopted"] == [{"storage_key": key}]
    assert [q["storage_key"] for q in orphans["quarantined"]] == [ghost_key]
    assert orphans["foreign"] == ["someone-else.db"]
    rec = srv.catalog.get_database(key)
    assert rec is not None and rec["sha256"]
    assert not ghost.exists() and foreign.exists()
    qdir = Path(orphans["quarantined"][0]["path"])
    assert (qdir / ghost.name).is_file() and (qdir / "reason.json").is_file()
    # The adopted database is healthy afterwards.
    assert srv.check_health()["healthy"] is True


# --------------------------------------------------------------------------- #
# state, locking, dry run
# --------------------------------------------------------------------------- #
def test_state_persists_across_instances_and_survives_corruption(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    _truncate_half(loc)
    srv.check_health()

    # A second instance on the same repo sees the verdicts and the suspect key.
    other = _server(tmp_path)
    st = other.autopilot_status()
    assert st["databases"][key]["status"] == CORRUPT
    assert key in other.backups.suspect_keys
    assert st["tasks"]["check"]["last_run"] is not None

    other.autopilot.state_path.write_text("{ torn json")
    third = _server(tmp_path)
    assert third.autopilot.status()["databases"] == {}
    rep = third.run_maintenance(tasks=["check", "heal"])
    assert rep["healthy"] is True
    kinds = [e["kind"] for e in third.autopilot_status()["events"]]
    assert "state-reset" in kinds


def test_concurrent_tick_is_skipped(tmp_path):
    srv = _server(tmp_path)
    holder = FileLock(srv.autopilot.lock_path, timeout=0)
    got = threading.Event()
    release = threading.Event()

    def _hold():
        holder.acquire()
        got.set()
        release.wait(10)
        holder.release()

    t = threading.Thread(target=_hold)
    t.start()
    try:
        assert got.wait(5)
        rep = srv.run_maintenance(wait=False)
        assert rep["skipped"] is True
    finally:
        release.set()
        t.join()
    assert srv.run_maintenance(wait=False).get("skipped") is None


def test_dry_run_modifies_nothing(tmp_path):
    srv = _server(tmp_path)
    key, loc = _host(srv, tmp_path)
    srv.run_maintenance(tasks=["check", "backup"])
    _truncate_half(loc)
    damaged = loc.read_bytes()
    state_before = srv.autopilot.state_path.read_bytes()
    sets_before = srv.backups.list_backups(key)
    old = srv.data_dir / ".z.check.9.tmp"
    old.write_bytes(b"z")
    _age(old)

    rep = srv.run_maintenance(dry_run=True)
    assert rep["dry_run"] is True
    (res,) = _heal_results(rep)
    assert res["result"] == "would-restore"
    assert loc.read_bytes() == damaged
    assert srv.autopilot.state_path.read_bytes() == state_before
    assert srv.backups.list_backups(key) == sets_before
    assert old.exists()


def test_unknown_task_is_rejected(tmp_path):
    srv = _server(tmp_path)
    with pytest.raises(ValueError):
        srv.run_maintenance(tasks=["defrag"])


# --------------------------------------------------------------------------- #
# HTTP, CLI, SDK
# --------------------------------------------------------------------------- #
def test_http_autopilot_routes(tmp_path):
    srv = _server(tmp_path, autopilot_startup_delay=3600)
    key, loc = _host(srv, tmp_path)
    t = threading.Thread(target=lambda: srv.serve(contained=False), daemon=True)
    t.start()
    try:
        deadline = time.monotonic() + 15
        while not srv.endpoint_file.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        client = ServerClient(srv.url, srv.token)
        health = client.health()
        assert health["status"] == "ok"
        assert health["autopilot"]["running"] is True

        rep = client.run_autopilot(tasks=["check", "backup"])
        assert rep["healthy"] is True
        _truncate_half(loc)
        assert client.check()["healthy"] is False
        rep = client.run_autopilot()
        assert rep["healthy"] is True and _rows(loc) == N_ROWS
        st = client.autopilot_status()
        assert st["enabled"] is True and st["running"] is True
        with pytest.raises(ServerError) as exc:
            client.run_autopilot(tasks=["defrag"])
        assert exc.value.status == 400
        with pytest.raises(ServerError) as exc:
            ServerClient(srv.url).autopilot_status()
        assert exc.value.status == 401
    finally:
        if srv._httpd is not None:
            srv._httpd.shutdown()
        t.join(timeout=15)
    assert not srv.autopilot.running


def test_cli_check_and_maintain(tmp_path, capsys, monkeypatch):
    from file_analyzer.server.__main__ import main

    monkeypatch.setenv("FILE_ANALYZER_ALLOW_BARE_METAL", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    srv = DatabaseServer(repo, catalog_dir=tmp_path / "catalog", backup_interval=0)
    key, loc = _host(srv, tmp_path)
    common = [str(repo), "--catalog-dir", str(tmp_path / "catalog")]

    assert main(["maintain", *common]) == 0
    assert json.loads(capsys.readouterr().out)["healthy"] is True
    _truncate_half(loc)
    assert main(["check", *common]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["problems"][0]["status"] == CORRUPT
    assert main(["maintain", *common, "--dry-run"]) == 1
    capsys.readouterr()
    assert main(["maintain", *common, "--task", "check", "--task", "heal"]) == 0
    capsys.readouterr()
    assert _rows(loc) == N_ROWS
    assert main(["autopilot", *common]) == 0
    st = json.loads(capsys.readouterr().out)
    assert st["databases"][key]["status"] == "healthy"


def test_autopilot_config_reaches_the_detached_child(tmp_path):
    from file_analyzer.server.__main__ import build_parser

    srv = _server(
        tmp_path,
        auto_heal=False,
        allow_rollback=False,
        auto_backup=False,
        drift_action="adopt",
        check_interval=120,
        deep_check_interval=0,
        autopilot_interval=60,
    )
    argv = srv._autopilot_argv()
    assert "--no-auto-heal" in argv and "--no-rollback" in argv
    assert "--no-auto-backup" in argv
    args = build_parser().parse_args(["run", str(tmp_path / "repo"), *argv])
    assert args.drift_action == "adopt"
    assert args.check_interval == 120.0 and args.deep_check_interval == 0.0
    assert args.autopilot_interval == 60.0 and args.no_auto_heal is True


def test_sdk_self_healing_methods(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    fas = FileAnalyzerServer(
        repo,
        catalog_dir=tmp_path / "catalog",
        data_dir=tmp_path / "data",
        backup_interval=0,
        retention_interval=0,
        autopilot_startup_delay=0,
    )
    src = _sample_db(tmp_path / "s.db")
    rec = fas.host_database(src, "repository")
    loc = Path(rec["location"])
    assert fas.check()["healthy"] is True
    assert fas.maintain(tasks=["backup"])["tasks"]["backup"]["backed_up"]
    _truncate_half(loc)
    assert fas.heal(dry_run=True)["tasks"]["heal"]["results"][0]["result"] == (
        "would-restore"
    )
    rep = fas.heal()
    assert rep["healthy"] is True and _rows(loc) == N_ROWS
    hr = fas.health_report()
    assert set(hr) == {"autopilot", "backups", "retention", "supervisor"}
    assert hr["supervisor"] is None
    st = fas.start_autopilot()
    assert st["running"] is True
    fas.stop_autopilot()
    assert fas.autopilot_status()["running"] is False
    with pytest.raises(ValueError):
        fas.start(detach=False, supervise=True)


# --------------------------------------------------------------------------- #
# supervisor
# --------------------------------------------------------------------------- #
def test_supervisor_gives_up_after_max_restarts(tmp_path):
    srv = _server(tmp_path)
    sup = ServerSupervisor(srv, max_restarts=0)
    out = sup.check_once()  # never started: the process is "dead"
    assert out["state"] == "dead"
    assert out["restart"]["result"] == "gave-up"
    assert sup.gave_up and sup.check_once()["state"] == "gave-up"
    assert sup.status()["history"][0]["result"] == "gave-up"


def _child_env(monkeypatch):
    import file_analyzer

    roots = [str(Path(p).resolve().parent) for p in list(file_analyzer.__path__)]
    existing = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv(
        "PYTHONPATH", os.pathsep.join([*roots, existing] if existing else roots)
    )
    monkeypatch.setenv("FILE_ANALYZER_ALLOW_BARE_METAL", "1")


def _healthy(url, token):
    try:
        return ServerClient(url, token, timeout=2).health()["status"] == "ok"
    except Exception:
        return False


def _wait(pred, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.1)
    return False


@pytest.mark.skipif(os.name != "posix", reason="signals are POSIX-only")
@pytest.mark.parametrize("how", ["kill", "freeze"])
def test_supervisor_restarts_dead_or_frozen_server(tmp_path, monkeypatch, how):
    _child_env(monkeypatch)
    repo = tmp_path / "repo"
    repo.mkdir()
    fas = FileAnalyzerServer(repo, catalog_dir=tmp_path / "catalog", backup_interval=0)
    info = fas.start(
        supervise=True,
        interval=3600,  # the test drives check_once() itself
        failure_threshold=2,
        health_timeout=1,
        backoff=0,
        stop_timeout=1,
    )
    sup = fas._supervisor
    pids = [int(info["pid"])]
    try:
        assert _wait(lambda: _healthy(info["url"], info["token"]))
        assert sup.check_once()["state"] == "healthy"
        if how == "kill":
            from file_analyzer.server.supervisor import process_alive

            os.kill(pids[0], signal.SIGKILL)
            _wait(lambda: not process_alive(pids[0]), timeout=5)
            # "dead" once reaped; an un-reaped zombie (non-reaping PID 1 in a
            # container) is caught as unresponsive on the next check instead.
            out = sup.check_once()
            if "restart" not in out:
                out = sup.check_once()
            assert out["state"] in ("dead", "unresponsive")
        else:
            os.kill(pids[0], signal.SIGSTOP)
            first = sup.check_once()
            assert first["state"] == "unresponsive" and "restart" not in first
            out = sup.check_once()
            assert out["state"] == "unresponsive"
        assert out["restart"]["result"] == "restarted", out
        new = sup.info
        pids.append(int(new["pid"]))
        assert pids[1] != pids[0]
        assert new["token"] == info["token"]
        assert _wait(lambda: _healthy(new["url"], new["token"]))
        assert sup.check_once()["state"] == "healthy"
        st = fas.supervisor_status()
        assert st["restarts_in_window"] == 1 and not st["gave_up"]
    finally:
        fas.stop()
        assert fas.supervisor_status() is None
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
