"""
Tests for the autopilot's worker pool (``file_analyzer.server.autopilot_pool``
+ ``file_analyzer.server.autopilot_worker``): health checks, backup-set
verification/repair and heal restore staging fanned out across the Go worker
pool, with the in-process thread pool as the toolchain-free fallback.

Everything runs against real hosted SQLite files and real backup sets. The Go
tests are skipped when no Go toolchain is on PATH (the CI image has none, so
there the Python fallback is what runs).
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from file_analyzer.server import autopilot_worker  # noqa: E402
from file_analyzer.server import AutopilotPolicy, DatabaseServer  # noqa: E402
from file_analyzer.server.autopilot import (  # noqa: E402
    CORRUPT,
    HEALTHY,
    MISSING,
    PROBLEM_STATUSES,
    check_database,
    healing_path,
    sqlite_integrity,
    stage_restore,
)
from file_analyzer.server.autopilot_pool import run_jobs  # noqa: E402

N_ROWS = 2000
HAVE_GO = shutil.which("go") is not None
needs_go = pytest.mark.skipif(not HAVE_GO, reason="Go toolchain not on PATH")


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


def _host_many(srv: DatabaseServer, tmp_path: Path, n: int):
    """Host ``n`` databases of distinct sizes; returns ``[(key, location)]``."""
    out = []
    for i in range(n):
        src = _sample_db(tmp_path / f"db{i}-src.db", N_ROWS + 100 * i)
        rec = srv.host_database(src, f"db{i}")
        out.append((rec["storage_key"], Path(rec["location"])))
    return out


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


def _inspect_items(srv: DatabaseServer, deep: bool = True):
    recs = srv.catalog.list_databases(token=srv.dbhost.token)
    return [{"rec": r, "entry": {}, "deep": deep} for r in recs]


def _heal_by_key(report):
    return {r["storage_key"]: r for r in report["tasks"]["heal"]["results"]}


# --------------------------------------------------------------------------- #
# Primitives shared by both pool paths
# --------------------------------------------------------------------------- #
def test_check_database_triage_defers_only_the_expensive_pass(tmp_path):
    srv = _server(tmp_path)
    ((key, loc),) = _host_many(srv, tmp_path, 1)
    rec = srv.catalog.get_database(key)

    # First sight: no cached stat, so a full check is needed -> deferred.
    entry: dict = {}
    assert check_database(srv.dbhost, rec, entry, deep=False, triage=True) is None
    assert entry == {}  # untouched when deferred
    # The full check fills the cache ...
    assert check_database(srv.dbhost, rec, entry, deep=False) == (HEALTHY, [])
    assert entry["sha"] == rec["sha256"] and entry["size"] == loc.stat().st_size
    entry["status"] = HEALTHY
    # ... after which an unchanged file is settled by the cheap pass alone.
    assert check_database(srv.dbhost, rec, entry, deep=False, triage=True) == (
        HEALTHY,
        [],
    )
    # A deep pass is never settled cheaply.
    assert check_database(srv.dbhost, rec, entry, deep=True, triage=True) is None
    # A missing file is decided in triage (nothing expensive to do).
    loc.unlink()
    status, problems = check_database(srv.dbhost, rec, entry, deep=False, triage=True)
    assert status == MISSING and "missing" in problems[0]


def test_stage_restore_skips_bad_candidates_and_reports_them(tmp_path):
    srv = _server(tmp_path)
    ((key, _),) = _host_many(srv, tmp_path, 1)
    good = srv.backups.backup_database(key)["timestamp"]
    dest = healing_path(srv.dbhost.data_dir, key)

    res = stage_restore(
        srv.backups,
        key,
        [{"timestamp": "19700101T000000Z", "kind": "exact"}, {"timestamp": good}],
        dest,
    )
    assert res["staged"] == str(dest) and res["timestamp"] == good
    assert res["index"] == 1 and len(res["failures"]) == 1
    assert res["failures"][0]["timestamp"] == "19700101T000000Z"
    assert sqlite_integrity(dest, quick=False) == ("ok", [])
    assert _rows(dest) == N_ROWS

    # Nothing restorable: no staged file is left behind.
    res = stage_restore(srv.backups, key, [{"timestamp": "nope"}], dest)
    assert res["staged"] is None and len(res["failures"]) == 1
    assert not dest.exists()


# --------------------------------------------------------------------------- #
# run_jobs engines
# --------------------------------------------------------------------------- #
def test_run_jobs_engine_selection_and_identical_results(tmp_path):
    srv = _server(tmp_path)
    _host_many(srv, tmp_path, 4)
    items = _inspect_items(srv)

    none = run_jobs(srv.backups, "inspect", [])
    assert none["engine"] == "none" and none["results"] == []

    inline = run_jobs(srv.backups, "inspect", items, workers=1)
    assert inline["engine"] == "inline" and inline["workers"] == 1

    pooled = run_jobs(srv.backups, "inspect", items, workers=4, use_go=False)
    assert pooled["engine"] == "python" and pooled["workers"] == 4

    def strip(results):
        return [
            (r["storage_key"], r["status"], r["problems"], r["entry"]["sha"])
            for r in results
        ]

    assert strip(inline["results"]) == strip(pooled["results"])
    assert [r["status"] for r in pooled["results"]] == [HEALTHY] * 4
    # results are aligned with the items
    assert [r["storage_key"] for r in pooled["results"]] == [
        it["rec"]["storage_key"] for it in items
    ]
    # the input entries are never mutated by the jobs
    assert all(it["entry"] == {} for it in items)

    with pytest.raises(ValueError):
        run_jobs(srv.backups, "bogus", items)


def test_job_exception_is_reported_per_item(tmp_path, monkeypatch):
    srv = _server(tmp_path)
    _host_many(srv, tmp_path, 3)
    items = _inspect_items(srv)
    bad = items[1]["rec"]["storage_key"]
    real = autopilot_worker.execute

    def flaky(kind, manager, item):
        if item["rec"]["storage_key"] == bad:
            raise RuntimeError("worker blew up")
        return real(kind, manager, item)

    monkeypatch.setattr(autopilot_worker, "execute", flaky)
    run = run_jobs(srv.backups, "inspect", items, workers=3, use_go=False)
    assert run["results"][1] == {"error": "RuntimeError: worker blew up"}
    assert run["results"][0]["status"] == HEALTHY
    assert run["results"][2]["status"] == HEALTHY


# --------------------------------------------------------------------------- #
# The worker CLI (what each Go-pool child runs)
# --------------------------------------------------------------------------- #
def test_worker_cli_runs_a_batch_and_marks_status(tmp_path):
    srv = _server(tmp_path)
    _host_many(srv, tmp_path, 2)
    out = tmp_path / "pool"
    (out / "batches").mkdir(parents=True)
    spec = out / "spec.json"
    spec.write_text(json.dumps(srv.backups.job_spec()), encoding="utf-8")
    items = _inspect_items(srv)
    batch = out / "batches" / "batch_0.json"
    batch.write_text(
        json.dumps(
            {
                "batch_id": 0,
                "kind": "inspect",
                "items": [{"id": i, "item": it} for i, it in enumerate(items)],
            }
        ),
        encoding="utf-8",
    )
    args = ["--spec", str(spec), "--out", str(out), "--batch", str(batch)]
    assert autopilot_worker.main(["--kind", "inspect", *args]) == 0
    assert (out / "status" / "0.ok").is_file()
    payload = json.loads((out / "results" / "result_0.json").read_text())
    assert [r["id"] for r in payload["results"]] == [0, 1]
    assert {r["result"]["status"] for r in payload["results"]} == {HEALTHY}

    # A batch staged for another kind is refused, and the failure is marked.
    assert autopilot_worker.main(["--kind", "verify", *args]) == 1
    assert "not 'verify'" in (out / "status" / "0.err").read_text()


# --------------------------------------------------------------------------- #
# Autopilot tasks through the pool (thread-pool fallback: runs everywhere)
# --------------------------------------------------------------------------- #
def test_pooled_check_and_heal_of_many_databases(tmp_path):
    srv = _server(tmp_path, autopilot_workers=4, autopilot_use_go=False)
    dbs = _host_many(srv, tmp_path, 5)
    rep = srv.run_maintenance(tasks=["check", "backup"])
    assert rep["tasks"]["check"]["engine"] == "python"
    assert rep["tasks"]["check"]["full_checks"] == 5  # first sight: all hashed
    assert len(rep["tasks"]["backup"]["backed_up"]) == 5

    # Steady state: the cheap triage settles everything, nothing is pooled.
    rep = srv.check_health()
    assert rep["tasks"]["check"]["full_checks"] == 0
    assert rep["tasks"]["check"]["engine"] == "none"
    assert rep["tasks"]["check"]["by_status"] == {HEALTHY: 5}

    (k0, l0), (k1, l1), (k2, l2), (k3, _), (k4, _) = dbs
    size = l0.stat().st_size
    _flip(l0, [size // 2, size // 2 + 1, size // 2 + 4000])
    l1.unlink()
    _truncate_half(l2)
    rep = srv.check_health()
    check = rep["tasks"]["check"]
    assert check["full_checks"] == 2  # the missing file is settled in triage
    assert check["engine"] == "python"
    statuses = {p["storage_key"]: p["status"] for p in rep["problems"]}
    assert set(statuses) == {k0, k1, k2}
    assert statuses[k1] == MISSING and statuses[k2] == CORRUPT
    assert all(s in PROBLEM_STATUSES for s in statuses.values())

    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert rep["healthy"] is True
    heal = rep["tasks"]["heal"]
    assert heal["engines"] == {"check": "python", "stage": "python"}
    by_key = _heal_by_key(rep)
    assert {k: r["result"] for k, r in by_key.items()} == {
        k0: "restored",
        k1: "restored",
        k2: "restored",
    }
    for i, (key, loc) in enumerate(dbs):
        assert _rows(loc) == N_ROWS + 100 * i
        assert sqlite_integrity(loc, quick=False) == ("ok", [])
    # no staging debris
    assert not list(Path(srv.dbhost.data_dir).glob("*.healing*"))
    assert srv.autopilot.status()["last_pool"]["kind"] in ("inspect", "stage")


def test_pooled_heal_skips_corrupt_candidate_per_database(tmp_path):
    srv = _server(tmp_path, autopilot_workers=3, autopilot_use_go=False)
    dbs = _host_many(srv, tmp_path, 3)
    srv.run_maintenance(tasks=["check", "backup"])
    older = {k: srv.backups.list_backups(k)[0]["timestamp"] for k, _ in dbs}
    time.sleep(1.1)  # distinct set timestamps
    newest = {k: srv.backups.backup_database(k)["timestamp"] for k, _ in dbs}
    for key, loc in dbs:
        for part in (srv.backups.backup_dir / key / newest[key]).glob("*.gz.part*"):
            _flip(part, [part.stat().st_size // 2])
        _truncate_half(loc)
    rep = srv.run_maintenance(tasks=["check", "heal"])
    by_key = _heal_by_key(rep)
    for key, loc in dbs:
        res = by_key[key]
        assert res["result"] == "restored"
        assert res["timestamp"] == older[key]
        assert [c["timestamp"] for c in res["skipped_candidates"]] == [newest[key]]
        assert _rows(loc) >= N_ROWS


def test_staging_worker_failure_never_escalates(tmp_path, monkeypatch):
    """A job the pool could not run is transient: no drop, no adopt."""
    srv = _server(tmp_path, autopilot_workers=2, autopilot_use_go=False)
    dbs = _host_many(srv, tmp_path, 2)
    srv.run_maintenance(tasks=["check", "backup"])
    srv.autopilot.policy.lost_grace = 0.0  # a real escalation would drop at once
    for _, loc in dbs:
        loc.unlink()
    real = autopilot_worker.execute

    def broken(kind, manager, item):
        if kind == "stage":
            raise OSError("worker lost its disk")
        return real(kind, manager, item)

    monkeypatch.setattr(autopilot_worker, "execute", broken)
    rep = srv.run_maintenance(tasks=["check", "heal"])
    by_key = _heal_by_key(rep)
    for key, _ in dbs:
        assert by_key[key]["result"] == "failed"
        assert "worker lost its disk" in by_key[key]["error"]
        assert srv.catalog.get_database(key) is not None  # not dropped
    kinds = [e["kind"] for e in srv.autopilot_status()["events"]]
    assert "heal-failed" in kinds and "dropped-lost" not in kinds

    # Once the workers work again the next (forced) heal restores both.
    monkeypatch.setattr(autopilot_worker, "execute", real)
    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert {r["result"] for r in _heal_by_key(rep).values()} == {"restored"}
    for i, (_, loc) in enumerate(dbs):
        assert _rows(loc) == N_ROWS + 100 * i


def test_recheck_worker_failure_is_transient(tmp_path, monkeypatch):
    srv = _server(tmp_path, autopilot_workers=2, autopilot_use_go=False)
    dbs = _host_many(srv, tmp_path, 2)
    srv.run_maintenance(tasks=["check", "backup"])
    for _, loc in dbs:
        _truncate_half(loc)
    srv.check_health()
    real = autopilot_worker.execute

    def broken(kind, manager, item):
        if kind == "inspect":
            raise RuntimeError("recheck crashed")
        return real(kind, manager, item)

    monkeypatch.setattr(autopilot_worker, "execute", broken)
    rep = srv.run_maintenance(tasks=["heal"])
    for key, _ in dbs:
        res = _heal_by_key(rep)[key]
        assert res["result"] == "transient-error"
        assert "recheck crashed" in res["problems"][0]


def test_pooled_scrub_and_verify_report_engine(tmp_path):
    srv = _server(
        tmp_path,
        rs_data_shards=2,
        rs_parity_shards=1,
        autopilot_workers=3,
        autopilot_use_go=False,
    )
    dbs = _host_many(srv, tmp_path, 3)
    srv.run_maintenance(tasks=["check", "backup"])
    ver = srv.verify_backups()
    assert ver["engine"] == "python" and ver["workers"] == 3
    assert ver["by_status"] == {"healthy": 3}

    # Lose one shard of every set; the pooled scrub repairs them all.
    for key, _ in dbs:
        ts = srv.backups.list_backups(key)[0]["timestamp"]
        shard = next(
            p
            for root in srv.backups._roots()
            for p in sorted(root.rglob("*"))
            if p.is_file() and ts in str(p) and key in str(p) and "shard" in p.name
        )
        shard.unlink()
    rep = srv.run_maintenance(tasks=["scrub"])
    scrub = rep["tasks"]["scrub"]
    assert scrub["engine"] == "python" and scrub["repaired"] == 3
    assert srv.verify_backups()["by_status"] == {"healthy": 3}
    # a single key runs inline
    assert srv.verify_backups(dbs[0][0])["engine"] == "inline"


# --------------------------------------------------------------------------- #
# Configuration plumbing
# --------------------------------------------------------------------------- #
def test_policy_workers_validation_and_child_argv(tmp_path):
    assert AutopilotPolicy(workers=0).workers is None
    assert AutopilotPolicy(workers="6").workers == 6
    with pytest.raises(ValueError):
        AutopilotPolicy(workers=-1)

    from file_analyzer.server.__main__ import build_parser

    srv = _server(tmp_path, autopilot_workers=3, autopilot_use_go=False)
    argv = srv._autopilot_argv()
    assert argv[argv.index("--autopilot-workers") + 1] == "3"
    assert "--no-go-workers" in argv
    args = build_parser().parse_args(["run", str(tmp_path / "repo"), *argv])
    assert args.autopilot_workers == 3 and args.no_go_workers is True

    (tmp_path / "b").mkdir()
    plain = _server(tmp_path / "b")
    assert "--autopilot-workers" not in plain._autopilot_argv()
    assert "--no-go-workers" not in plain._autopilot_argv()


# --------------------------------------------------------------------------- #
# Go worker pool (skipped without a Go toolchain)
# --------------------------------------------------------------------------- #
@needs_go
def test_go_pool_matches_python_for_every_kind(tmp_path):
    srv = _server(tmp_path)
    dbs = _host_many(srv, tmp_path, 4)
    for key, _ in dbs:
        srv.backups.backup_database(key)

    items = _inspect_items(srv)
    go = run_jobs(srv.backups, "inspect", items, workers=4, use_go=True)
    py = run_jobs(srv.backups, "inspect", items, workers=4, use_go=False)
    assert go["engine"] == "go", go["log"]
    assert [
        (r["storage_key"], r["status"], r["entry"]["sha"]) for r in go["results"]
    ] == [(r["storage_key"], r["status"], r["entry"]["sha"]) for r in py["results"]]

    vitems = [
        {
            "storage_key": k,
            "timestamps": [m["timestamp"] for m in srv.backups.list_backups(k)],
            "repair": False,
        }
        for k, _ in dbs
    ]
    go = run_jobs(srv.backups, "verify", vitems, workers=4, use_go=True)
    py = run_jobs(srv.backups, "verify", vitems, workers=4, use_go=False)
    assert go["engine"] == "go", go["log"]
    assert [[s["status"] for s in r["sets"]] for r in go["results"]] == [
        [s["status"] for s in r["sets"]] for r in py["results"]
    ]

    def stage_items(tag):
        return [
            {
                "storage_key": k,
                "candidates": [
                    {"timestamp": m["timestamp"], "kind": "exact"}
                    for m in srv.backups.list_backups(k)
                ],
                "dest": str(tmp_path / f"{tag}-{k}.db"),
            }
            for k, _ in dbs
        ]

    go = run_jobs(srv.backups, "stage", stage_items("go"), workers=4, use_go=True)
    py = run_jobs(srv.backups, "stage", stage_items("py"), workers=4, use_go=False)
    assert go["engine"] == "go", go["log"]
    for i, (g, p) in enumerate(zip(go["results"], py["results"])):
        assert g["timestamp"] == p["timestamp"] and g["failures"] == p["failures"]
        assert _rows(Path(g["staged"])) == _rows(Path(p["staged"])) == N_ROWS + 100 * i


@needs_go
def test_go_pool_heals_many_databases(tmp_path):
    srv = _server(tmp_path, autopilot_workers=3)
    dbs = _host_many(srv, tmp_path, 3)
    srv.run_maintenance(tasks=["check", "backup"])
    for _, loc in dbs:
        _truncate_half(loc)
    rep = srv.run_maintenance(tasks=["check", "heal"])
    assert rep["tasks"]["check"]["engine"] == "go"
    assert rep["tasks"]["heal"]["engines"] == {"check": "go", "stage": "go"}
    assert {r["result"] for r in _heal_by_key(rep).values()} == {"restored"}
    for i, (_, loc) in enumerate(dbs):
        assert _rows(loc) == N_ROWS + 100 * i
    assert srv.verify_backups()["engine"] == "go"
