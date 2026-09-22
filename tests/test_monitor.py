"""
Functional tests for the background repository monitor (file_analyzer/monitor/).

Everything here runs on a bare interpreter (pure stdlib + the pure-stdlib analyzer
core), so it matches the CI runner, which installs only ``.[agent]``. The tests
cover the load-bearing contracts:

* the diff database is a FIFO ring buffer capped at ``capacity`` (default 16);
* the scanner detects created / modified / deleted files by content;
* :meth:`RepositoryMonitor.scan_once` records changes AND re-analyzes changed
  files inline with the correct analyzer;
* the update engine routes a file to the same analyzer the full pipeline would;
* the worker pool's Python fallback fans a change set out across subprocesses and
  returns real per-file results.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make ``import file_analyzer`` resolve when pytest is run from the repo root.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from file_analyzer.monitor.diff_db import ChangeDiffDatabase  # noqa: E402
from file_analyzer.monitor.incremental import IncrementalUpdateEngine  # noqa: E402
from file_analyzer.monitor.monitor import RepositoryMonitor  # noqa: E402
from file_analyzer.monitor.pool import (  # noqa: E402
    UpdateWorkerPool,
    _clamp_workers,
    _partition,
)
from file_analyzer.monitor.scanner import Scanner  # noqa: E402


# --------------------------------------------------------------------------- #
# Diff database: FIFO ring buffer
# --------------------------------------------------------------------------- #
def _event(rel, ctype="modified"):
    return {
        "rel_path": rel,
        "abs_path": f"/repo/{rel}",
        "change_type": ctype,
        "new_hash": "h" + rel,
        "new_size": 10,
        "is_binary": False,
        "lines_added": 1,
        "lines_removed": 0,
    }


def test_diff_db_fifo_wraps_at_capacity(tmp_path):
    db = ChangeDiffDatabase(str(tmp_path / "changes.db"), capacity=4).initialize()
    try:
        # Record 10 events one per batch; only the last 4 must survive.
        for i in range(10):
            bid = db.begin_batch()
            db.record_events(bid, [_event(f"f{i}.py")])
            db.finalize_batch(bid, created=0, modified=1, deleted=0)

        rows = db.recent_changes()
        assert len(rows) == 4, "ring buffer must retain exactly `capacity` events"
        # Newest first, and they are the last 4 recorded (seq 7..10).
        seqs = [r["seq"] for r in rows]
        assert seqs == [10, 9, 8, 7]
        rels = [r["rel_path"] for r in rows]
        assert rels == ["f9.py", "f8.py", "f7.py", "f6.py"]

        # Total change count is cumulative across the whole run, not the buffer.
        assert db.summary()["total_changes"] == 10
        assert db.summary()["buffered_events"] == 4
    finally:
        db.close()


def test_diff_db_update_event_result_and_recycle(tmp_path):
    db = ChangeDiffDatabase(str(tmp_path / "c.db"), capacity=2).initialize()
    try:
        bid = db.begin_batch()
        seqs = db.record_events(bid, [_event("a.py"), _event("b.py")])
        db.finalize_batch(bid, created=0, modified=2, deleted=0)
        db.update_event_result(seqs[0], "reanalyzed", {"tables": {"t": 3}})
        rows = {r["seq"]: r for r in db.recent_changes()}
        assert rows[seqs[0]]["update_status"] == "reanalyzed"

        # Push the first event out of the 2-deep ring; patching it is a safe no-op.
        bid2 = db.begin_batch()
        db.record_events(bid2, [_event("c.py"), _event("d.py")])
        db.finalize_batch(bid2, created=0, modified=2, deleted=0)
        db.update_event_result(seqs[0], "reanalyzed")  # recycled slot -> no error
        assert seqs[0] not in {r["seq"] for r in db.recent_changes()}
    finally:
        db.close()


def test_diff_db_empty_batch_consumes_no_slot(tmp_path):
    db = ChangeDiffDatabase(str(tmp_path / "c.db"), capacity=4).initialize()
    try:
        bid = db.begin_batch()
        db.finalize_batch(bid, created=0, modified=0, deleted=0)
        assert db.recent_batches() == []
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Scanner: content-based change detection
# --------------------------------------------------------------------------- #
def test_scanner_detects_created_modified_deleted(tmp_path):
    (tmp_path / "keep.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "gone.txt").write_text("bye\n", encoding="utf-8")
    scanner = Scanner(tmp_path)
    snap1 = scanner.snapshot()
    assert set(snap1) == {"keep.py", "gone.txt"}

    (tmp_path / "new.md").write_text("# hi\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("print(1)\nprint(2)\n", encoding="utf-8")
    (tmp_path / "gone.txt").unlink()
    snap2 = scanner.snapshot()

    events = {e["rel_path"]: e for e in scanner.diff(snap1, snap2)}
    assert events["new.md"]["change_type"] == "created"
    assert events["keep.py"]["change_type"] == "modified"
    assert events["keep.py"]["lines_added"] == 1
    assert (
        events["keep.py"]["diff_snippet"]
        and "print(2)" in events["keep.py"]["diff_snippet"]
    )
    assert events["gone.txt"]["change_type"] == "deleted"


def test_scanner_ignores_dot_dirs_and_globs(tmp_path):
    (tmp_path / ".file-analyzer").mkdir()
    (tmp_path / ".file-analyzer" / "changes.db").write_text("x", encoding="utf-8")
    (tmp_path / "a.pyc").write_text("x", encoding="utf-8")
    (tmp_path / "real.py").write_text("x=1\n", encoding="utf-8")
    snap = Scanner(tmp_path).snapshot()
    assert set(snap) == {"real.py"}


# --------------------------------------------------------------------------- #
# Pool sizing helpers
# --------------------------------------------------------------------------- #
def test_clamp_workers_envelope():
    assert _clamp_workers(0, 16, 128) == 0
    assert _clamp_workers(1, 16, 128) == 1  # never more than one per file
    assert _clamp_workers(5, 16, 128) == 5
    assert _clamp_workers(50, 16, 128) == 50
    assert _clamp_workers(500, 16, 128) == 128  # ceiling
    assert _clamp_workers(20, 16, 128) == 20  # at/above the floor


def test_partition_round_robin():
    parts = _partition(["a", "b", "c", "d", "e"], 2)
    assert parts == [["a", "c", "e"], ["b", "d"]]
    assert _partition(["a"], 1) == [["a"]]
    assert _partition([], 4) == []


# --------------------------------------------------------------------------- #
# Incremental update engine: real re-analysis + routing
# --------------------------------------------------------------------------- #
def test_incremental_reanalyzes_a_python_file(tmp_path):
    f = tmp_path / "mod.py"
    f.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    eng = IncrementalUpdateEngine(readers_root=str(_ROOT))
    assert eng.resolve_class(str(f)) == "code"
    res = eng.analyze_file(str(f))
    assert res["status"] == "reanalyzed", res
    assert res["analyzer_class"] == "code"
    assert res["summary"]["total_rows"] >= 1


def test_incremental_missing_and_skipped(tmp_path):
    eng = IncrementalUpdateEngine(readers_root=str(_ROOT))
    missing = eng.analyze_file(str(tmp_path / "nope.py"))
    assert missing["status"] == "missing"


# --------------------------------------------------------------------------- #
# Worker pool: Python fallback fans out across real subprocesses
# --------------------------------------------------------------------------- #
def test_worker_pool_python_fallback(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    files = []
    for i in range(4):
        p = repo / f"m{i}.py"
        p.write_text(f"x{i} = {i}\n", encoding="utf-8")
        files.append(str(p))

    pool = UpdateWorkerPool(
        readers_root=_ROOT,
        out_dir=tmp_path / "pool",
        min_workers=2,
        max_workers=4,
        use_go=False,  # force the concurrent.futures fallback
    )
    outcome = pool.analyze(files)
    assert outcome["engine"] == "python"
    assert outcome["returncode"] == 0, "\n".join(pool.log)
    statuses = {Path(r["path"]).name: r["status"] for r in outcome["results"]}
    assert len(statuses) == 4
    assert all(s == "reanalyzed" for s in statuses.values()), statuses


# --------------------------------------------------------------------------- #
# End-to-end: RepositoryMonitor.scan_once
# --------------------------------------------------------------------------- #
def test_monitor_scan_once_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")

    mon = RepositoryMonitor(
        repo,
        out_dir=tmp_path / "artifacts",
        interval=0.2,
        capacity=8,
        use_go=False,
        inline_threshold=16,  # analyze inline, no subprocess needed
    )
    mon.initialize()
    try:
        # No changes since the baseline snapshot.
        assert mon.scan_once()["changes"] == 0

        # Create + modify -> both detected, recorded and re-analyzed.
        (repo / "b.py").write_text("def f():\n    return 2\n", encoding="utf-8")
        (repo / "a.py").write_text("a = 1\nb = 2\n", encoding="utf-8")
        summary = mon.scan_once()
        assert summary["created"] == 1
        assert summary["modified"] == 1
        assert summary["engine"] == "inline"

        changes = {c["rel_path"]: c for c in mon.recent_changes()}
        assert changes["b.py"]["change_type"] == "created"
        assert changes["b.py"]["analyzer_class"] == "code"
        assert changes["b.py"]["update_status"] == "reanalyzed"
        assert changes["a.py"]["update_status"] == "reanalyzed"

        # Delete -> recorded as deleted, dropped from the live index.
        (repo / "a.py").unlink()
        summary = mon.scan_once()
        assert summary["deleted"] == 1
        latest = mon.recent_changes(limit=1)[0]
        assert latest["rel_path"] == "a.py"
        assert latest["change_type"] == "deleted"
        assert latest["update_status"] == "deleted"
    finally:
        mon.close()


def test_monitor_rejects_non_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        RepositoryMonitor(f)
