"""
Functional tests for the durable dumps added on top of the FIFO monitor:

* the cross-dialect :class:`SqlStore` (local SQLite path/URL handling);
* the continuous :class:`ChangeLogStore` -- a strict superset of the 16-deep FIFO
  ring, so a change evicted from the ring still lives in the log;
* the :class:`SessionSummaryStore` + the deterministic :func:`classify_sentiment`
  lexicon classifier (satisfied / dissatisfied / annoyed / confused / neutral),
  including the "assess the previous session from the next prompt" flow;
* end-to-end: :class:`RepositoryMonitor` keeps only ``capacity`` events in the
  FIFO but archives every change in the durable log.

Everything runs on a bare interpreter (pure stdlib), matching the CI runner.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make ``import file_analyzer`` resolve when pytest is run from the repo root.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from file_analyzer.monitor.change_log import ChangeLogStore  # noqa: E402
from file_analyzer.monitor.monitor import RepositoryMonitor  # noqa: E402
from file_analyzer.monitor.session_log import (  # noqa: E402
    SessionSummaryStore,
    classify_sentiment,
)
from file_analyzer.store import (  # noqa: E402
    DIALECT_MYSQL,
    DIALECT_POSTGRES,
    DIALECT_SQLITE,
    SqlStore,
    resolve_dialect,
)


# --------------------------------------------------------------------------- #
# SqlStore: dialect resolution + local SQLite round-trip
# --------------------------------------------------------------------------- #
def test_resolve_dialect_distinguishes_urls_from_paths():
    assert resolve_dialect("D:\\repo\\x.db") == DIALECT_SQLITE  # windows path
    assert resolve_dialect("/var/lib/x.db") == DIALECT_SQLITE
    assert resolve_dialect("x.db") == DIALECT_SQLITE
    assert resolve_dialect("sqlite:///tmp/x.db") == DIALECT_SQLITE
    assert resolve_dialect("postgresql://u:p@h:5432/db") == DIALECT_POSTGRES
    assert resolve_dialect("postgres://u@h/db") == DIALECT_POSTGRES
    assert resolve_dialect("mysql://u:p@h:3306/db") == DIALECT_MYSQL
    assert resolve_dialect("mariadb://h/db") == DIALECT_MYSQL


def test_sqlstore_sqlite_roundtrip(tmp_path):
    store = SqlStore(str(tmp_path / "s.db")).connect()
    try:
        store.ensure_table("t", f"id {store.pk_autoinc()}, name TEXT, n INTEGER")
        store.insert("t", {"name": "a", "n": 1})
        store.insert("t", {"name": "b", "n": 2})
        store.insert_many("t", ("name", "n"), [["c", 3], ["d", 4]])
        rows = store.query("SELECT name, n FROM t ORDER BY n")
        assert [r["name"] for r in rows] == ["a", "b", "c", "d"]
        one = store.query_one("SELECT n FROM t WHERE name = ?", ("c",))
        assert one["n"] == 3
    finally:
        store.close()


# --------------------------------------------------------------------------- #
# ChangeLogStore: durable, append-only, per-repo
# --------------------------------------------------------------------------- #
def _ev(rel, ctype="modified", seq=None, status="reanalyzed"):
    return {
        "rel_path": rel,
        "abs_path": f"/repo/{rel}",
        "change_type": ctype,
        "analyzer_class": "code",
        "new_hash": "h" + rel,
        "new_size": 10,
        "lines_added": 1,
        "lines_removed": 0,
        "seq": seq,
        "batch_id": 1,
        "update_status": status,
        "update_summary": {"tables": {"t": 1}},
    }


def test_change_log_appends_and_reads(tmp_path):
    log = ChangeLogStore(
        repo="/repo", default_path=str(tmp_path / "log.db")
    ).initialize()
    try:
        n = log.append_events([_ev(f"f{i}.py", seq=i) for i in range(1, 6)])
        assert n == 5
        assert log.count() == 5
        recent = log.recent(limit=3)
        assert len(recent) == 3
        assert recent[0]["rel_path"] == "f5.py"  # newest first
        assert recent[0]["update_status"] == "reanalyzed"
        # update_summary is stored as JSON text
        assert '"tables"' in recent[0]["update_summary"]

        hist = log.history_for_path("f2.py")
        assert len(hist) == 1 and hist[0]["rel_path"] == "f2.py"
    finally:
        log.close()


def test_change_log_isolates_repos(tmp_path):
    shared = str(tmp_path / "shared.db")
    a = ChangeLogStore(repo="/repo/a", default_path=shared).initialize()
    b = ChangeLogStore(repo="/repo/b", default_path=shared).initialize()
    try:
        a.append_events([_ev("only_a.py", seq=1)])
        b.append_events([_ev("only_b.py", seq=1), _ev("also_b.py", seq=2)])
        assert a.count() == 1
        assert b.count() == 2
        assert {r["rel_path"] for r in a.recent()} == {"only_a.py"}
    finally:
        a.close()
        b.close()


# --------------------------------------------------------------------------- #
# Sentiment classifier
# --------------------------------------------------------------------------- #
def test_classify_sentiment_labels():
    assert classify_sentiment("perfect, that works now! thank you")[0] == "satisfied"
    assert classify_sentiment("no, it's still broken and wrong")[0] == "dissatisfied"
    assert (
        classify_sentiment("I already told you, that's not what I asked!!")[0]
        == "annoyed"
    )
    assert classify_sentiment("I don't understand what you mean")[0] == "confused"
    assert classify_sentiment("ok, now add a new endpoint for users")[0] == "neutral"
    label, conf, why = classify_sentiment("")
    assert label == "neutral" and conf == 0.0 and "no follow-up" in why


def test_classify_confidence_is_bounded():
    for text in ["perfect!!", "totally broken and failing", "ugh again", ""]:
        _, conf, _ = classify_sentiment(text)
        assert 0.0 <= conf <= 1.0


# --------------------------------------------------------------------------- #
# SessionSummaryStore
# --------------------------------------------------------------------------- #
def test_session_record_and_assess_from_next_prompt(tmp_path):
    store = SessionSummaryStore(
        repo="/repo", default_path=str(tmp_path / "sess.db")
    ).initialize()
    try:
        sid = store.record_session(
            task_given="add a logging db dump",
            work_done="added change_log.py + session_log.py",
            files_changed=[
                "file_analyzer/monitor/change_log.py",
                "file_analyzer/monitor/session_log.py",
            ],
            improvements="Wire remote drivers. Add tests. Verify CI on Linux.",
        )
        row = store.get_session(sid)
        assert row["user_sentiment"] == "pending"  # awaiting next prompt
        assert row["files_changed_count"] == 2

        # The next user prompt is unhappy -> the previous session is assessed.
        updated = store.assess_last_session("no, this is still broken")
        assert updated["session_id"] == sid
        assert updated["user_sentiment"] == "dissatisfied"
        assert updated["next_prompt"] == "no, this is still broken"

        # Now there is no pending session left to assess.
        assert store.assess_last_session("anything") is None
    finally:
        store.close()


def test_session_explicit_sentiment_override(tmp_path):
    store = SessionSummaryStore(
        repo="/repo", default_path=str(tmp_path / "sess.db")
    ).initialize()
    try:
        sid = store.record_session(
            task_given="t",
            work_done="w",
            user_sentiment="satisfied",
        )
        row = store.get_session(sid)
        assert row["user_sentiment"] == "satisfied"
        assert store.count() == 1
    finally:
        store.close()


# --------------------------------------------------------------------------- #
# End-to-end: FIFO ring is capped, durable log keeps everything
# --------------------------------------------------------------------------- #
def test_monitor_change_log_is_superset_of_fifo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("a = 0\n", encoding="utf-8")

    mon = RepositoryMonitor(
        repo,
        out_dir=tmp_path / "artifacts",
        interval=0.2,
        capacity=4,  # tiny FIFO ring
        use_go=False,
        inline_threshold=16,
    )
    mon.initialize()
    try:
        # Ten separate edits -> ten change events across ten scan cycles.
        for i in range(1, 11):
            (repo / "a.py").write_text(f"a = {i}\n", encoding="utf-8")
            summary = mon.scan_once()
            assert summary["changes"] == 1

        # FIFO keeps only the last `capacity` events...
        fifo = mon.recent_changes()
        assert len(fifo) == 4

        # ...but the durable change log kept every single one.
        history = mon.change_history(limit=100)
        assert len(history) == 10
        assert history[0]["change_type"] == "modified"
        assert history[0]["update_status"] == "reanalyzed"
        # Newest-first ordering in the durable log.
        seqs = [h["seq"] for h in history]
        assert seqs == sorted(seqs, reverse=True)
    finally:
        mon.close()
