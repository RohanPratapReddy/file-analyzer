"""
Change-diff database for the repository monitor.

The monitor watches a repository and, on every scan cycle, records what changed
(created / modified / deleted files) into a small SQLite database. Two facts
about that database are load-bearing:

* **It is a FIFO ring buffer.** Only the last ``capacity`` (default **16**)
  *consecutive change events* are retained. Event number ``seq`` is written to
  ring slot ``(seq - 1) % capacity``; when ``seq`` wraps past ``capacity`` the
  oldest event is overwritten in place. ``change_batches`` (one row per scan
  cycle) is capped the same way. This is exactly the "show 16 consecutive
  changes, FIFO" contract: the table never grows without bound, and reading it
  ``ORDER BY seq DESC LIMIT capacity`` yields the most recent changes newest
  first.
* **It is concurrent-safe.** The monitor thread writes; MCP tools, the CLI and
  agents read at the same time. The writer opens one connection in WAL mode
  guarded by a lock; readers open their own short-lived read-only connections
  (:func:`connect_readonly`). WAL lets readers proceed without blocking the
  writer.

``file_state`` is *not* part of the FIFO -- it is the live index of the current
on-disk state (path -> hash / size / mtime / analyzer_class), so the monitor can
detect the next change and so a reader can see the current snapshot. It is
authoritative, not historical.

The module imports nothing outside the standard library, so it is safe to import
from ``file_analyzer/__init__.py``'s neighbours and from the fast-start MCP server.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime
from datetime import timezone as _tz
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

DEFAULT_CAPACITY = 16

_SCHEMA = """
CREATE TABLE IF NOT EXISTS monitor_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- FIFO ring of the last <capacity> individual file-change events.
-- slot = (seq - 1) % capacity ; the row at a slot is overwritten when seq wraps.
CREATE TABLE IF NOT EXISTS change_events (
    slot           INTEGER PRIMARY KEY,       -- ring position 0..capacity-1
    seq            INTEGER NOT NULL,          -- monotonic 1-based global sequence
    batch_id       INTEGER,                   -- scan cycle this event belongs to
    ts             TEXT NOT NULL,             -- ISO-8601 UTC
    epoch          REAL NOT NULL,
    rel_path       TEXT NOT NULL,             -- path relative to the repo root
    abs_path       TEXT,
    change_type    TEXT NOT NULL,             -- created | modified | deleted
    analyzer_class TEXT,                      -- resolve_analyzer() result (or NULL)
    old_hash       TEXT,
    new_hash       TEXT,
    old_size       INTEGER,
    new_size       INTEGER,
    is_binary      INTEGER NOT NULL DEFAULT 0,
    lines_added    INTEGER NOT NULL DEFAULT 0,
    lines_removed  INTEGER NOT NULL DEFAULT 0,
    diff_snippet   TEXT,                       -- bounded unified diff (text files)
    update_status  TEXT,                       -- reanalyzed | skipped | error | pending
    update_summary TEXT,                       -- JSON: per-table row counts etc.
    detail         TEXT
);
CREATE INDEX IF NOT EXISTS ix_change_events_seq ON change_events(seq);

-- One row per scan cycle that produced >= 1 change (also FIFO-capped).
CREATE TABLE IF NOT EXISTS change_batches (
    batch_id  INTEGER PRIMARY KEY,           -- monotonic 1-based
    slot      INTEGER NOT NULL,              -- ring position for the FIFO cap
    ts        TEXT NOT NULL,
    epoch     REAL NOT NULL,
    created   INTEGER NOT NULL DEFAULT 0,
    modified  INTEGER NOT NULL DEFAULT 0,
    deleted   INTEGER NOT NULL DEFAULT 0,
    total     INTEGER NOT NULL DEFAULT 0,
    scan_ms   REAL,
    update_ms REAL,
    workers   INTEGER,
    engine    TEXT                            -- go | python | inline
);
CREATE INDEX IF NOT EXISTS ix_change_batches_bid ON change_batches(batch_id);

-- Live index of the current on-disk state (NOT part of the FIFO).
CREATE TABLE IF NOT EXISTS file_state (
    rel_path       TEXT PRIMARY KEY,
    abs_path       TEXT,
    hash           TEXT,
    size           INTEGER,
    mtime          REAL,
    analyzer_class TEXT,
    last_seq       INTEGER,
    updated_ts     TEXT
);
"""

_VIEWS = """
DROP VIEW IF EXISTS v_recent_changes;
CREATE VIEW v_recent_changes AS
    SELECT seq, batch_id, ts, change_type, analyzer_class, rel_path,
           old_size, new_size, lines_added, lines_removed,
           update_status, is_binary
    FROM change_events
    ORDER BY seq DESC;

DROP VIEW IF EXISTS v_change_type_summary;
CREATE VIEW v_change_type_summary AS
    SELECT change_type, COUNT(*) AS events,
           SUM(lines_added) AS lines_added, SUM(lines_removed) AS lines_removed
    FROM change_events
    GROUP BY change_type;

DROP VIEW IF EXISTS v_changes_by_analyzer;
CREATE VIEW v_changes_by_analyzer AS
    SELECT COALESCE(analyzer_class, '(unrouted)') AS analyzer_class,
           COUNT(*) AS events
    FROM change_events
    GROUP BY analyzer_class
    ORDER BY events DESC;

DROP VIEW IF EXISTS v_recent_batches;
CREATE VIEW v_recent_batches AS
    SELECT batch_id, ts, created, modified, deleted, total,
           scan_ms, update_ms, workers, engine
    FROM change_batches
    ORDER BY batch_id DESC;
"""

_EVENT_COLUMNS = (
    "slot",
    "seq",
    "batch_id",
    "ts",
    "epoch",
    "rel_path",
    "abs_path",
    "change_type",
    "analyzer_class",
    "old_hash",
    "new_hash",
    "old_size",
    "new_size",
    "is_binary",
    "lines_added",
    "lines_removed",
    "diff_snippet",
    "update_status",
    "update_summary",
    "detail",
)


def _now() -> "tuple[str, float]":
    epoch = time.time()
    ts = datetime.fromtimestamp(epoch, _tz.utc).isoformat()
    return ts, epoch


def connect_readonly(db_path: str) -> sqlite3.Connection:
    """Open the diff database strictly read-only (for MCP tools / the CLI)."""
    p = Path(db_path)
    if not p.is_file():
        raise FileNotFoundError(f"diff database not found: {db_path}")
    conn = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


class ChangeDiffDatabase:
    """SQLite-backed FIFO buffer of the last ``capacity`` change events.

    The writer is single-threaded (the monitor's scan loop) but guarded by a lock
    so it is safe to call from a signal handler or a stop() on another thread.
    """

    def __init__(self, db_path: str, capacity: int = DEFAULT_CAPACITY):
        self.db_path = str(Path(db_path))
        self.capacity = max(1, int(capacity))
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None

    # -- lifecycle ------------------------------------------------------
    def initialize(self) -> "ChangeDiffDatabase":
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self._conn = sqlite3.connect(
                self.db_path, timeout=30.0, check_same_thread=False
            )
            self._conn.row_factory = sqlite3.Row
            # WAL so readers never block the writer; NORMAL sync is durable enough
            # for a monitor log and much faster than FULL.
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.execute("PRAGMA busy_timeout = 30000")
            self._conn.executescript(_SCHEMA)
            self._conn.executescript(_VIEWS)
            self._conn.commit()
            # Seed persistent counters if this is a fresh database.
            if self._get_meta("seq") is None:
                self._set_meta("seq", "0")
            if self._get_meta("batch_id") is None:
                self._set_meta("batch_id", "0")
            self._set_meta("capacity", str(self.capacity))
            self._conn.commit()
        return self

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                    self._conn.close()
                finally:
                    self._conn = None

    def __enter__(self) -> "ChangeDiffDatabase":
        return self.initialize()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- meta -----------------------------------------------------------
    def _require(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("ChangeDiffDatabase.initialize() has not been called")
        return self._conn

    def _get_meta(self, key: str) -> Optional[str]:
        row = (
            self._require()
            .execute("SELECT value FROM monitor_meta WHERE key = ?", (key,))
            .fetchone()
        )
        return None if row is None else row["value"]

    def _set_meta(self, key: str, value: str) -> None:
        self._require().execute(
            "INSERT INTO monitor_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )

    def set_status(self, **fields: Any) -> None:
        """Merge arbitrary status fields (root, pid, running, interval, ...) into meta."""
        with self._lock:
            for key, value in fields.items():
                self._set_meta(key, "" if value is None else str(value))
            self._require().commit()

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            rows = (
                self._require()
                .execute("SELECT key, value FROM monitor_meta")
                .fetchall()
            )
        return {r["key"]: r["value"] for r in rows}

    # -- batches --------------------------------------------------------
    def begin_batch(self) -> int:
        """Allocate the next batch id (a scan cycle). Returns the new id."""
        with self._lock:
            bid = int(self._get_meta("batch_id") or "0") + 1
            self._set_meta("batch_id", str(bid))
            self._require().commit()
            return bid

    def finalize_batch(
        self,
        batch_id: int,
        created: int,
        modified: int,
        deleted: int,
        scan_ms: Optional[float] = None,
        update_ms: Optional[float] = None,
        workers: Optional[int] = None,
        engine: Optional[str] = None,
    ) -> None:
        total = created + modified + deleted
        if total == 0:
            return  # empty scans do not consume a FIFO slot
        ts, epoch = _now()
        slot = (batch_id - 1) % self.capacity
        with self._lock:
            conn = self._require()
            # REPLACE by slot => overwrite the oldest batch when the ring wraps.
            conn.execute(
                "DELETE FROM change_batches WHERE slot = ? AND batch_id <> ?",
                (slot, batch_id),
            )
            conn.execute(
                "INSERT INTO change_batches(batch_id, slot, ts, epoch, created, "
                "modified, deleted, total, scan_ms, update_ms, workers, engine) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(batch_id) DO UPDATE SET "
                "slot=excluded.slot, ts=excluded.ts, epoch=excluded.epoch, "
                "created=excluded.created, modified=excluded.modified, "
                "deleted=excluded.deleted, total=excluded.total, "
                "scan_ms=excluded.scan_ms, update_ms=excluded.update_ms, "
                "workers=excluded.workers, engine=excluded.engine",
                (
                    batch_id,
                    slot,
                    ts,
                    epoch,
                    created,
                    modified,
                    deleted,
                    total,
                    scan_ms,
                    update_ms,
                    workers,
                    engine,
                ),
            )
            self._set_meta("last_scan_ts", ts)
            self._set_meta("last_batch_total", str(total))
            conn.commit()

    # -- events ---------------------------------------------------------
    def record_events(
        self, batch_id: int, events: Sequence[Dict[str, Any]]
    ) -> List[int]:
        """Append change events to the ring, assigning each the next ``seq``.

        Each event dict may carry: rel_path (required), abs_path, change_type
        (required), analyzer_class, old_hash, new_hash, old_size, new_size,
        is_binary, lines_added, lines_removed, diff_snippet, update_status,
        update_summary (dict -> JSON), detail. Returns the assigned seq numbers.
        """
        if not events:
            return []
        assigned: List[int] = []
        ts, epoch = _now()
        with self._lock:
            conn = self._require()
            seq = int(self._get_meta("seq") or "0")
            for ev in events:
                seq += 1
                slot = (seq - 1) % self.capacity
                summary = ev.get("update_summary")
                if isinstance(summary, (dict, list)):
                    summary = json.dumps(summary)
                row = {
                    "slot": slot,
                    "seq": seq,
                    "batch_id": batch_id,
                    "ts": ev.get("ts", ts),
                    "epoch": ev.get("epoch", epoch),
                    "rel_path": ev["rel_path"],
                    "abs_path": ev.get("abs_path"),
                    "change_type": ev["change_type"],
                    "analyzer_class": ev.get("analyzer_class"),
                    "old_hash": ev.get("old_hash"),
                    "new_hash": ev.get("new_hash"),
                    "old_size": ev.get("old_size"),
                    "new_size": ev.get("new_size"),
                    "is_binary": 1 if ev.get("is_binary") else 0,
                    "lines_added": int(ev.get("lines_added") or 0),
                    "lines_removed": int(ev.get("lines_removed") or 0),
                    "diff_snippet": ev.get("diff_snippet"),
                    "update_status": ev.get("update_status"),
                    "update_summary": summary,
                    "detail": ev.get("detail"),
                }
                placeholders = ",".join("?" for _ in _EVENT_COLUMNS)
                conn.execute(
                    f"INSERT INTO change_events({','.join(_EVENT_COLUMNS)}) "
                    f"VALUES({placeholders}) "
                    "ON CONFLICT(slot) DO UPDATE SET "
                    + ",".join(
                        f"{c}=excluded.{c}" for c in _EVENT_COLUMNS if c != "slot"
                    ),
                    tuple(row[c] for c in _EVENT_COLUMNS),
                )
                assigned.append(seq)
            self._set_meta("seq", str(seq))
            total = int(self._get_meta("change_count") or "0") + len(events)
            self._set_meta("change_count", str(total))
            conn.commit()
        return assigned

    def update_event_result(
        self,
        seq: int,
        update_status: str,
        update_summary: Optional[Any] = None,
        detail: Optional[str] = None,
    ) -> None:
        """Patch the incremental-update outcome onto an already-recorded event.

        No-op if the slot has since been recycled to a newer event (the event has
        already fallen out of the 16-deep FIFO), which is expected and harmless.
        """
        if isinstance(update_summary, (dict, list)):
            update_summary = json.dumps(update_summary)
        slot = (seq - 1) % self.capacity
        with self._lock:
            conn = self._require()
            conn.execute(
                "UPDATE change_events SET update_status = ?, update_summary = ?, "
                "detail = COALESCE(?, detail) WHERE slot = ? AND seq = ?",
                (update_status, update_summary, detail, slot, seq),
            )
            conn.commit()

    # -- file_state (live index) ---------------------------------------
    def load_file_state(self) -> Dict[str, Dict[str, Any]]:
        """Return the persisted current-state index keyed by rel_path."""
        with self._lock:
            rows = (
                self._require()
                .execute(
                    "SELECT rel_path, abs_path, hash, size, mtime, analyzer_class, "
                    "last_seq FROM file_state"
                )
                .fetchall()
            )
        return {
            r["rel_path"]: {
                "abs_path": r["abs_path"],
                "hash": r["hash"],
                "size": r["size"],
                "mtime": r["mtime"],
                "analyzer_class": r["analyzer_class"],
                "last_seq": r["last_seq"],
            }
            for r in rows
        }

    def upsert_file_state(self, rel_path: str, **fields: Any) -> None:
        ts, _ = _now()
        with self._lock:
            conn = self._require()
            conn.execute(
                "INSERT INTO file_state(rel_path, abs_path, hash, size, mtime, "
                "analyzer_class, last_seq, updated_ts) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(rel_path) DO UPDATE SET "
                "abs_path=excluded.abs_path, hash=excluded.hash, size=excluded.size, "
                "mtime=excluded.mtime, analyzer_class=excluded.analyzer_class, "
                "last_seq=excluded.last_seq, updated_ts=excluded.updated_ts",
                (
                    rel_path,
                    fields.get("abs_path"),
                    fields.get("hash"),
                    fields.get("size"),
                    fields.get("mtime"),
                    fields.get("analyzer_class"),
                    fields.get("last_seq"),
                    ts,
                ),
            )
            conn.commit()

    def delete_file_state(self, rel_path: str) -> None:
        with self._lock:
            conn = self._require()
            conn.execute("DELETE FROM file_state WHERE rel_path = ?", (rel_path,))
            conn.commit()

    # -- reads (also usable by anyone via connect_readonly) ------------
    def recent_changes(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        limit = self.capacity if limit is None else max(1, int(limit))
        with self._lock:
            rows = (
                self._require()
                .execute(
                    "SELECT * FROM change_events ORDER BY seq DESC LIMIT ?", (limit,)
                )
                .fetchall()
            )
        return [dict(r) for r in rows]

    def recent_batches(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        limit = self.capacity if limit is None else max(1, int(limit))
        with self._lock:
            rows = (
                self._require()
                .execute(
                    "SELECT * FROM change_batches ORDER BY batch_id DESC LIMIT ?",
                    (limit,),
                )
                .fetchall()
            )
        return [dict(r) for r in rows]

    def summary(self) -> Dict[str, Any]:
        status = self.get_status()
        with self._lock:
            conn = self._require()
            by_type = {
                r["change_type"]: r["events"]
                for r in conn.execute(
                    "SELECT change_type, COUNT(*) AS events FROM change_events "
                    "GROUP BY change_type"
                ).fetchall()
            }
            buffered = conn.execute(
                "SELECT COUNT(*) AS n FROM change_events"
            ).fetchone()["n"]
        return {
            "root": status.get("root"),
            "pid": status.get("pid"),
            "running": status.get("running"),
            "interval": status.get("interval"),
            "capacity": self.capacity,
            "buffered_events": buffered,
            "total_changes": int(status.get("change_count") or "0"),
            "last_scan_ts": status.get("last_scan_ts"),
            "by_change_type": by_type,
        }
