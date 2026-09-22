"""
Continuous, append-only **change log** for a monitored repository.

The FIFO diff database (:mod:`src.monitor.diff_db`) only ever keeps the last
``capacity`` (default 16) change events -- when the ring wraps, the oldest event
is overwritten in place and is gone. That is the intended behaviour for a
"what changed most recently" view, but it means history is lost.

This module is the durable counterpart: **every** change event the monitor ever
records is *also* appended here and never deleted, so when the 16-deep ring
recycles a slot the evicted change still lives on in the change log. It is a
strict superset of the FIFO -- nothing is thrown away.

Because it is built on :class:`src.monitor.store.SqlStore`, the change log can
live in a local SQLite file (the zero-config default) **or on any remote SQL
server** (PostgreSQL / MySQL) by passing a connection URL. The schema and every
statement are dialect-portable (see :mod:`src.monitor.store`).

Import-time contract: only the standard library and the sibling ``store`` module
are imported here; the remote drivers load lazily inside ``store``.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from datetime import timezone as _tz
from typing import Any, Dict, List, Optional, Sequence

from .store import SqlStore, describe_target, open_store

_TABLE = "change_log"

# Columns of a change-log row, in insert order. ``id`` is the surrogate PK and is
# added separately (its type is dialect-specific). Everything else is portable.
_COLUMNS = (
    "repo",
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
    "recorded_at",
    "recorded_epoch",
)


def _now() -> "tuple[str, float]":
    epoch = time.time()
    return datetime.fromtimestamp(epoch, _tz.utc).isoformat(), epoch


class ChangeLogStore:
    """Durable append-only archive of all monitor change events.

    Parameters
    ----------
    repo:
        Identifier for the repository these changes belong to (its resolved path).
        Stored on every row so one remote database can hold many repositories.
    url:
        Optional connection URL for a remote server
        (``postgresql://...`` / ``mysql://...``). When omitted, ``default_path``
        (a local SQLite file) is used.
    default_path:
        Local SQLite path used when ``url`` is not given.
    """

    def __init__(
        self,
        repo: str,
        url: Optional[str] = None,
        default_path: Optional[str] = None,
    ):
        self.repo = str(repo)
        self.url = url
        self.default_path = default_path
        self.dialect, self.display = describe_target(url, default_path)
        self._store: Optional[SqlStore] = None

    # -- lifecycle ------------------------------------------------------
    def initialize(self) -> "ChangeLogStore":
        store = open_store(self.url, self.default_path)
        pk = store.pk_autoinc()
        cols = f"id {pk}, " + ", ".join(self._column_ddl())
        store.ensure_table(_TABLE, cols)
        store.ensure_index("ix_change_log_repo_seq", _TABLE, "repo, seq")
        store.ensure_index("ix_change_log_repo_path", _TABLE, "repo, rel_path")
        store.ensure_index("ix_change_log_recorded", _TABLE, "repo, recorded_epoch")
        self._store = store
        return self

    def _column_ddl(self) -> List[str]:
        # Portable types across sqlite / postgres / mysql. TEXT + BIGINT +
        # DOUBLE PRECISION are accepted by all three (sqlite is typeless anyway).
        real = "DOUBLE PRECISION" if self.dialect != "sqlite" else "REAL"
        big = "BIGINT" if self.dialect != "sqlite" else "INTEGER"
        return [
            "repo TEXT NOT NULL",
            f"seq {big}",
            f"batch_id {big}",
            "ts TEXT",
            f"epoch {real}",
            "rel_path TEXT NOT NULL",
            "abs_path TEXT",
            "change_type TEXT NOT NULL",
            "analyzer_class TEXT",
            "old_hash TEXT",
            "new_hash TEXT",
            f"old_size {big}",
            f"new_size {big}",
            f"is_binary {big} DEFAULT 0",
            f"lines_added {big} DEFAULT 0",
            f"lines_removed {big} DEFAULT 0",
            "diff_snippet TEXT",
            "update_status TEXT",
            "update_summary TEXT",
            "detail TEXT",
            "recorded_at TEXT",
            f"recorded_epoch {real}",
        ]

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None

    def __enter__(self) -> "ChangeLogStore":
        return self.initialize()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _require(self) -> SqlStore:
        if self._store is None:
            raise RuntimeError("ChangeLogStore.initialize() has not been called")
        return self._store

    # -- writes ---------------------------------------------------------
    def append_events(self, events: Sequence[Dict[str, Any]]) -> int:
        """Append change events to the durable log. Returns the count written.

        Each event dict uses the same field names as
        :meth:`ChangeDiffDatabase.record_events` plus (optionally) ``seq`` and the
        final ``update_status`` / ``update_summary`` / ``detail`` produced after
        re-analysis. Anything missing is stored as NULL / 0.
        """
        if not events:
            return 0
        store = self._require()
        recorded_at, recorded_epoch = _now()
        rows: List[List[Any]] = []
        for ev in events:
            summary = ev.get("update_summary")
            if isinstance(summary, (dict, list)):
                summary = json.dumps(summary)
            rows.append(
                [
                    self.repo,
                    ev.get("seq"),
                    ev.get("batch_id"),
                    ev.get("ts"),
                    ev.get("epoch"),
                    ev["rel_path"],
                    ev.get("abs_path"),
                    ev["change_type"],
                    ev.get("analyzer_class"),
                    ev.get("old_hash"),
                    ev.get("new_hash"),
                    ev.get("old_size"),
                    ev.get("new_size"),
                    1 if ev.get("is_binary") else 0,
                    int(ev.get("lines_added") or 0),
                    int(ev.get("lines_removed") or 0),
                    ev.get("diff_snippet"),
                    ev.get("update_status"),
                    summary,
                    ev.get("detail"),
                    recorded_at,
                    recorded_epoch,
                ]
            )
        store.insert_many(_TABLE, _COLUMNS, rows)
        return len(rows)

    # -- reads ----------------------------------------------------------
    def count(self) -> int:
        row = self._require().query_one(
            f"SELECT COUNT(*) AS n FROM {_TABLE} WHERE repo = ?", (self.repo,)
        )
        return int(row["n"]) if row else 0

    def recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Most-recent-first slice of the durable log for this repo."""
        return self._require().query(
            f"SELECT * FROM {_TABLE} WHERE repo = ? "
            "ORDER BY recorded_epoch DESC, id DESC LIMIT ?",
            (self.repo, max(1, int(limit))),
        )

    def history_for_path(self, rel_path: str, limit: int = 50) -> List[Dict[str, Any]]:
        return self._require().query(
            f"SELECT * FROM {_TABLE} WHERE repo = ? AND rel_path = ? "
            "ORDER BY recorded_epoch DESC, id DESC LIMIT ?",
            (self.repo, rel_path, max(1, int(limit))),
        )
