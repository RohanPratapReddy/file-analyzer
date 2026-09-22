"""
Repository monitoring + incremental-update layer.

An always-on background layer that watches a repository and keeps a rolling,
16-deep FIFO record of what changed (created / modified / deleted), re-analyzing
each changed file with the correct analyzer as it happens -- concurrently, across
a Go worker pool (with a pure-Python fallback) for large change sets.

Public API::

    from file_analyzer.monitor import RepositoryMonitor, ChangeDiffDatabase
    mon = RepositoryMonitor("/path/to/repo").start()   # daemon-thread mode
    mon.scan_once()                                     # or drive it manually
    mon.recent_changes()                                # last 16 change events
    mon.stop()

or as a standalone process (see ``file_analyzer/__main__.py``)::

    python -m file_analyzer monitor /path/to/repo --interval 2

The heavy analyzer fleet is imported lazily (only when a changed file is actually
re-analyzed), so importing this package is cheap.
"""

from ..store import SqlStore, open_store
from .change_log import ChangeLogStore
from .control import (
    assess_last_session,
    get_monitor,
    list_monitors,
    read_change_log,
    read_recent_changes,
    read_sessions,
    read_status,
    record_session,
    start_monitor,
    stop_all,
    stop_monitor,
)
from .diff_db import DEFAULT_CAPACITY, ChangeDiffDatabase, connect_readonly
from .incremental import IncrementalUpdateEngine
from .monitor import RepositoryMonitor
from .pool import UpdateWorkerPool
from .scanner import Scanner
from .session_log import SessionSummaryStore, classify_sentiment

__all__ = [
    "RepositoryMonitor",
    "ChangeDiffDatabase",
    "connect_readonly",
    "DEFAULT_CAPACITY",
    "IncrementalUpdateEngine",
    "UpdateWorkerPool",
    "Scanner",
    "ChangeLogStore",
    "SessionSummaryStore",
    "classify_sentiment",
    "SqlStore",
    "open_store",
    "start_monitor",
    "stop_monitor",
    "stop_all",
    "get_monitor",
    "list_monitors",
    "read_recent_changes",
    "read_status",
    "read_change_log",
    "read_sessions",
    "record_session",
    "assess_last_session",
]
