"""
PostgreSQL server-log discovery and tailing.

When the hosting server runs on a Postgres backend it can surface the Postgres
server's own logs ("it also shows server postgres logs"). Postgres writes logs to
files only when ``logging_collector`` is on; the file location is
``log_directory`` (absolute, or relative to the cluster ``data_directory``) and
the file names follow the ``log_filename`` strftime pattern. This module reads
those settings over a normal connection and tails the newest matching file.

If ``logging_collector`` is off, logs are going to the server's stderr (typically
captured by the init system, e.g. journald/syslog) and cannot be tailed from a
file; :meth:`PostgresLogTailer.tail` reports that clearly instead of guessing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from ..store import SqlStore, resolve_dialect


class PostgresLogTailer:
    """Locate and tail a Postgres cluster's log files via its own settings."""

    def __init__(self, database_url: str) -> None:
        if resolve_dialect(database_url) != "postgresql":
            raise ValueError("PostgresLogTailer requires a postgresql:// URL")
        self.url = database_url

    # -- settings -------------------------------------------------------
    def _show(self, store: SqlStore, name: str) -> Optional[str]:
        try:
            row = store.query_one(f"SHOW {name}")
        except Exception:
            return None
        if not row:
            return None
        # SHOW returns a single column named after the setting.
        return next(iter(row.values()), None)

    def settings(self) -> Dict[str, Any]:
        """Return the log-relevant server settings + resolved log directory."""
        store = SqlStore(self.url).connect()
        try:
            data_dir = self._show(store, "data_directory")
            log_dir = self._show(store, "log_directory")
            collector = self._show(store, "logging_collector")
            filename = self._show(store, "log_filename")
            destination = self._show(store, "log_destination")
        finally:
            store.close()
        resolved = None
        if log_dir:
            p = Path(log_dir)
            if not p.is_absolute() and data_dir:
                p = Path(data_dir) / log_dir
            resolved = str(p)
        return {
            "data_directory": data_dir,
            "log_directory": log_dir,
            "resolved_log_directory": resolved,
            "logging_collector": collector,
            "log_filename": filename,
            "log_destination": destination,
        }

    def current_log_file(self) -> Optional[Path]:
        """The most recently modified log file in the resolved log directory."""
        cfg = self.settings()
        resolved = cfg.get("resolved_log_directory")
        if not resolved:
            return None
        d = Path(resolved)
        if not d.is_dir():
            return None
        candidates = [f for f in d.iterdir() if f.is_file()]
        if not candidates:
            return None
        return max(candidates, key=lambda f: f.stat().st_mtime)

    def tail(self, lines: int = 100) -> Dict[str, Any]:
        """Return the last ``lines`` lines of the current log file (or a reason).

        The result always carries the discovered ``settings``; when a file is
        readable it also has ``file`` and ``lines`` (a list of strings), and when
        it is not it carries a ``message`` explaining why (collector off, no file,
        unreadable directory).
        """
        cfg = self.settings()
        collector = (cfg.get("logging_collector") or "").lower()
        if collector in ("off", "false", "0", "no"):
            return {
                "settings": cfg,
                "message": (
                    "logging_collector is off; PostgreSQL is logging to stderr "
                    "(captured by the init system, e.g. journald/syslog), so there "
                    "is no log file to tail. Enable logging_collector to collect "
                    "logs into files under log_directory."
                ),
                "lines": [],
            }
        target = self.current_log_file()
        if target is None:
            return {
                "settings": cfg,
                "message": (
                    "no readable log file was found in the resolved log_directory; "
                    "the directory may be on the database host and not visible from "
                    "here, or no logs have been written yet."
                ),
                "lines": [],
            }
        return {
            "settings": cfg,
            "file": str(target),
            "lines": _tail_lines(target, lines),
        }


def _tail_lines(path: Path, lines: int) -> List[str]:
    """Read the last ``lines`` lines of a file without loading it all in memory."""
    lines = max(1, int(lines))
    block = 8192
    data = b""
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        pos = size
        while pos > 0 and data.count(b"\n") <= lines:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step) + data
    text = data.decode("utf-8", "replace")
    return text.splitlines()[-lines:]
