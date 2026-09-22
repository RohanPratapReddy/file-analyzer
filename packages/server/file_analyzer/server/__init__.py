"""
``file_analyzer.server`` -- the database-hosting server and its client.

This subpackage is the *hosting* half of the server split (the MCP/agent
transport half stays in ``mcp_server`` / :class:`FileAnalyzerMCPServer`). It
stands up a real, detachable, multi-instance server that hosts a repo-session's
databases under the ``PROJECT_ROOT-{session-token}-{db_name}`` convention in
SQLite or Postgres/MySQL, coordinates parallel instances through a shared
session catalog (with token reuse), runs periodic chunked rotating backups, can
surface the backend Postgres logs, and serves a token-authenticated HTTP control
plane that a :class:`ServerClient` connects to.

Everything here is import-safe on a bare interpreter: only the standard library
is imported at module load; the optional Postgres/MySQL drivers are imported
lazily by :class:`~file_analyzer.store.SqlStore` when a remote backend is
actually used.

References consulted for the implementation (best-practice grounding):

* SQLite online backup API (``Connection.backup(pages=...)``) --
  https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup
* ``secrets`` for session tokens --
  https://docs.python.org/3/library/secrets.html
* Cross-platform file locking (fcntl/msvcrt) --
  https://dev.to/susumun/cross-platform-file-locking-in-python-fcntl-vs-msvcrt-from-scratch-19c5
* PostgreSQL logging / ``logging_collector`` / ``log_directory`` --
  https://www.postgresql.org/docs/current/runtime-config-logging.html
* ``pg_dump`` custom-format backups --
  https://www.postgresql.org/docs/current/app-pgdump.html
"""

from __future__ import annotations

from ..client import ServerClient, ServerError
from ..naming import sqlite_db_path, storage_key
from ..tokens import new_session_token, project_fingerprint, project_slug
from .backup import BackupManager
from .catalog import SessionCatalog, default_catalog_dir
from .daemon import pid_alive, spawn_detached, stop_pid
from .dbhost import DatabaseHost, HostedDatabase
from .pglog import PostgresLogTailer
from .sdk import FileAnalyzerServer
from .server import DatabaseServer

__all__ = [
    "DatabaseServer",
    "FileAnalyzerServer",
    "ServerClient",
    "ServerError",
    "SessionCatalog",
    "DatabaseHost",
    "HostedDatabase",
    "BackupManager",
    "PostgresLogTailer",
    "default_catalog_dir",
    "storage_key",
    "sqlite_db_path",
    "new_session_token",
    "project_fingerprint",
    "project_slug",
    "pid_alive",
    "spawn_detached",
    "stop_pid",
]
