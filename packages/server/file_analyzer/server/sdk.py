"""
file_analyzer.server.sdk -- object-oriented facade over the hosting server.

``FileAnalyzerServer`` is the high-level, database-*hosting* SDK class. It ships
in the ``file-analyzer-server`` wheel because it drives
:class:`file_analyzer.server.DatabaseServer`; it connects out through the
:class:`~file_analyzer.client.ServerClient` from the (required) client wheel.

Like the rest of the SDK it is a thin-but-real facade -- every method delegates
to the concrete server machinery, and heavy imports stay lazy so importing this
module never stands up a server or touches a backend driver.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .._version import __version__

__all__ = ["FileAnalyzerServer"]

PathLike = Union[str, Path]


class FileAnalyzerServer:
    """Object-oriented control of the database-**hosting** server.

    Where the MCP server (``FileAnalyzerMCPServer``, engine wheel) speaks the
    agent/transport protocol that *builds* databases, this class *hosts* them: it
    resolves (or reuses) a session token for a repository, stores every database
    under ``PROJECT_ROOT-{token}-{db_name}`` in SQLite or Postgres/MySQL, serves a
    token-authenticated HTTP control plane that clients connect to, persists
    **detached with a PID** once started, and runs periodic chunked rotating
    backups. Parallel instances on the same repository share one token (no
    duplicate database copies).

    All of this is delegated to :class:`file_analyzer.server.DatabaseServer` and
    :class:`file_analyzer.client.ServerClient`; the modules are imported lazily so
    ``import file_analyzer.server`` stays cheap and bare-metal-safe.

    Typical use::

        srv = FileAnalyzerServer("/repo", backend="sqlite")
        info = srv.start(detach=True)      # background, returns {url, token, pid}
        srv.host_database("repository.db", "repository")
        client = srv.connect()             # a ServerClient bound to url + token
        client.query(srv.storage_key_for("repository"),
                     "SELECT * FROM v_file_inventory")
        srv.stop()
    """

    def __init__(self, path: PathLike = ".", **kwargs: Any) -> None:
        self._path = path
        self._kwargs = kwargs
        self._server: Any = None  # lazily built DatabaseServer

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"FileAnalyzerServer(root={str(self._path)!r})"

    def _srv(self) -> Any:
        if self._server is None:
            from .server import DatabaseServer

            self._server = DatabaseServer(self._path, **self._kwargs)
        return self._server

    # -- identity ----------------------------------------------------
    @property
    def version(self) -> str:
        return __version__

    @property
    def token(self) -> str:
        """The (reused-or-minted) session token for this repository."""
        return self._srv().token

    @property
    def url(self) -> str:
        """The control-plane URL (valid once the server is bound)."""
        return self._srv().url

    def storage_key_for(self, db_name: str) -> str:
        """The ``PROJECT_ROOT-{token}-{db_name}`` key a database is stored under."""
        return self._srv().storage_key_for(db_name)

    # -- lifecycle ---------------------------------------------------
    def start(self, *, detach: bool = True, contained: bool = True) -> Any:
        """Start the server.

        With ``detach=True`` (default) it is launched as a background process that
        persists with a PID and this call returns its endpoint info
        (``{server_id, pid, url, token, ...}``). With ``detach=False`` it serves in
        the foreground and blocks until stopped (honoring the containment guard
        unless ``contained=False``).
        """
        if detach:
            return self._srv().start_detached()
        return self._srv().serve(contained=contained)

    def serve(self, *, contained: bool = True) -> int:
        """Serve in the foreground until stopped (blocks). Returns an exit code."""
        return self._srv().serve(contained=contained)

    def stop(self, *, all_for_repo: bool = False, timeout: float = 10.0) -> Any:
        """Stop this server by PID (or every server hosting this repo)."""
        return self._srv().stop(all_for_repo=all_for_repo, timeout=timeout)

    def status(self) -> Dict[str, Any]:
        """Live status: running servers for this repo + hosted databases."""
        return self._srv().status()

    # -- hosting -----------------------------------------------------
    def host_database(self, source_db_path: PathLike, db_name: str) -> Dict[str, Any]:
        """Store a database file under this session; return its catalog record."""
        return self._srv().host_database(source_db_path, db_name)

    def databases(self) -> List[Dict[str, Any]]:
        """List the databases hosted for this session."""
        return self._srv().databases()

    def backup(self, storage_key: Optional[str] = None) -> Any:
        """Run a backup now (one database by key, or all)."""
        srv = self._srv()
        if storage_key:
            return srv.backups.backup_database(storage_key)
        return srv.backups.backup_all()

    def postgres_logs(self, lines: int = 100) -> Dict[str, Any]:
        """Tail the backend Postgres server logs (empty on a SQLite backend)."""
        return self._srv().postgres_logs(lines)

    def servers(self) -> List[Dict[str, Any]]:
        """All live servers hosting this repository (from the shared catalog)."""
        return self._srv().catalog.list_servers(self._srv().root)

    def is_running(self) -> bool:
        """True if at least one live server is hosting this repository."""
        try:
            return bool(self.servers())
        except Exception:  # pragma: no cover - catalog may not exist yet
            return False

    def wait_ready(self, timeout: float = 10.0, interval: float = 0.1) -> bool:
        """Poll the control-plane health endpoint until it answers ``ok``.

        Useful right after :meth:`start` with ``detach=True``: the launcher
        returns before the child has bound its socket. Returns ``True`` once the
        server reports healthy, ``False`` if ``timeout`` elapses first.
        """
        import time

        deadline = time.monotonic() + max(0.0, timeout)
        client = self.connect()
        while True:
            try:
                if client.health().get("status") == "ok":
                    return True
            except Exception:
                pass
            if time.monotonic() >= deadline:
                return False
            time.sleep(interval)

    # -- client entrypoint -------------------------------------------
    def connect(self, url: Optional[str] = None, token: Optional[str] = None) -> Any:
        """Return a :class:`ServerClient` bound to this server (the entrypoint).

        Defaults to this server's own URL and session token; pass ``url`` /
        ``token`` to connect to a different (e.g. remote) instance.
        """
        from ..client import ServerClient

        return ServerClient(url or self.url, token or self.token)

    @staticmethod
    def client(url: str, token: Optional[str] = None) -> Any:
        """Build a bare :class:`ServerClient` for an already-running server."""
        from ..client import ServerClient

        return ServerClient(url, token)
