"""
file_analyzer.client -- the small, dependency-free client surface.

This is the public API of the ``file-analyzer-client`` wheel. It is pure Python
standard library and installs with no analyzer fleet, so it is cheap to put on a
machine that only needs to:

* **connect to a hosted server and run queries** -- :class:`ServerClient` /
  :func:`connect`;
* **read/query a local ``.db`` offline** -- :class:`FileAnalyzerDatabase` /
  :func:`open_database`;
* **optionally run an analysis locally** -- :func:`analyze`, which works only when
  the separate engine wheel (``file-analyzer-engine``) is also installed and
  otherwise raises :class:`EngineNotInstalled` with install instructions.

Whether local analysis is available can be checked ahead of time with
:func:`has_engine`.
"""

from __future__ import annotations

from typing import Optional

from .._version import __version__
from ._engine import EngineNotInstalled, analyze, has_engine
from .database import FileAnalyzerDatabase, PathLike, open_database
from .server_client import ServerClient, ServerError

__all__ = [
    "__version__",
    "FileAnalyzerDatabase",
    "open_database",
    "ServerClient",
    "ServerError",
    "connect",
    "analyze",
    "has_engine",
    "EngineNotInstalled",
    "PathLike",
]


def connect(
    url: str, token: Optional[str] = None, *, timeout: float = 30.0
) -> ServerClient:
    """Return a :class:`ServerClient` bound to a hosted server's control plane.

    ``connect("http://host:8765", token)`` is the quickest way to reach a running
    :class:`~file_analyzer.server.server.DatabaseServer` and run read-only queries
    against the databases it hosts.
    """
    return ServerClient(url, token, timeout=timeout)
