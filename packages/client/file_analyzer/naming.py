"""
Storage naming for hosted databases.

Every database the server hosts is stored under the convention the user asked
for::

    PROJECT_ROOT-{server-session-token}-{db_name}

where ``PROJECT_ROOT`` is the human-readable, collision-free project slug
(:func:`file_analyzer.server.tokens.project_slug`), ``session-token`` is the
repo-session token, and ``db_name`` is the logical database name (``repository``,
``unified``, ``enrichment``, ``changes``, ``sessions``, ...).

For the **SQLite** backend the storage key becomes a filename
(``<storage_key>.db``) under the host's data directory; for the **Postgres /
MySQL** backend it becomes the primary key that ties a hosted database's manifest
row to its content chunks. Either way the naming is deterministic, so any server
instance can compute the same key for the same ``(root, token, db_name)`` triple
without consulting the catalog.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from .tokens import PathLike, project_slug, sanitize_db_name


def storage_key(root: PathLike, session_token: str, db_name: str) -> str:
    """Return ``PROJECT_ROOT-{session-token}-{db_name}`` as one storage token."""
    return f"{project_slug(root)}-{session_token}-{sanitize_db_name(db_name)}"


def sqlite_db_path(
    data_dir: PathLike, root: PathLike, session_token: str, db_name: str
) -> Path:
    """Absolute path of a hosted SQLite database file for the SQLite backend."""
    return Path(data_dir) / f"{storage_key(root, session_token, db_name)}.db"


def parse_storage_key(key: str) -> Union[dict, None]:
    """Best-effort split of a storage key back into its parts.

    Returns ``{"project": ..., "token": ..., "db_name": ...}`` or ``None`` if the
    key does not have the expected three-part shape. The token is the middle
    component; because the project slug and db name can themselves contain
    hyphens, this is heuristic and intended for display/diagnostics only -- the
    catalog is the source of truth for the exact mapping.
    """
    parts = key.split("-")
    if len(parts) < 3:
        return None
    return {"project": parts[0], "token": parts[-2], "db_name": parts[-1]}
