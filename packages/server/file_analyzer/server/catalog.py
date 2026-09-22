"""
The shared session catalog -- coordination layer for parallel servers.

Several :class:`~file_analyzer.server.server.DatabaseServer` instances may run at
once, on the same repo-session or on different ones. To keep them from
conflicting they share a small SQLite catalog (guarded by a
:class:`~file_analyzer.server.locking.FileLock`) that records:

* **sessions** -- one row per repository, mapping its stable fingerprint to a
  single session token. This is what makes *token reuse* work: when a second
  server starts on a repo that already has a token, it adopts the existing token
  instead of minting a new one, so both servers address the exact same hosted
  databases (no duplicate copies);
* **databases** -- one row per hosted database (its storage key, dialect,
  location, size, checksum), so any server or client can enumerate what exists;
* **servers** -- one row per running instance (pid, host, port, backend), with a
  heartbeat, so ``status`` can list live servers and prune dead ones.

The catalog lives under a shared directory (default
``~/.file-analyzer/servers``) so every server on the host sees the same file. The
critical sections (mint-or-reuse a token, register a database, register a server)
are wrapped in the cross-process :class:`FileLock`; on top of that the token
mint uses an insert-or-reselect race guard, so even a remote catalog backend --
or a lock that is only advisory -- still converges on one token per repository.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..store import SqlStore
from ..tokens import PathLike, canonical_root, new_session_token, project_fingerprint
from .daemon import pid_alive
from .locking import FileLock

#: Default shared root for the catalog + SQLite-backend data + backups.
DEFAULT_HOME = Path(
    os.environ.get("FILE_ANALYZER_SERVER_HOME", str(Path.home() / ".file-analyzer"))
)


def default_catalog_dir() -> Path:
    return DEFAULT_HOME / "servers"


class SessionCatalog:
    """A lock-protected, cross-dialect registry of sessions, databases, servers.

    ``catalog_dir`` holds the SQLite catalog + its lock file. Pass ``target`` to
    put the catalog on a remote SQL server instead (so servers across hosts can
    coordinate); the lock file still lives locally and is a best-effort fast path
    -- correctness for token reuse also rests on the insert-or-reselect guard.
    """

    def __init__(
        self,
        catalog_dir: Optional[PathLike] = None,
        *,
        target: Optional[str] = None,
        lock_timeout: float = 30.0,
    ) -> None:
        self.dir = Path(catalog_dir) if catalog_dir else default_catalog_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.target = target or str(self.dir / "catalog.db")
        self.lock_path = self.dir / "catalog.lock"
        self.lock_timeout = float(lock_timeout)
        self._initialized = False

    # -- schema ---------------------------------------------------------
    def _store(self) -> SqlStore:
        return SqlStore(self.target).connect()

    def _ensure_schema(self, store: SqlStore) -> None:
        if self._initialized:
            return
        store.ensure_table(
            "sessions",
            "fingerprint TEXT PRIMARY KEY, project_root TEXT NOT NULL, "
            "token TEXT NOT NULL, backend TEXT, created_at REAL, updated_at REAL",
        )
        store.ensure_table(
            "databases",
            "storage_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, "
            "token TEXT NOT NULL, db_name TEXT NOT NULL, dialect TEXT, "
            "location TEXT, size_bytes INTEGER, sha256 TEXT, "
            "n_chunks INTEGER, updated_at REAL",
        )
        store.ensure_table(
            "servers",
            "server_id TEXT PRIMARY KEY, pid INTEGER, host TEXT, port INTEGER, "
            "backend TEXT, data_dir TEXT, fingerprint TEXT, project_root TEXT, "
            "token TEXT, url TEXT, started_at REAL, heartbeat_at REAL",
        )
        store.ensure_index("ix_databases_token", "databases", "token")
        store.ensure_index("ix_servers_fingerprint", "servers", "fingerprint")
        self._initialized = True

    # -- sessions (token reuse) ----------------------------------------
    def get_or_create_session(
        self, root: PathLike, backend: str = "sqlite"
    ) -> Dict[str, Any]:
        """Return the session for ``root``, minting a token only if none exists.

        The returned dict has ``token``, ``fingerprint``, ``project_root`` and a
        ``created`` flag (``True`` when this call minted the token, ``False`` when
        it adopted an existing one -- i.e. token reuse across parallel servers).
        """
        fp = project_fingerprint(root)
        proot = canonical_root(root)
        now = time.time()
        with FileLock(self.lock_path, timeout=self.lock_timeout):
            store = self._store()
            try:
                self._ensure_schema(store)
                existing = store.query_one(
                    "SELECT token, project_root FROM sessions WHERE fingerprint = ?",
                    (fp,),
                )
                if existing:
                    store.execute(
                        "UPDATE sessions SET updated_at = ? WHERE fingerprint = ?",
                        (now, fp),
                    )
                    return {
                        "token": existing["token"],
                        "fingerprint": fp,
                        "project_root": existing["project_root"] or proot,
                        "backend": backend,
                        "created": False,
                    }
                token = new_session_token()
                try:
                    store.insert(
                        "sessions",
                        {
                            "fingerprint": fp,
                            "project_root": proot,
                            "token": token,
                            "backend": backend,
                            "created_at": now,
                            "updated_at": now,
                        },
                    )
                    created = True
                except Exception:
                    # Race: another process inserted between our SELECT and INSERT
                    # (possible with a remote catalog where the file lock does not
                    # apply). Re-select and adopt their token.
                    row = store.query_one(
                        "SELECT token, project_root FROM sessions "
                        "WHERE fingerprint = ?",
                        (fp,),
                    )
                    if not row:
                        raise
                    token = row["token"]
                    proot = row["project_root"] or proot
                    created = False
                return {
                    "token": token,
                    "fingerprint": fp,
                    "project_root": proot,
                    "backend": backend,
                    "created": created,
                }
            finally:
                store.close()

    def get_session(self, root: PathLike) -> Optional[Dict[str, Any]]:
        fp = project_fingerprint(root)
        store = self._store()
        try:
            self._ensure_schema(store)
            return store.query_one(
                "SELECT * FROM sessions WHERE fingerprint = ?", (fp,)
            )
        finally:
            store.close()

    # -- databases ------------------------------------------------------
    def register_database(self, record: Dict[str, Any]) -> None:
        """Upsert one hosted-database record (delete-then-insert; no upsert SQL)."""
        record = dict(record)
        record.setdefault("updated_at", time.time())
        with FileLock(self.lock_path, timeout=self.lock_timeout):
            store = self._store()
            try:
                self._ensure_schema(store)
                store.execute(
                    "DELETE FROM databases WHERE storage_key = ?",
                    (record["storage_key"],),
                )
                store.insert("databases", record)
            finally:
                store.close()

    def get_database(self, storage_key: str) -> Optional[Dict[str, Any]]:
        store = self._store()
        try:
            self._ensure_schema(store)
            return store.query_one(
                "SELECT * FROM databases WHERE storage_key = ?", (storage_key,)
            )
        finally:
            store.close()

    def list_databases(
        self, token: Optional[str] = None, root: Optional[PathLike] = None
    ) -> List[Dict[str, Any]]:
        store = self._store()
        try:
            self._ensure_schema(store)
            if token is not None:
                return store.query(
                    "SELECT * FROM databases WHERE token = ? ORDER BY db_name",
                    (token,),
                )
            if root is not None:
                return store.query(
                    "SELECT * FROM databases WHERE fingerprint = ? ORDER BY db_name",
                    (project_fingerprint(root),),
                )
            return store.query("SELECT * FROM databases ORDER BY token, db_name")
        finally:
            store.close()

    def remove_database(self, storage_key: str) -> None:
        with FileLock(self.lock_path, timeout=self.lock_timeout):
            store = self._store()
            try:
                self._ensure_schema(store)
                store.execute(
                    "DELETE FROM databases WHERE storage_key = ?", (storage_key,)
                )
            finally:
                store.close()

    # -- servers --------------------------------------------------------
    def register_server(self, record: Dict[str, Any]) -> None:
        record = dict(record)
        now = time.time()
        record.setdefault("started_at", now)
        record.setdefault("heartbeat_at", now)
        with FileLock(self.lock_path, timeout=self.lock_timeout):
            store = self._store()
            try:
                self._ensure_schema(store)
                store.execute(
                    "DELETE FROM servers WHERE server_id = ?", (record["server_id"],)
                )
                store.insert("servers", record)
            finally:
                store.close()

    def heartbeat(self, server_id: str) -> None:
        store = self._store()
        try:
            self._ensure_schema(store)
            store.execute(
                "UPDATE servers SET heartbeat_at = ? WHERE server_id = ?",
                (time.time(), server_id),
            )
        finally:
            store.close()

    def unregister_server(self, server_id: str) -> None:
        with FileLock(self.lock_path, timeout=self.lock_timeout):
            store = self._store()
            try:
                self._ensure_schema(store)
                store.execute("DELETE FROM servers WHERE server_id = ?", (server_id,))
            finally:
                store.close()

    def list_servers(
        self, root: Optional[PathLike] = None, *, prune: bool = True
    ) -> List[Dict[str, Any]]:
        """List registered servers, optionally pruning ones whose PID is dead."""
        store = self._store()
        try:
            self._ensure_schema(store)
            if root is not None:
                rows = store.query(
                    "SELECT * FROM servers WHERE fingerprint = ? "
                    "ORDER BY started_at",
                    (project_fingerprint(root),),
                )
            else:
                rows = store.query("SELECT * FROM servers ORDER BY started_at")
        finally:
            store.close()
        if not prune:
            return rows
        live: List[Dict[str, Any]] = []
        dead: List[str] = []
        for row in rows:
            pid = row.get("pid")
            if pid and pid_alive(int(pid)):
                live.append(row)
            else:
                dead.append(row["server_id"])
        for sid in dead:
            self.unregister_server(sid)
        return live
