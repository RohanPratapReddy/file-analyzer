"""
The database host -- where the server actually stores the databases it serves.

A repo-session produces several SQLite databases (``repository``, ``unified``,
``enrichment``, the monitor's ``changes`` / ``sessions`` logs, ...). The host
takes each one and stores it under the ``PROJECT_ROOT-{token}-{db_name}``
convention (:mod:`file_analyzer.server.naming`), in one of two backends:

* **sqlite** (default) -- the database is stored as a *live file* under the
  host's data directory. It can be queried in place (read-only) and copied out.
* **postgres / mysql** (a SQL URL) -- the database's bytes are split into
  fixed-size **chunks** and stored as rows in a content table. Chunking is what
  keeps any single stored row bounded ("chunking so that db size will be
  modulated"): a 2 GB database becomes N bounded rows, not one giant blob, which
  is friendlier to the server's row-size limits, backups, and transfer. The host
  reassembles the chunks into a temp file on demand.

Every host operation also records/updates the database's row in the shared
:class:`~file_analyzer.server.catalog.SessionCatalog`, so any server or client
can enumerate what is hosted and where.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, ContextManager, Dict, List, Optional

from ..naming import sqlite_db_path, storage_key
from ..store import SqlStore, resolve_dialect
from ..tokens import PathLike
from .catalog import SessionCatalog

#: Default per-chunk size for the remote (bytea) backend: 8 MiB.
DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024
#: Minimum seconds between two recorded read accesses of the same database, so
#: a busy query loop does not turn every read into a catalog write.
TOUCH_THROTTLE_SECONDS = 60.0


def _sha256_file(path: PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _blob_type(dialect: str) -> str:
    if dialect == "postgresql":
        return "BYTEA"
    if dialect == "mysql":
        return "LONGBLOB"
    return "BLOB"


class HostedDatabase:
    """A handle to one database the host is storing."""

    def __init__(self, record: Dict[str, Any]) -> None:
        self.record = dict(record)

    @property
    def storage_key(self) -> str:
        return self.record["storage_key"]

    @property
    def db_name(self) -> str:
        return self.record["db_name"]

    @property
    def location(self) -> str:
        return self.record.get("location", "")

    @property
    def size_bytes(self) -> int:
        return int(self.record.get("size_bytes") or 0)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"HostedDatabase(key={self.storage_key!r}, "
            f"size={self.size_bytes}, location={self.location!r})"
        )


class DatabaseHost:
    """Stores and serves hosted databases for a repo-session.

    ``backend`` is ``"sqlite"`` (live files under ``data_dir``) or a SQL URL
    (``postgresql://...`` / ``mysql://...``) for the chunked content store.
    """

    def __init__(
        self,
        *,
        root: PathLike,
        token: str,
        data_dir: PathLike,
        catalog: SessionCatalog,
        backend: str = "sqlite",
        chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    ) -> None:
        self.root = str(root)
        self.token = token
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.catalog = catalog
        self.backend = backend
        self.dialect = resolve_dialect(backend) if backend != "sqlite" else "sqlite"
        self.chunk_bytes = max(64 * 1024, int(chunk_bytes))
        self._schema_ready = False
        self._touched: Dict[str, float] = {}
        # Optional ``key -> context manager`` that serializes content changes of
        # one storage key with backups/heals of it (the server wires the
        # BackupManager's per-key lock in here).
        self.key_lock_factory: Optional[Callable[[str], ContextManager[Any]]] = None

    def _key_lock(self, key: str) -> ContextManager[Any]:
        if self.key_lock_factory is None:
            return contextlib.nullcontext()
        return self.key_lock_factory(key)

    @property
    def is_remote(self) -> bool:
        return self.dialect != "sqlite"

    # -- remote content store schema -----------------------------------
    def _store(self) -> SqlStore:
        return SqlStore(self.backend).connect()

    def _ensure_remote_schema(self, store: SqlStore) -> None:
        if self._schema_ready:
            return
        blob = _blob_type(store.dialect)
        store.ensure_table(
            "hosted_databases",
            "storage_key TEXT PRIMARY KEY, token TEXT, db_name TEXT, "
            "dialect TEXT, size_bytes BIGINT, sha256 TEXT, chunk_bytes INTEGER, "
            "n_chunks INTEGER, updated_at DOUBLE PRECISION",
        )
        store.ensure_table(
            "hosted_chunks",
            f"storage_key TEXT, seq INTEGER, data {blob}, "
            "PRIMARY KEY (storage_key, seq)",
        )
        self._schema_ready = True

    # -- host / register ------------------------------------------------
    def host(
        self, source_db_path: PathLike, db_name: str, *, copy: bool = True
    ) -> HostedDatabase:
        """Store ``source_db_path`` under the session as ``db_name``.

        With the SQLite backend the file is copied into the data directory (an
        atomic replace); with a remote backend its bytes are chunked into the
        content store. Returns a :class:`HostedDatabase`.
        """
        source = Path(source_db_path)
        if not source.is_file():
            raise FileNotFoundError(f"no such database file: {source}")
        key = storage_key(self.root, self.token, db_name)
        size = source.stat().st_size
        sha = _sha256_file(source)
        now = time.time()

        if not self.is_remote:
            dest = sqlite_db_path(self.data_dir, self.root, self.token, db_name)
            record = {
                "storage_key": key,
                "fingerprint": None,
                "token": self.token,
                "db_name": db_name,
                "dialect": "sqlite",
                "location": str(dest),
                "size_bytes": size,
                "sha256": sha,
                "n_chunks": None,
                "updated_at": now,
            }
        else:
            record = {
                "storage_key": key,
                "fingerprint": None,
                "token": self.token,
                "db_name": db_name,
                "dialect": self.dialect,
                "location": f"{self.backend}#{key}",
                "size_bytes": size,
                "sha256": sha,
                "n_chunks": None,
                "updated_at": now,
            }
        # Fill the fingerprint from the catalog's identity helper.
        from ..tokens import project_fingerprint

        record["fingerprint"] = project_fingerprint(self.root)
        # Content swap + catalog update happen under the key lock, so a
        # concurrent backup/heal of the same key never sees a half-updated pair.
        with self._key_lock(key):
            if not self.is_remote:
                dest = Path(record["location"])
                if source.resolve() != dest.resolve():
                    # Copy to a sibling temp then atomically replace, so a
                    # reader never sees a partial file.
                    tmp = dest.with_name(f".{dest.name}.incoming")
                    shutil.copyfile(source, tmp)
                    # Stale WAL/SHM sidecars belong to the previous content.
                    for side in ("-wal", "-shm"):
                        try:
                            dest.with_name(dest.name + side).unlink()
                        except FileNotFoundError:
                            pass
                    tmp.replace(dest)
            else:
                record["n_chunks"] = self._write_chunks(
                    key, source, db_name, size, sha, now
                )
            self.catalog.register_database(record)
        return HostedDatabase(record)

    def reinstall(self, storage_key_: str, source: PathLike) -> Dict[str, Any]:
        """Replace a hosted database's content with ``source`` *in place*.

        Used by the autopilot to install a verified restore over a damaged copy:
        the catalog row keeps its identity and ``updated_at`` (it is the same
        logical database, repaired, not a re-host) while ``size_bytes`` and
        ``sha256`` are updated to the installed content. For SQLite the file is
        moved into place atomically (a ``source`` in the data directory is
        consumed); for a remote backend the chunks are rewritten. Call under
        the key lock.
        """
        rec = self.catalog.get_database(storage_key_)
        if rec is None:
            raise KeyError(f"no hosted database with key {storage_key_!r}")
        source = Path(source)
        size = source.stat().st_size
        sha = _sha256_file(source)
        record = dict(rec)
        record["size_bytes"] = size
        record["sha256"] = sha
        if rec.get("dialect") == "sqlite":
            dest = Path(rec.get("location") or "")
            if dest.name != f"{storage_key_}.db":
                raise ValueError(f"refusing to reinstall over unexpected path {dest}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if source.parent.resolve() != dest.parent.resolve():
                tmp = dest.with_name(f".{dest.name}.incoming")
                shutil.copyfile(source, tmp)
                source = tmp
            for side in ("-wal", "-shm"):
                try:
                    dest.with_name(dest.name + side).unlink()
                except FileNotFoundError:
                    pass
            os.replace(source, dest)
        else:
            updated = float(rec.get("updated_at") or time.time())
            record["n_chunks"] = self._write_chunks(
                storage_key_, source, rec["db_name"], size, sha, updated
            )
        self.catalog.register_database(record)
        return record

    def chunk_stats(self, storage_key_: str) -> Dict[str, Any]:
        """Cheap structural facts about a remote-hosted database's chunks.

        Returns ``n_chunks`` (rows present), ``min_seq``/``max_seq``,
        ``total_bytes`` (sum of chunk lengths) and the content table's own
        ``declared`` row (``size_bytes``/``sha256``/``n_chunks``) or ``None``.
        """
        store = self._store()
        try:
            self._ensure_remote_schema(store)
            rows = store.query(
                "SELECT COUNT(*) AS n, MIN(seq) AS lo, MAX(seq) AS hi, "
                "SUM(LENGTH(data)) AS total FROM hosted_chunks "
                "WHERE storage_key = ?",
                (storage_key_,),
            )
            declared = store.query(
                "SELECT size_bytes, sha256, n_chunks FROM hosted_databases "
                "WHERE storage_key = ?",
                (storage_key_,),
            )
        finally:
            store.close()
        row = rows[0] if rows else {}
        return {
            "n_chunks": int(row.get("n") or 0),
            "min_seq": row.get("lo"),
            "max_seq": row.get("hi"),
            "total_bytes": int(row.get("total") or 0),
            "declared": dict(declared[0]) if declared else None,
        }

    def _write_chunks(
        self,
        key: str,
        source: Path,
        db_name: str,
        size: int,
        sha: str,
        now: float,
    ) -> int:
        store = self._store()
        try:
            self._ensure_remote_schema(store)
            # Replace any prior content for this key.
            store.execute("DELETE FROM hosted_chunks WHERE storage_key = ?", (key,))
            store.execute("DELETE FROM hosted_databases WHERE storage_key = ?", (key,))
            seq = 0
            with open(source, "rb") as fh:
                while True:
                    block = fh.read(self.chunk_bytes)
                    if not block:
                        break
                    store.insert(
                        "hosted_chunks",
                        {"storage_key": key, "seq": seq, "data": memoryview(block)},
                    )
                    seq += 1
            store.insert(
                "hosted_databases",
                {
                    "storage_key": key,
                    "token": self.token,
                    "db_name": db_name,
                    "dialect": self.dialect,
                    "size_bytes": size,
                    "sha256": sha,
                    "chunk_bytes": self.chunk_bytes,
                    "n_chunks": seq,
                    "updated_at": now,
                },
            )
            return seq
        finally:
            store.close()

    # -- retrieve -------------------------------------------------------
    def materialize(self, storage_key_: str, dest: Optional[PathLike] = None) -> Path:
        """Return a local file path for a hosted database.

        For the SQLite backend this is the live file itself (unless ``dest`` asks
        for a copy). For a remote backend the chunks are reassembled into
        ``dest`` (or a temp file) and its checksum verified.
        """
        rec = self.catalog.get_database(storage_key_)
        if rec is None:
            raise KeyError(f"no hosted database with key {storage_key_!r}")
        if rec.get("dialect") == "sqlite":
            src = Path(rec["location"])
            if not src.is_file():
                raise FileNotFoundError(f"hosted file missing: {src}")
            if dest is None:
                return src
            shutil.copyfile(src, dest)
            return Path(dest)
        # Remote: reassemble chunks.
        if dest is None:
            fd, tmp = tempfile.mkstemp(suffix=".db", prefix="hosted-")
            import os as _os

            _os.close(fd)
            dest = tmp
        self._read_chunks(storage_key_, dest)
        expected = rec.get("sha256")
        if expected and _sha256_file(dest) != expected:
            raise ValueError(
                f"checksum mismatch reassembling {storage_key_!r}: file corrupt"
            )
        return Path(dest)

    def read_bytes(self, storage_key_: str) -> bytes:
        """Return the full bytes of a hosted database (any backend)."""
        rec = self.catalog.get_database(storage_key_)
        if rec is None:
            raise KeyError(f"no hosted database with key {storage_key_!r}")
        self.touch(storage_key_)
        if rec.get("dialect") == "sqlite":
            return Path(rec["location"]).read_bytes()
        fd, tmp = tempfile.mkstemp(suffix=".db", prefix="hosted-")
        import os as _os

        _os.close(fd)
        try:
            self._read_chunks(storage_key_, tmp)
            return Path(tmp).read_bytes()
        finally:
            try:
                Path(tmp).unlink()
            except OSError:
                pass

    def _read_chunks(self, key: str, dest: PathLike) -> None:
        store = self._store()
        try:
            self._ensure_remote_schema(store)
            rows = store.query(
                "SELECT seq, data FROM hosted_chunks WHERE storage_key = ? "
                "ORDER BY seq",
                (key,),
            )
            with open(dest, "wb") as fh:
                for row in rows:
                    data = row["data"]
                    if isinstance(data, memoryview):
                        data = data.tobytes()
                    fh.write(data)
        finally:
            store.close()

    # -- enumerate / query ---------------------------------------------
    def list(self) -> List[HostedDatabase]:
        return [
            HostedDatabase(r) for r in self.catalog.list_databases(token=self.token)
        ]

    def query(
        self, storage_key_: str, sql: str, params: Any = (), limit: int = 100
    ) -> Dict[str, Any]:
        """Run a read-only SELECT/WITH against a hosted database.

        The statement is validated as a single read-only query (the same guard
        the SDK's :class:`FileAnalyzerDatabase` uses). For remote-hosted
        databases the content is materialized to a temp SQLite file first.
        """
        from .readonly import is_readonly_select, run_readonly_query

        if not is_readonly_select(sql):
            raise ValueError("only a single read-only SELECT/WITH query is allowed")
        rec = self.catalog.get_database(storage_key_)
        if rec is None:
            raise KeyError(f"no hosted database with key {storage_key_!r}")
        self.touch(storage_key_)
        if rec.get("dialect") == "sqlite":
            return run_readonly_query(rec["location"], sql, params, limit)
        tmp = self.materialize(storage_key_)
        try:
            return run_readonly_query(str(tmp), sql, params, limit)
        finally:
            try:
                Path(tmp).unlink()
            except OSError:
                pass

    # -- access tracking -------------------------------------------------
    def touch(self, storage_key_: str) -> None:
        """Record a read access (throttled), so retention sees the db as in use.

        Backups deliberately do *not* call this -- a database that is only ever
        backed up is still idle.
        """
        now = time.time()
        if now - self._touched.get(storage_key_, 0.0) < TOUCH_THROTTLE_SECONDS:
            return
        self._touched[storage_key_] = now
        try:
            self.catalog.touch_database(storage_key_, now)
        except Exception:
            # Access tracking is advisory; never fail a read over it.
            pass

    # -- size / removal (retention) ---------------------------------------
    @staticmethod
    def _sqlite_files(location: PathLike) -> List[Path]:
        """The live file plus its WAL/SHM sidecars and any half-copied upload."""
        loc = Path(location)
        return [
            loc,
            loc.with_name(loc.name + "-wal"),
            loc.with_name(loc.name + "-shm"),
            loc.with_name(f".{loc.name}.incoming"),
        ]

    def stored_bytes(self, record: Dict[str, Any]) -> int:
        """Bytes a hosted database occupies in its backend right now."""
        if record.get("dialect") == "sqlite":
            total = 0
            for p in self._sqlite_files(record["location"]):
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
            return total
        return int(record.get("size_bytes") or 0)

    def remove(self, storage_key_: str) -> int:
        """Delete a hosted database's content and catalog row; return bytes freed.

        For the SQLite backend only a file named exactly ``<storage_key>.db`` (and
        its sidecars) is ever unlinked, so a corrupted catalog row can never point
        this at an unrelated file.
        """
        rec = self.catalog.get_database(storage_key_)
        if rec is None:
            return 0
        freed = 0
        if rec.get("dialect") == "sqlite":
            loc = Path(rec.get("location") or "")
            if loc.name == f"{storage_key_}.db":
                for p in self._sqlite_files(loc):
                    try:
                        size = p.stat().st_size
                        p.unlink()
                        freed += size
                    except FileNotFoundError:
                        pass
        else:
            store = self._store()
            try:
                self._ensure_remote_schema(store)
                store.execute(
                    "DELETE FROM hosted_chunks WHERE storage_key = ?", (storage_key_,)
                )
                store.execute(
                    "DELETE FROM hosted_databases WHERE storage_key = ?",
                    (storage_key_,),
                )
            finally:
                store.close()
            freed = int(rec.get("size_bytes") or 0)
        self.catalog.remove_database(storage_key_)
        self._touched.pop(storage_key_, None)
        return freed

    def reclaim(self) -> Dict[str, Any]:
        """Best-effort space reclaim on the remote content store after deletions.

        Postgres gets a plain ``VACUUM`` (non-blocking; makes the freed chunk
        space reusable), MySQL/MariaDB an ``OPTIMIZE TABLE`` (rebuilds the table
        and returns space to the OS). The SQLite backend stores one file per
        database, so deleting the file already returned the space.
        """
        if not self.is_remote:
            return {"action": "none", "reason": "sqlite backend frees space on delete"}
        store = self._store()
        try:
            self._ensure_remote_schema(store)
            conn = store._require()
            if store.dialect == "postgresql":
                # VACUUM cannot run inside a transaction block.
                previous = getattr(conn, "autocommit", False)
                conn.autocommit = True
                try:
                    cur = conn.cursor()
                    try:
                        cur.execute("VACUUM hosted_chunks")
                    finally:
                        cur.close()
                finally:
                    conn.autocommit = previous
                return {"action": "VACUUM hosted_chunks"}
            store.execute("OPTIMIZE TABLE hosted_chunks")
            return {"action": "OPTIMIZE TABLE hosted_chunks"}
        except Exception as exc:
            return {"action": "failed", "error": str(exc)}
        finally:
            store.close()
