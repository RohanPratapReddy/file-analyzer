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

import hashlib
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..naming import sqlite_db_path, storage_key
from ..store import SqlStore, resolve_dialect
from ..tokens import PathLike
from .catalog import SessionCatalog

#: Default per-chunk size for the remote (bytea) backend: 8 MiB.
DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024


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
            if source.resolve() != dest.resolve():
                # Copy to a sibling temp then atomically replace, so a reader
                # never sees a partial file.
                tmp = dest.with_name(f".{dest.name}.incoming")
                shutil.copyfile(source, tmp)
                tmp.replace(dest)
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
            n_chunks = self._write_chunks(key, source, db_name, size, sha, now)
            record = {
                "storage_key": key,
                "fingerprint": None,
                "token": self.token,
                "db_name": db_name,
                "dialect": self.dialect,
                "location": f"{self.backend}#{key}",
                "size_bytes": size,
                "sha256": sha,
                "n_chunks": n_chunks,
                "updated_at": now,
            }
        # Fill the fingerprint from the catalog's identity helper.
        from ..tokens import project_fingerprint

        record["fingerprint"] = project_fingerprint(self.root)
        self.catalog.register_database(record)
        return HostedDatabase(record)

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
