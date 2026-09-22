"""
Periodic, chunked, rotating backups of hosted databases.

The server backs up what it hosts on a schedule, and does it in a way that keeps
individual backup artifacts bounded in size ("chunking so that db size will be
modulated") and old backups from piling up (rotation):

* **SQLite hosted databases** are copied with SQLite's *online backup API*
  (``sqlite3.Connection.backup(dest, pages=...)``), which produces a consistent
  snapshot without blocking writers and, by copying a bounded number of pages per
  step, never holds the source locked for long. The snapshot is gzip-compressed
  and then split into fixed-size ``.partNNN`` chunk files, with a JSON manifest
  describing the set.
* **Remote (Postgres/MySQL) hosted databases** are reassembled from their content
  chunks and backed up the same way; additionally, when the backend is Postgres
  and ``pg_dump`` is on ``PATH``, a native ``pg_dump -Fc`` custom-format dump of
  the whole cluster database is taken and chunked alongside.

:meth:`BackupManager.start_periodic` runs the whole thing on a background daemon
thread until stopped; the server owns one and stops it on shutdown.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..tokens import PathLike
from .catalog import SessionCatalog
from .dbhost import DEFAULT_CHUNK_BYTES, DatabaseHost
from .locking import FileLock, atomic_write_text

#: SQLite pages copied per online-backup step (32 MiB at the 4 KiB default).
DEFAULT_BACKUP_PAGES = 8192
#: Default size of each backup part file: 16 MiB.
DEFAULT_PART_BYTES = 16 * 1024 * 1024
#: Default number of backup sets to keep per database before rotating out.
DEFAULT_KEEP = 5


def _timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


class BackupManager:
    """Creates, chunks, rotates and restores backups for a :class:`DatabaseHost`."""

    def __init__(
        self,
        host: DatabaseHost,
        *,
        backup_dir: PathLike,
        part_bytes: int = DEFAULT_PART_BYTES,
        pages_per_step: int = DEFAULT_BACKUP_PAGES,
        keep: int = DEFAULT_KEEP,
    ) -> None:
        self.host = host
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.part_bytes = max(64 * 1024, int(part_bytes))
        self.pages_per_step = max(64, int(pages_per_step))
        self.keep = max(1, int(keep))
        # Legacy shared lock path (kept for compatibility); per-database backups
        # use a per-key lock so distinct databases back up genuinely concurrently.
        self._lock_path = self.backup_dir / "backup.lock"
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _key_lock_path(self, key: str) -> Path:
        """Per-key lock: distinct storage keys never share a lock, so concurrent
        backups of different databases do not serialize on one global lock. Each
        key owns its own ``<backup_dir>/<key>/`` subtree (snapshot set + rotation),
        so the lock is both sufficient and non-conflicting."""
        key_dir = self.backup_dir / key
        key_dir.mkdir(parents=True, exist_ok=True)
        return key_dir / "backup.lock"

    # -- snapshot -------------------------------------------------------
    def _online_backup_sqlite(self, source_path: PathLike, dest_path: PathLike) -> None:
        """Consistent hot copy of a SQLite file via the online backup API."""
        src = sqlite3.connect(f"file:{Path(source_path).as_posix()}?mode=ro", uri=True)
        try:
            dst = sqlite3.connect(str(dest_path))
            try:
                src.backup(dst, pages=self.pages_per_step)
            finally:
                dst.close()
        finally:
            src.close()

    def _chunk_file(self, plain_path: Path, key: str, ts: str) -> Dict[str, Any]:
        """gzip ``plain_path`` and split it into bounded part files + manifest."""
        set_dir = self.backup_dir / key / ts
        set_dir.mkdir(parents=True, exist_ok=True)
        parts: List[Dict[str, Any]] = []
        sha = hashlib.sha256()
        raw_size = 0
        seq = 0
        with open(plain_path, "rb") as fin:
            # Stream through gzip in memory-bounded windows, emitting part files.
            buf = bytearray()
            compressor_path = set_dir / "_tmp.gz"
            with gzip.open(compressor_path, "wb") as gz:
                for block in iter(lambda: fin.read(1024 * 1024), b""):
                    raw_size += len(block)
                    sha.update(block)
                    gz.write(block)
        # Now split the compressed file into parts.
        with open(compressor_path, "rb") as gzf:
            while True:
                block = gzf.read(self.part_bytes)
                if not block:
                    break
                part_name = f"{key}.{ts}.gz.part{seq:04d}"
                part_path = set_dir / part_name
                part_path.write_bytes(block)
                parts.append({"seq": seq, "name": part_name, "bytes": len(block)})
                seq += 1
        compressor_path.unlink()
        manifest = {
            "storage_key": key,
            "timestamp": ts,
            "raw_size_bytes": raw_size,
            "raw_sha256": sha.hexdigest(),
            "compression": "gzip",
            "part_bytes": self.part_bytes,
            "n_parts": len(parts),
            "parts": parts,
            "created_at": time.time(),
        }
        atomic_write_text(set_dir / "manifest.json", json.dumps(manifest, indent=2))
        return manifest

    def backup_database(self, storage_key_: str) -> Dict[str, Any]:
        """Back up a single hosted database; return its manifest."""
        rec = self.host.catalog.get_database(storage_key_)
        if rec is None:
            raise KeyError(f"no hosted database with key {storage_key_!r}")
        ts = _timestamp()
        with FileLock(self._key_lock_path(storage_key_), timeout=60.0):
            with tempfile.TemporaryDirectory(prefix="fa-backup-") as tmpd:
                snap = Path(tmpd) / "snapshot.db"
                if rec.get("dialect") == "sqlite":
                    self._online_backup_sqlite(rec["location"], snap)
                else:
                    # Reassemble remote chunks, then take a consistent copy.
                    materialized = self.host.materialize(storage_key_, snap)
                    snap = Path(materialized)
                manifest = self._chunk_file(snap, storage_key_, ts)
            self._rotate(storage_key_)
        return manifest

    def job_spec(self) -> Dict[str, Any]:
        """A JSON-serializable description of this manager + its host + catalog.

        A subprocess backup worker (driven by the Go backup pool) rebuilds an
        identical :class:`SessionCatalog`, :class:`DatabaseHost` and
        :class:`BackupManager` from this spec, so it can back up a subset of the
        storage keys with exactly the same chunk/manifest/rotation logic -- which
        is what keeps every produced backup restore-compatible regardless of
        which process created it.
        """
        return {
            "catalog_dir": str(self.host.catalog.dir),
            "catalog_target": self.host.catalog.target,
            "catalog_lock_timeout": self.host.catalog.lock_timeout,
            "root": self.host.root,
            "token": self.host.token,
            "data_dir": str(self.host.data_dir),
            "backend": self.host.backend,
            "chunk_bytes": self.host.chunk_bytes,
            "backup_dir": str(self.backup_dir),
            "part_bytes": self.part_bytes,
            "pages_per_step": self.pages_per_step,
            "keep": self.keep,
        }

    @classmethod
    def from_job_spec(cls, spec: Dict[str, Any]) -> "BackupManager":
        """Rebuild a :class:`BackupManager` (with host + catalog) from a spec."""
        catalog = SessionCatalog(
            spec["catalog_dir"],
            target=spec.get("catalog_target"),
            lock_timeout=float(spec.get("catalog_lock_timeout", 30.0)),
        )
        host = DatabaseHost(
            root=spec["root"],
            token=spec["token"],
            data_dir=spec["data_dir"],
            catalog=catalog,
            backend=spec.get("backend", "sqlite"),
            chunk_bytes=int(spec.get("chunk_bytes", DEFAULT_CHUNK_BYTES)),
        )
        return cls(
            host,
            backup_dir=spec["backup_dir"],
            part_bytes=int(spec.get("part_bytes", DEFAULT_PART_BYTES)),
            pages_per_step=int(spec.get("pages_per_step", DEFAULT_BACKUP_PAGES)),
            keep=int(spec.get("keep", DEFAULT_KEEP)),
        )

    def backup_all(
        self, *, workers: Optional[int] = None, use_go: bool = True
    ) -> List[Dict[str, Any]]:
        """Back up every hosted database for this session, concurrently.

        Distinct storage keys own disjoint on-disk subtrees and per-key locks, so
        they back up in parallel with no contention. The work is fanned out by a
        Go pool (goroutine pool spawning backup-worker subprocesses) when the Go
        toolchain is present, and otherwise by a pure-Python thread pool -- both
        call the same :meth:`backup_database`, so the produced backups are
        identical either way. Returns one manifest (or ``{"error": ...}``) per key.
        """
        keys = [hosted.storage_key for hosted in self.host.list()]
        if not keys:
            return []
        from .backup_pool import backup_keys

        report = backup_keys(self, keys, workers=workers, use_go=use_go)
        return report["results"]

    # -- native postgres dump ------------------------------------------
    def pg_dump(self, database_url: str) -> Optional[Dict[str, Any]]:
        """Take a native ``pg_dump -Fc`` custom-format backup, then chunk it.

        Returns the manifest, or ``None`` if ``pg_dump`` is not available. The
        custom format (``-Fc``) is the production-recommended, restore-flexible
        format; the dump streams to a file (never through memory).
        """
        if shutil.which("pg_dump") is None:
            return None
        ts = _timestamp()
        with FileLock(self._key_lock_path("pg_cluster_dump"), timeout=120.0):
            with tempfile.TemporaryDirectory(prefix="fa-pgdump-") as tmpd:
                dump = Path(tmpd) / "cluster.dump"
                with open(dump, "wb") as out:
                    proc = subprocess.run(
                        ["pg_dump", "--format=custom", "--no-owner", database_url],
                        stdout=out,
                        stderr=subprocess.PIPE,
                    )
                if proc.returncode != 0:
                    raise RuntimeError(
                        "pg_dump failed: "
                        + proc.stderr.decode("utf-8", "replace").strip()
                    )
                manifest = self._chunk_file(dump, "pg_cluster_dump", ts)
            self._rotate("pg_cluster_dump")
        return manifest

    # -- rotation / listing / restore ----------------------------------
    def _rotate(self, key: str) -> None:
        key_dir = self.backup_dir / key
        if not key_dir.is_dir():
            return
        sets = sorted(
            (d for d in key_dir.iterdir() if d.is_dir()), key=lambda d: d.name
        )
        excess = len(sets) - self.keep
        for old in sets[: max(0, excess)]:
            shutil.rmtree(old, ignore_errors=True)

    def list_backups(self, storage_key_: Optional[str] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        keys = (
            [storage_key_]
            if storage_key_
            else [d.name for d in self.backup_dir.iterdir() if d.is_dir()]
        )
        for key in keys:
            key_dir = self.backup_dir / key
            if not key_dir.is_dir():
                continue
            for set_dir in sorted(key_dir.iterdir()):
                man = set_dir / "manifest.json"
                if man.is_file():
                    try:
                        out.append(json.loads(man.read_text(encoding="utf-8")))
                    except (OSError, ValueError):
                        continue
        return out

    def restore(self, storage_key_: str, timestamp: str, dest: PathLike) -> Path:
        """Reassemble + decompress a backup set into ``dest`` (a SQLite file)."""
        set_dir = self.backup_dir / storage_key_ / timestamp
        man_path = set_dir / "manifest.json"
        if not man_path.is_file():
            raise FileNotFoundError(f"no backup manifest at {man_path}")
        manifest = json.loads(man_path.read_text(encoding="utf-8"))
        parts = sorted(manifest["parts"], key=lambda p: p["seq"])
        dest = Path(dest)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".gz") as tmp:
            gz_path = Path(tmp.name)
            for part in parts:
                tmp.write((set_dir / part["name"]).read_bytes())
        try:
            with gzip.open(gz_path, "rb") as gz, open(dest, "wb") as fout:
                shutil.copyfileobj(gz, fout)
        finally:
            gz_path.unlink()
        expected = manifest.get("raw_sha256")
        if expected:
            h = hashlib.sha256()
            with open(dest, "rb") as fh:
                for block in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(block)
            if h.hexdigest() != expected:
                raise ValueError("restored file checksum mismatch")
        return dest

    # -- periodic loop --------------------------------------------------
    def start_periodic(
        self, interval: float, *, database_url: Optional[str] = None
    ) -> "BackupManager":
        """Run :meth:`backup_all` (and pg_dump, if applicable) every ``interval`` s."""
        if self._thread is not None:
            return self
        self._stop.clear()

        def _loop() -> None:
            # Wait first, so startup is not immediately followed by a backup.
            while not self._stop.wait(interval):
                try:
                    self.backup_all()
                    if database_url and self.host.dialect == "postgresql":
                        try:
                            self.pg_dump(database_url)
                        except Exception:
                            pass
                except Exception:
                    # Never let a backup failure kill the loop.
                    pass

        self._thread = threading.Thread(target=_loop, name="fa-backup", daemon=True)
        self._thread.start()
        return self

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
