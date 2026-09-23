"""
Periodic, chunked, rotating backups of hosted databases.

The server backs up what it hosts on a schedule, and does it in a way that keeps
individual backup artifacts bounded in size ("chunking so that db size will be
modulated") and old backups from piling up (rotation):

* **SQLite hosted databases** are copied with SQLite's *online backup API*
  (``sqlite3.Connection.backup(dest, pages=...)``), which produces a consistent
  snapshot without blocking writers and, by copying a bounded number of pages per
  step, never holds the source locked for long. The snapshot is gzip-compressed
  and then stored in one of two set formats, described by a JSON manifest:

  - **chunked** (default): split into fixed-size ``.partNNNN`` files.
  - **reed-solomon** (``erasure=`` set): erasure coded into ``k`` data + ``m``
    parity shards spread over one or more shard directories (see
    :mod:`.sharding`). Any ``k`` shards restore the backup; per-block hashes
    detect corruption; :meth:`BackupManager.repair_backups` rebuilds lost or
    damaged shards and a periodic *scrub* does that automatically.
* **Remote (Postgres/MySQL) hosted databases** are reassembled from their content
  chunks and backed up the same way; additionally, when the backend is Postgres
  and ``pg_dump`` is on ``PATH``, a native ``pg_dump -Fc`` custom-format dump of
  the whole cluster database is taken and stored alongside.

A set is identified by ``(storage_key, timestamp)``. Its primary directory is
``<backup_dir>/<key>/<timestamp>/``; an erasure-coded set also has a directory
under every shard root it uses, each holding its shards and a manifest replica.
Listing, rotation, retention and removal all operate on the union of those.

:meth:`BackupManager.start_periodic` runs the backups on a background daemon
thread until stopped; the server owns one and stops it on shutdown.
"""

from __future__ import annotations

import calendar
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from ..tokens import PathLike
from .catalog import SessionCatalog
from .dbhost import DEFAULT_CHUNK_BYTES, DatabaseHost
from .locking import FileLock, atomic_write_text
from .sharding import FORMAT as RS_FORMAT
from .sharding import (
    MANIFEST,
    ErasureConfig,
    ShardedSet,
    UnrecoverableSet,
    decode_to_file,
    publish_manifest,
    repair_set,
    verify_set,
    write_sharded,
)

#: SQLite pages copied per online-backup step (32 MiB at the 4 KiB default).
DEFAULT_BACKUP_PAGES = 8192
#: Default size of each backup part file: 16 MiB.
DEFAULT_PART_BYTES = 16 * 1024 * 1024
#: Default number of backup sets to keep per database before rotating out.
DEFAULT_KEEP = 5
#: Default seconds between integrity scrubs of erasure-coded sets (1 day).
DEFAULT_SCRUB_INTERVAL = 86400.0
#: Set format of the plain chunked layout.
CHUNKED_FORMAT = "chunked"

_LOCK_TIMEOUT = 120.0


class SnapshotIntegrityError(RuntimeError):
    """A backup was refused because its source/snapshot is damaged."""


def _timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def _timestamp_epoch(label: str) -> Optional[float]:
    """Inverse of :func:`_timestamp` (UTC); ``None`` if ``label`` is not one."""
    try:
        return float(calendar.timegm(time.strptime(label, "%Y%m%d-%H%M%S")))
    except (ValueError, OverflowError):
        return None


def _tree_bytes(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def _read_manifest(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _plain_name(value: str, what: str) -> str:
    """Reject anything that is not a single, ordinary path component: storage
    keys and timestamps are joined onto backup roots, so ``..`` or a separator
    would escape them."""
    v = str(value)
    if (
        not v
        or v in (".", "..")
        or "/" in v
        or "\\" in v
        or "\x00" in v
        or Path(v).name != v
    ):
        raise ValueError(f"invalid {what}: {value!r}")
    return v


def set_format(manifest: Dict[str, Any]) -> str:
    """``"reed-solomon"`` or ``"chunked"`` (manifests predating the field)."""
    return str(manifest.get("format") or CHUNKED_FORMAT)


def _set_error(key: str, ts: str, error: str) -> Dict[str, Any]:
    """The report of a set that could not be checked at all (status ``error``)."""
    return {
        "storage_key": key,
        "timestamp": ts,
        "status": "error",
        "healthy": False,
        "recoverable": False,
        "problems": [error],
        "error": error,
    }


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
        erasure: Union[ErasureConfig, Dict[str, Any], None] = None,
        suspect_file: Optional[PathLike] = None,
    ) -> None:
        self.host = host
        self.backup_dir = Path(backup_dir).resolve()
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.part_bytes = max(64 * 1024, int(part_bytes))
        self.pages_per_step = max(64, int(pages_per_step))
        self.keep = max(1, int(keep))
        if isinstance(erasure, dict):
            erasure = ErasureConfig.from_dict(erasure)
        self.erasure: Optional[ErasureConfig] = erasure
        # Shard roots are namespaced per backup directory, so one --shard-dir can
        # be shared by several servers/repos without them seeing (or rotating,
        # or pruning) each other's shards.
        self.namespace = (
            "fa-"
            + hashlib.sha256(str(self.backup_dir).encode("utf-8")).hexdigest()[:16]
        )
        # Legacy shared lock path (kept for compatibility); per-database backups
        # use a per-key lock so distinct databases back up genuinely concurrently.
        self._lock_path = self.backup_dir / "backup.lock"
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scrub_thread: Optional[threading.Thread] = None
        self.last_scrub: Optional[Dict[str, Any]] = None
        # Storage keys whose hosted copy is known to be damaged (set by the
        # autopilot's health checks). They are never backed up: a backup of a
        # bad copy would rotate the last good sets out.
        self.suspect_keys: set = set()
        # The same flags shared across processes (parallel server instances and
        # Go-pool backup workers read it; the autopilot writes it).
        self.suspect_file: Optional[Path] = Path(suspect_file) if suspect_file else None
        # Integrity-check every snapshot before it becomes a backup set.
        self.verify_snapshots = True

    def is_suspect(self, key: str) -> bool:
        """True when ``key`` is flagged damaged, in memory or in the shared
        suspect file (an unreadable file flags nothing)."""
        if key in self.suspect_keys:
            return True
        if self.suspect_file is None:
            return False
        try:
            data = json.loads(self.suspect_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        keys = data.get("keys") if isinstance(data, dict) else data
        return isinstance(keys, list) and key in keys

    def _key_lock_path(self, key: str) -> Path:
        """Per-key lock: distinct storage keys never share a lock, so concurrent
        backups of different databases do not serialize on one global lock. Each
        key owns its own ``<backup_dir>/<key>/`` subtree (snapshot set + rotation),
        so the lock is both sufficient and non-conflicting."""
        key_dir = self.backup_dir / _plain_name(key, "storage key")
        key_dir.mkdir(parents=True, exist_ok=True)
        return key_dir / "backup.lock"

    # -- roots ----------------------------------------------------------
    def shard_roots(self) -> List[Path]:
        """Where new erasure-coded shards go: one namespaced root per shard dir,
        or the primary backup directory when no shard dirs are configured."""
        if self.erasure is None or not self.erasure.shard_dirs:
            return [self.backup_dir]
        return [Path(d) / self.namespace for d in self.erasure.shard_dirs]

    def _roots(self) -> List[Path]:
        """Every root a set directory may live under (primary first)."""
        out = [self.backup_dir]
        if self.erasure is not None:
            for r in self.shard_roots():
                if r not in out:
                    out.append(r)
        return out

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

    def _set_exists(self, key: str, ts: str) -> bool:
        return any((r / key / ts).exists() for r in self._roots())

    def _fresh_timestamp(self, key: str) -> str:
        """A timestamp no existing set of ``key`` uses (call under the key lock).

        Labels have 1-second resolution; a second backup within the same second
        waits for the next one instead of overwriting the first set.
        """
        ts = _timestamp()
        while self._set_exists(key, ts):
            time.sleep(0.2)
            ts = _timestamp()
        return ts

    @staticmethod
    def _gzip_to(plain_path: Path, gz_path: Path) -> Tuple[int, str]:
        """Stream-compress ``plain_path``; return its raw size and SHA-256."""
        sha = hashlib.sha256()
        raw_size = 0
        with open(plain_path, "rb") as fin, gzip.open(gz_path, "wb") as gz:
            for block in iter(lambda: fin.read(1024 * 1024), b""):
                raw_size += len(block)
                sha.update(block)
                gz.write(block)
        return raw_size, sha.hexdigest()

    def _chunk_file(
        self,
        plain_path: Path,
        key: str,
        ts: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """gzip ``plain_path`` and store it as a backup set; return the manifest.

        ``extra`` fields (e.g. ``source_sha256``) are recorded in the manifest.
        """
        if self.erasure is not None:
            return self._shard_file(plain_path, key, ts, extra)
        set_dir = self.backup_dir / key / ts
        set_dir.mkdir(parents=True, exist_ok=True)
        parts: List[Dict[str, Any]] = []
        compressor_path = set_dir / "_tmp.gz"
        raw_size, raw_sha = self._gzip_to(plain_path, compressor_path)
        seq = 0
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
            "format": CHUNKED_FORMAT,
            "raw_size_bytes": raw_size,
            "raw_sha256": raw_sha,
            "compression": "gzip",
            "part_bytes": self.part_bytes,
            "n_parts": len(parts),
            "parts": parts,
            "created_at": time.time(),
            **(extra or {}),
        }
        atomic_write_text(set_dir / MANIFEST, json.dumps(manifest, indent=2))
        return manifest

    def _shard_file(
        self,
        plain_path: Path,
        key: str,
        ts: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """gzip ``plain_path`` and erasure code it across the shard roots."""
        assert self.erasure is not None
        primary = self.backup_dir / key / ts
        primary.mkdir(parents=True, exist_ok=True)
        gz_path = primary / "_tmp.gz"
        try:
            raw_size, raw_sha = self._gzip_to(plain_path, gz_path)
            section = write_sharded(
                gz_path,
                storage_key=key,
                timestamp=ts,
                config=self.erasure,
                roots=self.shard_roots(),
            )
        finally:
            try:
                gz_path.unlink()
            except OSError:
                pass
        manifest = {
            "storage_key": key,
            "timestamp": ts,
            "format": RS_FORMAT,
            "raw_size_bytes": raw_size,
            "raw_sha256": raw_sha,
            "compression": "gzip",
            "n_shards": len(section["shards"]),
            "erasure": section,
            "created_at": time.time(),
            **(extra or {}),
        }
        # Replicas first, the primary manifest last: it is the commit point.
        self._publish(manifest)
        return manifest

    def _manifest_dirs(self, manifest: Dict[str, Any]) -> List[Path]:
        """Directories that should hold a manifest copy, primary last."""
        key, ts = manifest["storage_key"], manifest["timestamp"]
        primary = self.backup_dir / key / ts
        out: List[Path] = []
        roots = (manifest.get("erasure") or {}).get("roots") or []
        for r in [Path(x) for x in roots]:
            d = r / key / ts
            if d != primary and d not in out and r.is_dir():
                out.append(d)
        out.append(primary)
        return out

    def _publish(self, manifest: Dict[str, Any]) -> None:
        publish_manifest(manifest, self._manifest_dirs(manifest))

    @staticmethod
    def _file_sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()

    @staticmethod
    def check_snapshot(path: PathLike) -> None:
        """Raise :class:`SnapshotIntegrityError` unless ``path`` is a sound
        SQLite database (``PRAGMA quick_check``)."""
        try:
            conn = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            raise SnapshotIntegrityError(f"snapshot unreadable: {exc}") from exc
        try:
            rows = conn.execute("PRAGMA quick_check(20)").fetchall()
        except sqlite3.Error as exc:
            raise SnapshotIntegrityError(f"snapshot unreadable: {exc}") from exc
        finally:
            conn.close()
        msgs = [str(r[0]) for r in rows]
        if msgs != ["ok"]:
            raise SnapshotIntegrityError(
                "snapshot failed integrity check: " + "; ".join(msgs[:5])
            )

    def backup_database(self, storage_key_: str) -> Dict[str, Any]:
        """Back up a single hosted database; return its manifest.

        Refuses keys flagged in :attr:`suspect_keys` and (with
        :attr:`verify_snapshots`) any snapshot that fails SQLite's integrity
        check -- both *before* anything is written, so a damaged source can
        never push the last good sets out through rotation. The manifest
        records ``source_sha256``: the SHA-256 of the hosted file the snapshot
        was taken from, when it is known to be stable (used by the autopilot to
        match a set to the exact hosted content it came from).
        """
        if self.is_suspect(storage_key_):
            raise SnapshotIntegrityError(
                f"{storage_key_} is flagged as damaged; refusing to back it up"
            )
        rec = self.host.catalog.get_database(storage_key_)
        if rec is None:
            raise KeyError(f"no hosted database with key {storage_key_!r}")
        with FileLock(self._key_lock_path(storage_key_), timeout=60.0):
            # Re-read under the lock: a heal/re-host may just have replaced it.
            rec = self.host.catalog.get_database(storage_key_) or rec
            ts = self._fresh_timestamp(storage_key_)
            extra: Dict[str, Any] = {}
            with tempfile.TemporaryDirectory(prefix="fa-backup-") as tmpd:
                snap = Path(tmpd) / "snapshot.db"
                if rec.get("dialect") == "sqlite":
                    src = Path(rec["location"])
                    before = src.stat()
                    source_sha = self._file_sha256(src)
                    self._online_backup_sqlite(src, snap)
                    after = src.stat()
                    if (before.st_size, before.st_mtime_ns) == (
                        after.st_size,
                        after.st_mtime_ns,
                    ):
                        extra["source_sha256"] = source_sha
                else:
                    # Reassemble remote chunks (checksum-verified by
                    # materialize), then take a consistent copy.
                    materialized = self.host.materialize(storage_key_, snap)
                    snap = Path(materialized)
                    if rec.get("sha256"):
                        extra["source_sha256"] = rec["sha256"]
                if self.verify_snapshots:
                    self.check_snapshot(snap)
                manifest = self._chunk_file(snap, storage_key_, ts, extra)
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
            "erasure": self.erasure.to_dict() if self.erasure else None,
            "suspect_file": str(self.suspect_file) if self.suspect_file else None,
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
            erasure=ErasureConfig.from_dict(spec.get("erasure")),
            suspect_file=spec.get("suspect_file"),
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
        keys = [
            hosted.storage_key
            for hosted in self.host.list()
            if not self.is_suspect(hosted.storage_key)
        ]
        if not keys:
            return []
        from .backup_pool import backup_keys

        report = backup_keys(self, keys, workers=workers, use_go=use_go)
        return report["results"]

    # -- native postgres dump ------------------------------------------
    def pg_dump(self, database_url: str) -> Optional[Dict[str, Any]]:
        """Take a native ``pg_dump -Fc`` custom-format backup, then store it.

        Returns the manifest, or ``None`` if ``pg_dump`` is not available. The
        custom format (``-Fc``) is the production-recommended, restore-flexible
        format; the dump streams to a file (never through memory).
        """
        if shutil.which("pg_dump") is None:
            return None
        with FileLock(self._key_lock_path("pg_cluster_dump"), timeout=120.0):
            ts = self._fresh_timestamp("pg_cluster_dump")
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

    # -- inventory ------------------------------------------------------
    def _scan(
        self, storage_key_: Optional[str] = None
    ) -> Dict[Tuple[str, str], List[Path]]:
        """``(key, ts) -> [set dirs]`` across every root (primary dir first).

        Roots recorded in a set's manifest are included even when they are no
        longer configured, so a set is always seen (and removed) as a whole.
        """
        if storage_key_ is not None:
            _plain_name(storage_key_, "storage key")
        found: Dict[Tuple[str, str], List[Path]] = {}
        roots = self._roots()
        for root in roots:
            if not root.is_dir():
                continue
            key_dirs = (
                [root / storage_key_]
                if storage_key_
                # A shard root nested in another root is not a storage key.
                else [d for d in root.iterdir() if d.is_dir() and d not in roots]
            )
            for key_dir in key_dirs:
                if not key_dir.is_dir():
                    continue
                for set_dir in key_dir.iterdir():
                    if set_dir.is_dir():
                        found.setdefault((key_dir.name, set_dir.name), []).append(
                            set_dir
                        )
        for (key, ts), dirs in found.items():
            loaded = self._load_manifest_from(dirs)
            if loaded is None:
                continue
            for r in (loaded[0].get("erasure") or {}).get("roots") or []:
                d = Path(r) / key / ts
                if d not in dirs and d.is_dir():
                    dirs.append(d)
        return found

    @staticmethod
    def _load_manifest_from(
        dirs: List[Path],
    ) -> Optional[Tuple[Dict[str, Any], Path]]:
        for d in dirs:
            man = _read_manifest(d / MANIFEST)
            if man is not None:
                return man, d
        return None

    def _locations(self, key: str, ts: str) -> List[Path]:
        _plain_name(ts, "timestamp")
        return self._scan(key).get((key, ts), [])

    def load_manifest(
        self, storage_key_: str, timestamp: str
    ) -> Tuple[Dict[str, Any], Path]:
        """The set's manifest from the primary dir or, failing that, any replica."""
        loaded = self._load_manifest_from(self._locations(storage_key_, timestamp))
        if loaded is None:
            raise FileNotFoundError(
                f"no backup manifest for {storage_key_}/{timestamp}"
            )
        return loaded

    def _set_keys(self, storage_key_: Optional[str] = None) -> List[Tuple[str, str]]:
        return sorted(self._scan(storage_key_))

    def newest_timestamp(self, storage_key_: str) -> str:
        """Timestamp of the newest *complete* set of ``storage_key_``."""
        scan = self._scan(storage_key_)
        for key, ts in sorted(scan, reverse=True):
            if self._load_manifest_from(scan[(key, ts)]) is not None:
                return ts
        raise FileNotFoundError(f"no backups for {storage_key_!r}")

    # -- rotation / removal ---------------------------------------------
    @staticmethod
    def _delete_dirs(dirs: List[Path]) -> int:
        """Delete a set's directories; manifests go first, so an interrupted
        delete leaves manifest-less debris (cleaned by retention), never a
        manifest pointing at missing shards."""
        freed = sum(_tree_bytes(d) for d in dirs)
        for d in dirs:
            try:
                (d / MANIFEST).unlink()
            except OSError:
                pass
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)
        for d in dirs:
            # Drop the key directory if now empty (a shard root's; the primary
            # one still holds the key's lock file).
            try:
                d.parent.rmdir()
            except OSError:
                pass
        return freed

    def _rotate(self, key: str) -> None:
        """Keep the newest ``keep`` sets of ``key`` (call under the key lock)."""
        scan = self._scan(key)
        sets = sorted(scan)
        excess = len(sets) - self.keep
        for sk in sets[: max(0, excess)]:
            self._delete_dirs(scan[sk])

    def backup_sets(self) -> List[Dict[str, Any]]:
        """Inventory every on-disk backup set (for retention), oldest first.

        Each entry has ``storage_key``, ``timestamp``, ``path`` (primary dir),
        ``paths`` (every dir, across shard roots), ``bytes`` (summed over all of
        them), ``created_at`` (epoch), ``format`` and ``complete`` (a manifest
        exists -- an incomplete set is the leftover of a backup that died midway).
        """
        out: List[Dict[str, Any]] = []
        for (key, ts), dirs in self._scan().items():
            created = _timestamp_epoch(ts)
            if created is None:
                try:
                    created = dirs[0].stat().st_mtime
                except OSError:
                    continue
            loaded = self._load_manifest_from(dirs)
            out.append(
                {
                    "storage_key": key,
                    "timestamp": ts,
                    "path": str(dirs[0]),
                    "paths": [str(d) for d in dirs],
                    "bytes": sum(_tree_bytes(d) for d in dirs),
                    "created_at": created,
                    "complete": loaded is not None,
                    "format": set_format(loaded[0]) if loaded else None,
                }
            )
        out.sort(key=lambda e: (e["created_at"], e["storage_key"]))
        return out

    def remove_set(self, storage_key_: str, timestamp: str) -> int:
        """Delete one backup set everywhere (under the key's lock); bytes freed."""
        if not self._locations(storage_key_, timestamp):
            return 0
        with FileLock(self._key_lock_path(storage_key_), timeout=60.0):
            return self._delete_dirs(self._locations(storage_key_, timestamp))

    def remove_backups(self, storage_key_: str) -> int:
        """Delete every backup set of one database, in every root; bytes freed."""
        if not self._scan(storage_key_):
            key_dir = self.backup_dir / storage_key_
            if key_dir.is_dir():
                shutil.rmtree(key_dir, ignore_errors=True)
            return 0
        freed = 0
        with FileLock(self._key_lock_path(storage_key_), timeout=60.0):
            for dirs in self._scan(storage_key_).values():
                freed += self._delete_dirs(dirs)
        # The lock file is released now; drop the (empty) key directories.
        for root in self._roots():
            shutil.rmtree(root / storage_key_, ignore_errors=True)
        return freed

    def list_backups(self, storage_key_: Optional[str] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        scan = self._scan(storage_key_)
        for sk in sorted(scan):
            loaded = self._load_manifest_from(scan[sk])
            if loaded is not None:
                out.append(loaded[0])
        return out

    # -- restore --------------------------------------------------------
    def restore(
        self, storage_key_: str, timestamp: Optional[str], dest: PathLike
    ) -> Path:
        """Reassemble + decompress a backup set into ``dest`` (a SQLite file).

        ``timestamp=None`` restores the newest complete set. Erasure-coded sets
        restore from any ``k`` intact shards; the result is verified end to end
        against the original file's SHA-256 before it replaces ``dest``.
        """
        with FileLock(self._key_lock_path(storage_key_), timeout=_LOCK_TIMEOUT):
            return self._restore_unlocked(storage_key_, timestamp, dest)

    def _restore_unlocked(
        self, storage_key_: str, timestamp: Optional[str], dest: PathLike
    ) -> Path:
        """:meth:`restore` for a caller that already holds the key lock."""
        ts = timestamp or self.newest_timestamp(storage_key_)
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        manifest, man_dir = self.load_manifest(storage_key_, ts)
        fd, gz_name = tempfile.mkstemp(
            prefix=".fa-restore-", suffix=".gz", dir=str(dest.parent)
        )
        os.close(fd)
        gz_path = Path(gz_name)
        out_tmp = dest.with_name(dest.name + ".restoring")
        try:
            if set_format(manifest) == RS_FORMAT:
                sset = ShardedSet(
                    manifest, manifest_dir=man_dir, search_roots=self._roots()
                )
                decode_to_file(sset, gz_path)
            else:
                with open(gz_path, "wb") as tmp:
                    for part in self._legacy_parts(manifest, man_dir):
                        with open(part, "rb") as fh:
                            shutil.copyfileobj(fh, tmp)
            h = hashlib.sha256()
            with gzip.open(gz_path, "rb") as gz, open(out_tmp, "wb") as fout:
                for block in iter(lambda: gz.read(1024 * 1024), b""):
                    h.update(block)
                    fout.write(block)
            expected = manifest.get("raw_sha256")
            if expected and h.hexdigest() != expected:
                raise ValueError("restored file checksum mismatch")
            os.replace(out_tmp, dest)
        finally:
            for p in (gz_path, out_tmp):
                try:
                    p.unlink()
                except OSError:
                    pass
        return dest

    @staticmethod
    def _legacy_parts(manifest: Dict[str, Any], set_dir: Path) -> List[Path]:
        parts = sorted(manifest.get("parts") or [], key=lambda p: p["seq"])
        paths = []
        for part in parts:
            p = set_dir / part["name"]
            if not p.is_file():
                raise FileNotFoundError(f"backup part missing: {p}")
            paths.append(p)
        return paths

    # -- verify / repair / scrub ----------------------------------------
    def _verify_chunked(
        self, manifest: Dict[str, Any], set_dir: Path
    ) -> Dict[str, Any]:
        """Check every part is present and sized right, then decompress the
        whole stream and compare against the original SHA-256."""
        problems: List[str] = []
        parts = sorted(manifest.get("parts") or [], key=lambda p: p["seq"])
        for part in parts:
            p = set_dir / part["name"]
            if not p.is_file():
                problems.append(f"missing part {part['name']}")
            elif p.stat().st_size != int(part["bytes"]):
                problems.append(f"part {part['name']} has the wrong size")
        if not problems:
            h = hashlib.sha256()
            dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                for part in parts:
                    with open(set_dir / part["name"], "rb") as fh:
                        for block in iter(lambda: fh.read(1024 * 1024), b""):
                            h.update(dec.decompress(block))
                h.update(dec.flush())
                if not dec.eof:
                    problems.append("gzip stream is truncated")
                elif h.hexdigest() != manifest.get("raw_sha256"):
                    problems.append("content checksum mismatch")
            except zlib.error as exc:
                problems.append(f"gzip stream is corrupt: {exc}")
        ok = not problems
        return {
            "format": CHUNKED_FORMAT,
            "healthy": ok,
            "recoverable": ok,  # no redundancy: damage is permanent
            "problems": problems,
        }

    def _verify_one(self, key: str, ts: str) -> Dict[str, Any]:
        """Verify one set (call under the key lock)."""
        dirs = self._locations(key, ts)
        base: Dict[str, Any] = {"storage_key": key, "timestamp": ts}
        loaded = self._load_manifest_from(dirs)
        if loaded is None:
            return {
                **base,
                "status": "incomplete",
                "healthy": False,
                "recoverable": False,
                "problems": ["no manifest"],
            }
        manifest, man_dir = loaded
        try:
            if set_format(manifest) == RS_FORMAT:
                sset = ShardedSet(
                    manifest, manifest_dir=man_dir, search_roots=self._roots()
                )
                report = verify_set(sset)
                missing_copies = [
                    str(d)
                    for d in self._manifest_dirs(manifest)
                    if not (d / MANIFEST).is_file()
                ]
                report["missing_manifest_copies"] = missing_copies
                if missing_copies:
                    report["healthy"] = False
            else:
                report = self._verify_chunked(manifest, man_dir)
        except (KeyError, TypeError, ValueError) as exc:
            report = {
                "healthy": False,
                "recoverable": False,
                "problems": [f"invalid manifest: {exc}"],
            }
        report.update(base)
        if report["healthy"]:
            report["status"] = "healthy"
        elif report["recoverable"]:
            report["status"] = "degraded"
        else:
            report["status"] = "unrecoverable"
        return report

    def _targets(
        self, storage_key_: Optional[str], timestamp: Optional[str]
    ) -> List[Tuple[str, str]]:
        sets = self._set_keys(storage_key_)
        if timestamp is not None:
            sets = [s for s in sets if s[1] == timestamp]
            if not sets:
                raise FileNotFoundError(
                    f"no backup set {storage_key_ or '*'}/{timestamp}"
                )
        return sets

    @staticmethod
    def _summarize(sets: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for s in sets:
            counts[s["status"]] = counts.get(s["status"], 0) + 1
        return {"checked": len(sets), "by_status": counts, "sets": sets}

    def check_sets(
        self,
        key: str,
        timestamps: List[str],
        *,
        repair: bool,
        lock_timeout: float = _LOCK_TIMEOUT,
    ) -> List[Dict[str, Any]]:
        """Verify (or repair) the given sets of one key, each under the key lock.

        This is the per-key unit the verify/repair/scrub pool runs, in this
        process or in a worker subprocess. A set that cannot be checked (for
        example because its key stays locked) is reported with the status
        ``"error"`` instead of aborting the whole pass.
        """
        out: List[Dict[str, Any]] = []
        for ts in timestamps:
            try:
                with FileLock(self._key_lock_path(key), timeout=lock_timeout):
                    out.append(
                        self._repair_one(key, ts)
                        if repair
                        else self._verify_one(key, ts)
                    )
            except Exception as exc:
                out.append(_set_error(key, ts, f"{type(exc).__name__}: {exc}"))
        return out

    def _check_all(
        self,
        storage_key_: Optional[str],
        timestamp: Optional[str],
        *,
        repair: bool,
        workers: Optional[int],
        use_go: bool,
    ) -> Dict[str, Any]:
        """Verify/repair the target sets, fanned out per storage key.

        Each key's sets form one job, so no two workers ever contend for a key
        lock. With several keys the jobs run on the Go worker pool (one
        ``autopilot_worker --kind verify`` subprocess per batch) when the Go
        toolchain is present, else on a thread pool; a single key runs inline.
        The report lists the sets in target order either way.
        """
        from .autopilot_pool import run_jobs

        by_key: Dict[str, List[str]] = {}
        for key, ts in self._targets(storage_key_, timestamp):
            by_key.setdefault(key, []).append(ts)
        items = [
            {
                "storage_key": key,
                "timestamps": tss,
                "repair": repair,
                "lock_timeout": _LOCK_TIMEOUT,
            }
            for key, tss in by_key.items()
        ]
        run = run_jobs(self, "verify", items, workers=workers, use_go=use_go)
        sets: List[Dict[str, Any]] = []
        for item, res in zip(items, run["results"]):
            if isinstance(res.get("sets"), list):
                sets.extend(res["sets"])
            else:
                err = res.get("error") or "verify worker produced no result"
                sets.extend(
                    _set_error(item["storage_key"], ts, err)
                    for ts in item["timestamps"]
                )
        report = self._summarize(sets)
        report["engine"] = run["engine"]
        report["workers"] = run["workers"]
        return report

    def verify_backups(
        self,
        storage_key_: Optional[str] = None,
        timestamp: Optional[str] = None,
        *,
        workers: Optional[int] = None,
        use_go: bool = True,
    ) -> Dict[str, Any]:
        """Read back and check every (or one) backup set; nothing is modified.

        Keys are verified concurrently (see :meth:`_check_all`)."""
        return self._check_all(
            storage_key_, timestamp, repair=False, workers=workers, use_go=use_go
        )

    def _repair_one(self, key: str, ts: str) -> Dict[str, Any]:
        """Repair one set (call under the key lock)."""
        report = self._verify_one(key, ts)
        out: Dict[str, Any] = {
            "storage_key": key,
            "timestamp": ts,
            "before": report["status"],
            "repaired_shards": [],
            "relocated": [],
            "manifest_copies_restored": 0,
        }
        if report["status"] == "healthy":
            out["status"] = "healthy"
            return out
        if report.get("format") != RS_FORMAT:
            out["status"] = report["status"]
            out["error"] = (
                "not repairable: no manifest"
                if report["status"] == "incomplete"
                else "not repairable: chunked sets carry no redundancy"
            )
            return out
        manifest, man_dir = self.load_manifest(key, ts)
        sset = ShardedSet(manifest, manifest_dir=man_dir, search_roots=self._roots())
        try:
            result = repair_set(
                sset,
                writable_roots=[r for r in self.shard_roots() if r.is_dir()]
                or sset.roots(),
            )
        except UnrecoverableSet as exc:
            out["status"] = "unrecoverable"
            out["error"] = str(exc)
            return out
        new_manifest = result["manifest"] or manifest
        out["repaired_shards"] = result["repaired"]
        out["relocated"] = result["relocated"]
        dirs = self._manifest_dirs(new_manifest)
        text = json.dumps(new_manifest, indent=2)
        stale = [
            d
            for d in dirs
            if not (d / MANIFEST).is_file()
            or (d / MANIFEST).read_text(encoding="utf-8") != text
        ]
        if stale:
            for d in dirs:  # primary last
                if d in stale:
                    d.mkdir(parents=True, exist_ok=True)
                    atomic_write_text(d / MANIFEST, text)
            out["manifest_copies_restored"] = len(stale)
        after = self._verify_one(key, ts)
        out["status"] = "repaired" if after["healthy"] else after["status"]
        return out

    def repair_backups(
        self,
        storage_key_: Optional[str] = None,
        timestamp: Optional[str] = None,
        *,
        workers: Optional[int] = None,
        use_go: bool = True,
    ) -> Dict[str, Any]:
        """Rebuild lost/corrupt shards and manifest copies of erasure-coded sets.

        Keys are repaired concurrently (see :meth:`_check_all`)."""
        return self._check_all(
            storage_key_, timestamp, repair=True, workers=workers, use_go=use_go
        )

    def scrub(
        self,
        *,
        repair: bool = True,
        workers: Optional[int] = None,
        use_go: bool = True,
    ) -> Dict[str, Any]:
        """Verify every set; with ``repair``, heal the degraded erasure-coded ones.

        The sets of different keys are checked concurrently on the Go worker
        pool (or a thread pool without Go); ``workers`` caps the concurrency."""
        started = time.time()
        report = self._check_all(
            None, None, repair=repair, workers=workers, use_go=use_go
        )
        report.update(
            {"repair": repair, "started_at": started, "finished_at": time.time()}
        )
        self.last_scrub = {k: v for k, v in report.items() if k != "sets"}
        self.last_scrub["problems"] = [
            s for s in report["sets"] if s["status"] not in ("healthy",)
        ][:50]
        return report

    # -- periodic loops -------------------------------------------------
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

    def start_scrub(
        self,
        interval: float,
        *,
        repair: bool = True,
        workers: Optional[int] = None,
        use_go: bool = True,
    ) -> "BackupManager":
        """Run :meth:`scrub` every ``interval`` seconds on a daemon thread."""
        if self._scrub_thread is not None or interval <= 0:
            return self
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.scrub(repair=repair, workers=workers, use_go=use_go)
                except Exception as exc:  # never let a scrub failure kill the loop
                    self.last_scrub = {"error": str(exc), "finished_at": time.time()}

        self._scrub_thread = threading.Thread(
            target=_loop, name="fa-backup-scrub", daemon=True
        )
        self._scrub_thread.start()
        return self

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        for attr in ("_thread", "_scrub_thread"):
            t = getattr(self, attr)
            if t is not None:
                t.join(timeout=timeout)
                setattr(self, attr, None)
