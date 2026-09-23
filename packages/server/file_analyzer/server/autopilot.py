"""
Autopilot -- self-checking, self-healing maintenance for a hosting server.

The server already *can* back up, scrub, restore and apply retention; the
autopilot is what makes it do the right one of those on its own, in the right
order, and repair what it finds. One maintenance **tick** runs these tasks (each
on its own schedule, all skippable/forceable):

1. ``catalog``   -- integrity-check the session catalog (SQLite target). While
   it is healthy, keep a few rolling online-backup *snapshots* of it; when it is
   damaged or gone, rebuild it: newest sound snapshot + every row still
   readable from the damaged file (row-by-row salvage around bad pages) + this
   server's own session row, verified, then atomically swapped in with the
   damaged file quarantined.
2. ``scrub``     -- verify every backup set block by block and rebuild damaged
   or lost Reed-Solomon shards. A set that stays unrecoverable for a grace
   period (and whose shard directories are all still present -- an unmounted
   disk never causes deletion) is dropped and a fresh backup is requested.
3. ``check``     -- health-check every hosted database: a cheap structural pass
   every tick (``stat`` + SQLite header sanity, or chunk-row accounting for a
   remote backend), escalating to a SHA-256 comparison against the catalog
   checksum plus ``PRAGMA quick_check`` when anything changed, and a full
   ``PRAGMA integrity_check`` on the deep schedule. Verdicts: ``healthy``,
   ``missing``, ``corrupt`` (fails integrity), ``drifted`` (sound SQLite, but
   not the content that was hosted), ``error`` (transient, e.g. locked).
   Damaged keys are flagged *suspect* so no backup of them can rotate the last
   good sets out.
4. ``heal``      -- under the key's lock: re-check, then restore the newest
   backup set that is an *exact* copy of the hosted content (matched by
   checksum lineage), falling back -- if allowed -- to an older *rollback* set.
   Every candidate is restored to a temp file, SHA-verified and
   ``integrity_check``-ed before it is installed atomically; the damaged file is
   preserved in ``quarantine/`` with a ``reason.json``. Drift can instead be
   *adopted* (``drift_action="adopt"``); a database whose file is gone and that
   has no backups is dropped from the catalog after ``lost_grace``.
5. ``backup``    -- make sure every healthy database has a recent exact backup
   (none yet, only stale ones, or only sets of other content -> back up now).
6. ``retention`` -- run the retention janitor (time + space limits).
7. ``sweep``     -- remove debris older than ``debris_max_age`` (half-written
   restores/heals/shards/temp files, dead servers' endpoint/PID files and
   catalog rows, expired quarantine), and re-adopt *orphaned* hosted files of
   this session (a file named for this session's storage key with no catalog
   row, e.g. after a catalog rollback) once they pass ``integrity_check`` --
   quarantining those that do not.

State (per-database health cache, checksum lineage, schedules, events) lives in
``<run_dir>/autopilot.json`` and ticks are serialized across processes by
``<run_dir>/autopilot.lock``, so several server instances of one repository
cooperate instead of racing. Every mutation of a database happens under the
same per-key lock backups, restores and retention use.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import struct
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

from ..naming import storage_key as make_storage_key
from ..tokens import (
    PathLike,
    canonical_root,
    project_fingerprint,
    project_slug,
    sanitize_db_name,
)
from .backup import BackupManager
from .daemon import pid_alive
from .dbhost import DatabaseHost
from .locking import FileLock, LockTimeout, atomic_write_text
from .retention import RetentionManager

log = logging.getLogger("file_analyzer.server.autopilot")

SQLITE_MAGIC = b"SQLite format 3\x00"

HEALTHY = "healthy"
MISSING = "missing"
CORRUPT = "corrupt"
DRIFTED = "drifted"
ERROR = "error"
PROBLEM_STATUSES = (MISSING, CORRUPT, DRIFTED)

#: Maintenance tasks, in the order one tick runs them.
TASKS = ("catalog", "scrub", "check", "heal", "backup", "retention", "sweep")
DRIFT_ACTIONS = ("restore", "adopt", "report")

_MAX_EVENTS = 200
_MAX_SALVAGE_PROBES = 100_000
_CATALOG_TABLES = ("sessions", "databases", "servers", "database_access")


# ====================================================================== #
# SQLite file checks
# ====================================================================== #
def _ro_uri(path: PathLike) -> str:
    return "file:" + quote(Path(path).resolve().as_posix(), safe="/:") + "?mode=ro"


def sqlite_header_problems(path: PathLike, size: Optional[int] = None) -> List[str]:
    """Cheap structural sanity of a SQLite file from its 100-byte header.

    Checks the magic string, that the page size is a power of two in
    [512, 65536], that the file is a whole number of pages, and -- when the
    header's in-file page count is valid and no WAL is pending -- that the file
    is not shorter than the header says (truncation). An empty file is a valid
    empty database. Returns a list of problems (empty when sane).
    """
    p = Path(path)
    try:
        if size is None:
            size = p.stat().st_size
        with open(p, "rb") as fh:
            hdr = fh.read(100)
    except OSError as exc:
        return [f"unreadable: {exc}"]
    if size == 0:
        return []
    if len(hdr) < 100:
        return [f"truncated: {size} bytes is shorter than the 100-byte header"]
    if hdr[:16] != SQLITE_MAGIC:
        return ["not a SQLite database (bad header magic)"]
    page_size = struct.unpack(">H", hdr[16:18])[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        return [f"invalid page size {page_size}"]
    problems: List[str] = []
    if size % page_size:
        problems.append(
            f"file size {size} is not a multiple of the page size {page_size}"
        )
    change_counter = struct.unpack(">I", hdr[24:28])[0]
    n_pages = struct.unpack(">I", hdr[28:32])[0]
    valid_for = struct.unpack(">I", hdr[92:96])[0]
    wal = p.with_name(p.name + "-wal")
    try:
        wal_pending = wal.stat().st_size > 0
    except OSError:
        wal_pending = False
    if n_pages and valid_for == change_counter and not wal_pending:
        if n_pages * page_size > size:
            problems.append(
                f"truncated: header declares {n_pages} pages "
                f"({n_pages * page_size} bytes) but the file has {size}"
            )
    return problems


def sqlite_integrity(
    path: PathLike, *, quick: bool = True, max_errors: int = 100
) -> Tuple[str, List[str]]:
    """Run ``PRAGMA quick_check``/``integrity_check`` read-only.

    Returns ``("ok", [])``, ``("corrupt", messages)`` or ``("error", [msg])``
    for a transient condition (locked/busy/cannot open) that says nothing
    about the file's soundness.
    """
    pragma = "quick_check" if quick else "integrity_check"
    try:
        conn = sqlite3.connect(_ro_uri(path), uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        return _classify_sqlite_error(exc)
    try:
        rows = conn.execute(f"PRAGMA {pragma}({int(max_errors)})").fetchall()
    except sqlite3.Error as exc:
        return _classify_sqlite_error(exc)
    finally:
        conn.close()
    msgs = [str(r[0]) for r in rows]
    if msgs == ["ok"]:
        return "ok", []
    return "corrupt", msgs


def _classify_sqlite_error(exc: Exception) -> Tuple[str, List[str]]:
    msg = str(exc)
    low = msg.lower()
    if isinstance(exc, sqlite3.OperationalError) and any(
        w in low for w in ("locked", "busy", "unable to open", "readonly")
    ):
        return "error", [msg]
    return "corrupt", [msg]


def _sha256_file(path: PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _unlink_quiet(*paths: Path) -> None:
    for p in paths:
        try:
            p.unlink()
        except OSError:
            pass


def _sidecars(path: Path) -> List[Path]:
    return [path.with_name(path.name + s) for s in ("-wal", "-shm", "-journal")]


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def _age(path: Path, now: float) -> Optional[float]:
    try:
        return now - path.stat().st_mtime
    except OSError:
        return None


def _remove_path(path: Path) -> int:
    """Delete a file or tree; bytes freed (0 if it was already gone)."""
    freed = 0
    try:
        if path.is_dir() and not path.is_symlink():
            for f in path.rglob("*"):
                try:
                    if f.is_file():
                        freed += f.stat().st_size
                except OSError:
                    pass
            shutil.rmtree(path, ignore_errors=True)
        else:
            freed = path.stat().st_size
            path.unlink()
    except OSError:
        return 0
    return freed


# ====================================================================== #
# Per-database checks and restore staging (shared with the pool workers)
# ====================================================================== #
def check_database(
    dbhost: DatabaseHost,
    rec: Dict[str, Any],
    entry: Dict[str, Any],
    *,
    deep: bool,
    triage: bool = False,
) -> Optional[Tuple[str, List[str]]]:
    """Health-check one hosted database; returns ``(status, problems)``.

    ``entry`` is the database's cached health entry (size, mtime, checksum,
    last verdict); it is updated in place. The cheap structural pass (stat +
    header, or chunk accounting for a remote backend) decides whether the
    expensive pass (SHA-256 + ``quick_check``/``integrity_check``) is needed.
    With ``triage=True`` the expensive pass is not run: ``None`` is returned
    instead (and ``entry`` is untouched) so the caller can fan those checks
    out across the worker pool.
    """
    if rec.get("dialect") == "sqlite":
        return _check_sqlite(rec, entry, deep=deep, triage=triage)
    return _check_remote(dbhost, rec, entry, deep=deep, triage=triage)


def _check_sqlite(
    rec: Dict[str, Any], entry: Dict[str, Any], *, deep: bool, triage: bool
) -> Optional[Tuple[str, List[str]]]:
    loc = Path(rec.get("location") or "")
    try:
        st = loc.stat()
    except FileNotFoundError:
        for k in ("size", "mtime_ns", "sha"):
            entry.pop(k, None)
        return MISSING, [f"hosted file is missing: {loc.name}"]
    header = sqlite_header_problems(loc, st.st_size)
    changed = (
        entry.get("size") != st.st_size
        or entry.get("mtime_ns") != st.st_mtime_ns
        or int(rec.get("size_bytes") or 0) != st.st_size
    )
    if not (changed or header or deep or entry.get("status") != HEALTHY):
        return HEALTHY, []
    if triage:
        return None
    sha = _sha256_file(loc)
    entry.update({"size": st.st_size, "mtime_ns": st.st_mtime_ns, "sha": sha})
    if deep:
        entry["deep_at"] = time.time()
    expected = rec.get("sha256")
    if expected and sha == expected and not deep:
        return HEALTHY, []
    verdict, msgs = sqlite_integrity(loc, quick=not deep)
    if verdict == "error":
        return ERROR, msgs
    if verdict == "corrupt" or header:
        return CORRUPT, header + msgs
    if expected and sha != expected:
        return DRIFTED, [
            "content no longer matches the hosted checksum "
            f"(expected {expected[:12]}..., found {sha[:12]}...)"
        ]
    return HEALTHY, []


def _check_remote(
    dbhost: DatabaseHost,
    rec: Dict[str, Any],
    entry: Dict[str, Any],
    *,
    deep: bool,
    triage: bool,
) -> Optional[Tuple[str, List[str]]]:
    key = rec["storage_key"]
    stats = dbhost.chunk_stats(key)
    n = stats["n_chunks"]
    size = int(rec.get("size_bytes") or 0)
    if n == 0 and size > 0:
        return MISSING, ["no content chunks stored"]
    problems = []
    declared = rec.get("n_chunks")
    if declared is not None and int(declared) != n:
        problems.append(f"{n} chunks stored, catalog declares {declared}")
    if stats["total_bytes"] != size:
        problems.append(
            f"chunks hold {stats['total_bytes']} bytes, catalog declares {size}"
        )
    if n and (stats["min_seq"] != 0 or stats["max_seq"] != n - 1):
        problems.append("chunk sequence has gaps")
    full = bool(problems) or deep or entry.get("status") != HEALTHY
    if not full:
        return HEALTHY, []
    if triage:
        return None
    tmp = Path(dbhost.data_dir) / (
        f".{key}.check.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    try:
        dbhost._read_chunks(key, tmp)
        sha = _sha256_file(tmp)
        entry["sha"] = sha
        if deep:
            entry["deep_at"] = time.time()
        expected = rec.get("sha256")
        if expected and sha == expected and not deep and not problems:
            return HEALTHY, []
        verdict, msgs = sqlite_integrity(tmp, quick=not deep)
    finally:
        _unlink_quiet(tmp, *_sidecars(tmp))
    if verdict == "error":
        return ERROR, msgs
    if verdict == "corrupt":
        return CORRUPT, problems + msgs
    if problems or (expected and sha != expected):
        return DRIFTED, problems or [
            "content no longer matches the hosted checksum "
            f"(expected {expected[:12]}..., found {sha[:12]}...)"
        ]
    return HEALTHY, []


def healing_path(data_dir: PathLike, key: str) -> Path:
    """Where a heal stages the restored copy of ``key`` before installing it."""
    return Path(data_dir) / f".{key}.db.healing"


def stage_restore(
    backups: BackupManager,
    key: str,
    candidates: Sequence[Dict[str, Any]],
    dest: PathLike,
) -> Dict[str, Any]:
    """Restore ``candidates`` (newest first) into ``dest`` until one is sound.

    Each candidate backup set is restored (end-to-end checksum-verified by the
    backup manager) and must then pass a full ``integrity_check``. The first
    one that does is left at ``dest`` and reported; failed attempts are listed
    in ``failures``. The caller must hold the key lock (no lock is taken here)
    and installs -- or discards -- the staged file.
    """
    dest = Path(dest)
    failures: List[Dict[str, Any]] = []
    for index, cand in enumerate(candidates):
        ts = cand["timestamp"]
        _unlink_quiet(dest, *_sidecars(dest))
        try:
            backups._restore_unlocked(key, ts, dest)
            verdict, msgs = sqlite_integrity(dest, quick=False)
        except Exception as exc:
            failures.append({"timestamp": ts, "error": f"{type(exc).__name__}: {exc}"})
            continue
        if verdict != "ok":
            failures.append(
                {
                    "timestamp": ts,
                    "error": "restored copy failed integrity_check",
                    "problems": msgs[:5],
                }
            )
            continue
        return {
            "storage_key": key,
            "staged": str(dest),
            "timestamp": ts,
            "kind": cand.get("kind"),
            "index": index,
            "failures": failures,
        }
    _unlink_quiet(dest, *_sidecars(dest))
    return {"storage_key": key, "staged": None, "failures": failures}


# ====================================================================== #
# Policy
# ====================================================================== #
@dataclass
class AutopilotPolicy:
    """What the autopilot checks, how often, and what it is allowed to fix.

    Intervals are seconds; ``0`` (or ``None``) disables a scheduled task (it
    still runs when asked for explicitly).
    """

    #: Seconds between maintenance ticks (each tick runs whatever is due).
    interval: float = 300.0
    #: Delay before the first tick after the server starts.
    startup_delay: float = 30.0
    #: Structural check + catalog check cadence.
    check_interval: float = 900.0
    #: Full ``integrity_check`` of every hosted database.
    deep_check_interval: float = 86400.0
    #: Backup-set verification/repair cadence.
    scrub_interval: float = 86400.0
    #: Retention janitor cadence.
    retention_interval: float = 3600.0
    #: Debris/orphan sweep cadence.
    sweep_interval: float = 3600.0
    #: Restore damaged/missing databases from backups.
    heal: bool = True
    #: When no exact backup exists, allow restoring an older (different) one.
    allow_rollback: bool = True
    #: What to do with a sound database whose checksum no longer matches.
    drift_action: str = "restore"
    #: Back up healthy databases that lack a recent exact backup.
    ensure_backups: bool = True
    #: Max age of the newest exact backup before a new one is taken.
    backup_max_age: Optional[float] = 1860.0
    #: Rebuild damaged/lost erasure-coded shards during the scrub.
    repair_backups: bool = True
    #: Drop backup sets that stay unrecoverable for ``unrecoverable_grace``.
    drop_unrecoverable_backups: bool = True
    unrecoverable_grace: float = 86400.0
    #: A hosted file gone with nothing to restore is dropped after this long.
    lost_grace: float = 86400.0
    #: Temp/partial files older than this are debris.
    debris_max_age: float = 3600.0
    #: Quarantined damaged files are kept this long.
    quarantine_max_age: float = 7 * 86400.0
    #: Rolling catalog snapshots kept (0 disables snapshots).
    catalog_snapshots: int = 3
    catalog_snapshot_interval: float = 3600.0
    #: Re-register orphaned hosted files of this session.
    adopt_orphans: bool = True
    #: Seconds to wait for a database's key lock before giving up this tick.
    lock_timeout: float = 60.0
    #: Concurrent workers for checks, backup verification and heal staging
    #: (``None``/``0``: sized to the work, 4..32; ``1``: run inline).
    workers: Optional[int] = None
    #: Fan the work out on the Go worker pool when the Go toolchain is present
    #: (otherwise, or when False, a thread pool is used).
    use_go: bool = True

    def __post_init__(self) -> None:
        if self.drift_action not in DRIFT_ACTIONS:
            raise ValueError(
                f"drift_action must be one of {DRIFT_ACTIONS}, "
                f"not {self.drift_action!r}"
            )
        for name in (
            "interval",
            "startup_delay",
            "check_interval",
            "deep_check_interval",
            "scrub_interval",
            "retention_interval",
            "sweep_interval",
            "unrecoverable_grace",
            "lost_grace",
            "debris_max_age",
            "quarantine_max_age",
            "catalog_snapshot_interval",
            "lock_timeout",
        ):
            value = getattr(self, name)
            setattr(self, name, max(0.0, float(value or 0.0)))
        if self.backup_max_age is not None:
            self.backup_max_age = float(self.backup_max_age)
            if self.backup_max_age <= 0:
                self.backup_max_age = None
        self.catalog_snapshots = max(0, int(self.catalog_snapshots))
        if self.workers is not None:
            if int(self.workers) < 0:
                raise ValueError("workers must be >= 0")
            self.workers = int(self.workers) or None
        self.use_go = bool(self.use_go)

    def task_interval(self, task: str) -> float:
        return {
            "catalog": self.check_interval,
            "scrub": self.scrub_interval,
            "check": self.check_interval,
            "sweep": self.sweep_interval,
            "retention": self.retention_interval,
        }.get(task, 0.0)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ====================================================================== #
# Autopilot
# ====================================================================== #
class Autopilot:
    """Runs checks, heals, backups, retention and sweeps for one server."""

    def __init__(
        self,
        dbhost: DatabaseHost,
        backups: BackupManager,
        retention: RetentionManager,
        *,
        run_dir: PathLike,
        policy: Optional[AutopilotPolicy] = None,
        quarantine_dir: Optional[PathLike] = None,
        own_server_id: Optional[str] = None,
        backend: str = "sqlite",
        on_catalog_restored: Optional[Callable[[], None]] = None,
    ) -> None:
        self.dbhost = dbhost
        self.backups = backups
        self.retention = retention
        self.catalog = dbhost.catalog
        self.policy = policy or AutopilotPolicy()
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.run_dir / "autopilot.json"
        self.lock_path = self.run_dir / "autopilot.lock"
        self.suspect_path = self.run_dir / "suspect.json"
        self.quarantine_dir = Path(
            quarantine_dir or Path(dbhost.data_dir).parent / "quarantine"
        )
        self.own_server_id = own_server_id
        self.backend = backend
        self.on_catalog_restored = on_catalog_restored
        self.last_report: Optional[Dict[str, Any]] = None
        self.last_error: Optional[str] = None
        #: Engine/worker count of the most recent worker-pool fan-out.
        self.last_pool: Optional[Dict[str, Any]] = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._forced: set = set()
        self._state: Dict[str, Any] = self._load_state()
        # Pick up damage flags persisted by an earlier run / another instance.
        self.backups.suspect_keys.update(self._suspect_keys(self._state))

    # -- state ------------------------------------------------------------
    @staticmethod
    def _empty_state() -> Dict[str, Any]:
        return {
            "version": 1,
            "tasks": {},
            "databases": {},
            "lineage": {},
            "unrecoverable_sets": {},
            "needs_backup": [],
            "events": [],
        }

    def _load_state(self) -> Dict[str, Any]:
        state = self._empty_state()
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return state
        except (OSError, ValueError) as exc:
            # A torn/corrupt state file costs only cached knowledge: start over.
            state["events"].append(
                {"at": time.time(), "kind": "state-reset", "error": str(exc)}
            )
            return state
        if not isinstance(data, dict):
            return state
        for k, default in state.items():
            v = data.get(k)
            if isinstance(v, type(default)):
                state[k] = v
        return state

    def _save_state(self, state: Dict[str, Any]) -> None:
        state["events"] = state["events"][-_MAX_EVENTS:]
        atomic_write_text(self.state_path, json.dumps(state, indent=1, default=str))

    @staticmethod
    def _suspect_keys(state: Dict[str, Any]) -> List[str]:
        return sorted(
            k
            for k, e in state["databases"].items()
            if e.get("status") in PROBLEM_STATUSES
        )

    def _publish_suspects(self, state: Dict[str, Any], dry_run: bool) -> None:
        keys = self._suspect_keys(state)
        if dry_run:
            return
        self.backups.suspect_keys.clear()
        self.backups.suspect_keys.update(keys)
        self.backups.suspect_file = self.suspect_path
        atomic_write_text(
            self.suspect_path,
            json.dumps({"keys": keys, "updated_at": time.time()}, indent=1),
        )

    @staticmethod
    def _event(state: Dict[str, Any], kind: str, **fields: Any) -> Dict[str, Any]:
        ev = {"at": time.time(), "kind": kind, **fields}
        state["events"].append(ev)
        log.info("autopilot %s %s", kind, fields)
        return ev

    # -- scheduling -------------------------------------------------------
    def _task_state(self, state: Dict[str, Any], task: str) -> Dict[str, Any]:
        return state["tasks"].setdefault(task, {})

    def _due(
        self, state: Dict[str, Any], task: str, now: float, *, wait_first: bool
    ) -> bool:
        """Whether a scheduled task is due. ``wait_first`` tasks wait one full
        interval from when the autopilot first saw them (so a fresh server does
        not immediately run an expensive scrub/retention pass)."""
        interval = self.policy.task_interval(task)
        if interval <= 0:
            return False
        ts = self._task_state(state, task)
        last = ts.get("last_run")
        if last is None:
            if not wait_first:
                return True
            first = ts.setdefault("first_seen", now)
            return now - float(first) >= interval
        return now - float(last) >= interval

    def _next_due_in(self, state: Dict[str, Any], now: float) -> Optional[float]:
        best: Optional[float] = None
        for task in ("catalog", "scrub", "check", "sweep", "retention"):
            interval = self.policy.task_interval(task)
            if interval <= 0:
                continue
            ts = state["tasks"].get(task, {})
            anchor = ts.get("last_run") or ts.get("first_seen")
            left = 0.0 if anchor is None else float(anchor) + interval - now
            best = left if best is None else min(best, left)
        return best

    # -- one tick ---------------------------------------------------------
    def run_once(
        self,
        *,
        dry_run: bool = False,
        tasks: Optional[Sequence[str]] = None,
        force: bool = False,
        wait: bool = False,
    ) -> Dict[str, Any]:
        """Run one maintenance tick; return its report.

        ``tasks`` limits (and forces) the tick to the named tasks; ``force``
        runs every task regardless of its schedule. ``dry_run`` reports what
        would be done and modifies nothing (not even the state file). When
        another process/thread is mid-tick the call returns
        ``{"skipped": True}`` immediately, or waits for it with ``wait=True``.
        """
        wanted = list(tasks) if tasks else list(TASKS)
        unknown = [t for t in wanted if t not in TASKS]
        if unknown:
            raise ValueError(f"unknown autopilot task(s) {unknown}; valid: {TASKS}")
        explicit = set(wanted) if tasks else set()
        lock = FileLock(
            self.lock_path, timeout=(self.policy.lock_timeout * 10 if wait else 0.0)
        )
        try:
            lock.acquire()
        except LockTimeout:
            return {"skipped": True, "reason": "another maintenance run is active"}
        try:
            return self._run_locked(wanted, explicit, force, dry_run)
        finally:
            lock.release()

    def _run_locked(
        self, wanted: List[str], explicit: set, force: bool, dry_run: bool
    ) -> Dict[str, Any]:
        state = self._load_state()
        now = time.time()
        report: Dict[str, Any] = {
            "started_at": now,
            "dry_run": dry_run,
            "tasks": {},
            "actions": [],
        }
        ran_check = False
        self._forced = set(TASKS) if force else set(explicit)
        for task in TASKS:
            if task not in wanted:
                continue
            forced = force or task in explicit
            if task == "heal":
                due = forced or (self.policy.heal and ran_check)
            elif task == "backup":
                due = forced or (
                    self.policy.ensure_backups
                    and (ran_check or bool(state["needs_backup"]))
                )
            else:
                due = forced or self._due(
                    state, task, now, wait_first=task in ("scrub", "retention")
                )
            if not due:
                continue
            fn = getattr(self, f"_task_{task}")
            try:
                result = fn(state, report, dry_run)
            except Exception as exc:  # one task failing never stops the tick
                log.exception("autopilot task %s failed", task)
                result = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
                self._event(state, "task-failed", task=task, error=str(exc))
            report["tasks"][task] = result
            ts = self._task_state(state, task)
            if not dry_run:
                ts["last_run"] = time.time()
                ts["last_status"] = result.get("status", "ok")
            if task == "check" and result.get("status") != "failed":
                ran_check = True
            if task in ("check", "heal") and not dry_run:
                # Flag damage before anything can back it up; clear healed keys
                # before the backup task runs.
                self._publish_suspects(state, dry_run)
        report["problems"] = [
            {
                "storage_key": k,
                "status": e.get("status"),
                "problems": e.get("problems", []),
            }
            for k, e in sorted(state["databases"].items())
            if e.get("status") in PROBLEM_STATUSES + (ERROR,)
        ]
        catalog_res = report["tasks"].get("catalog") or {}
        report["healthy"] = not report["problems"] and catalog_res.get("status") in (
            None,
            "ok",
            "skipped",
            "recovered",
        )
        report["finished_at"] = time.time()
        self._forced = set()
        if not dry_run:
            self._publish_suspects(state, dry_run)
            self._save_state(state)
        self._state = state
        self.last_report = report
        return report

    # -- background loop --------------------------------------------------
    def start(self) -> "Autopilot":
        if self._thread is not None:
            return self
        self._stop.clear()
        self._wake.clear()

        def _loop() -> None:
            if self._stop.wait(self.policy.startup_delay):
                return
            while not self._stop.is_set():
                try:
                    self.run_once()
                    self.last_error = None
                except Exception as exc:  # never let the loop die
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    log.exception("autopilot tick failed")
                delay = self.policy.interval or 300.0
                left = self._next_due_in(self._state, time.time())
                if left is not None:
                    delay = min(delay, left)
                self._wake.wait(max(1.0, delay))
                self._wake.clear()

        self._thread = threading.Thread(target=_loop, name="fa-autopilot", daemon=True)
        self._thread.start()
        return self

    def trigger(self) -> None:
        """Wake the background loop now (it still honours task schedules)."""
        self._wake.set()

    def stop(self, timeout: float = 30.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> Dict[str, Any]:
        """Policy, schedule, per-database health and recent events."""
        state = self._load_state()
        now = time.time()
        tasks = {}
        for task in TASKS:
            ts = state["tasks"].get(task, {})
            interval = self.policy.task_interval(task)
            anchor = ts.get("last_run") or ts.get("first_seen")
            tasks[task] = {
                "last_run": ts.get("last_run"),
                "last_status": ts.get("last_status"),
                "interval": interval or None,
                "next_due": (
                    None
                    if interval <= 0 or anchor is None
                    else float(anchor) + interval
                ),
            }
        dbs = {
            k: {
                "status": e.get("status"),
                "problems": e.get("problems", []),
                "checked_at": e.get("checked_at"),
                "deep_checked_at": e.get("deep_at"),
                "lost_since": e.get("lost_since"),
                "last_heal_attempt": e.get("heal_at"),
            }
            for k, e in sorted(state["databases"].items())
        }
        last = self.last_report
        return {
            "running": self.running,
            "policy": self.policy.to_dict(),
            "now": now,
            "tasks": tasks,
            "databases": dbs,
            "suspect_keys": self._suspect_keys(state),
            "pending_backups": sorted(state["needs_backup"]),
            "unrecoverable_backup_sets": state["unrecoverable_sets"],
            "events": state["events"][-20:],
            "last_error": self.last_error,
            "last_pool": self.last_pool,
            "last_run": (
                None
                if last is None
                else {
                    k: last[k]
                    for k in ("started_at", "finished_at", "dry_run", "healthy")
                }
                | {"tasks": sorted(last["tasks"]), "problems": last["problems"]}
            ),
        }

    # ================================================================== #
    # task: catalog
    # ================================================================== #
    def _catalog_path(self) -> Optional[Path]:
        target = str(self.catalog.target)
        if target.startswith("sqlite:///"):
            return Path(target[len("sqlite:///") :])
        if "://" in target:
            return None
        return Path(target)

    @property
    def _snapshot_dir(self) -> Path:
        return self.catalog.dir / "snapshots"

    def _catalog_health(self, path: Path) -> Tuple[str, List[str]]:
        if not path.is_file():
            return MISSING, ["catalog file is missing"]
        status, msgs = sqlite_integrity(path, quick=True)
        if status != "ok":
            return (CORRUPT if status == "corrupt" else ERROR), msgs
        try:
            conn = sqlite3.connect(_ro_uri(path), uri=True, timeout=5.0)
            try:
                names = {
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            finally:
                conn.close()
        except sqlite3.Error as exc:
            kind, emsgs = _classify_sqlite_error(exc)
            return (ERROR if kind == "error" else CORRUPT), emsgs
        absent = [t for t in _CATALOG_TABLES if t not in names]
        if absent:
            return CORRUPT, [f"catalog tables missing: {', '.join(absent)}"]
        return "ok", []

    def _task_catalog(
        self, state: Dict[str, Any], report: Dict[str, Any], dry_run: bool
    ) -> Dict[str, Any]:
        path = self._catalog_path()
        if path is None:
            return {"status": "skipped", "reason": "remote catalog"}
        status, msgs = self._catalog_health(path)
        out: Dict[str, Any] = {"status": status, "problems": msgs}
        if status == "ok":
            ts = self._task_state(state, "catalog")
            last = float(ts.get("snapshot_at") or 0.0)
            if (
                not dry_run
                and self.policy.catalog_snapshots > 0
                and time.time() - last >= self.policy.catalog_snapshot_interval
            ):
                snap = self._snapshot_catalog(path)
                if snap is not None:
                    out["snapshot"] = snap
                    ts["snapshot_at"] = time.time()
            return out
        if status == ERROR:
            return out  # transient; look again next tick
        if dry_run:
            out["action"] = "would-recover"
            return out
        out["recovery"] = self._recover_catalog(path)
        if out["recovery"].get("recovered"):
            out["status"] = "recovered"
            report["actions"].append({"task": "catalog", "action": "recovered"})
            self._event(
                state,
                "catalog-recovered",
                problems=msgs[:5],
                snapshot=out["recovery"].get("snapshot"),
                salvaged=out["recovery"].get("salvaged"),
            )
        return out

    def _snapshots(self) -> List[Path]:
        d = self._snapshot_dir
        if not d.is_dir():
            return []
        return sorted(d.glob("catalog-*.db"))

    def _snapshot_catalog(self, path: Path) -> Optional[str]:
        """Online-backup the catalog into ``snapshots/`` and keep the newest N."""
        d = self._snapshot_dir
        d.mkdir(parents=True, exist_ok=True)
        lock = FileLock(d / ".snapshot.lock", timeout=0.0)
        try:
            lock.acquire()
        except LockTimeout:
            return None  # another instance is snapshotting right now
        try:
            name = f"catalog-{_stamp()}-{os.getpid()}.db"
            tmp = d / f".{name}.tmp"
            _unlink_quiet(tmp)
            self._sqlite_copy(path, tmp)
            if sqlite_integrity(tmp, quick=True)[0] != "ok":
                _unlink_quiet(tmp)
                return None
            os.replace(tmp, d / name)
            snaps = self._snapshots()
            for old in snaps[: max(0, len(snaps) - self.policy.catalog_snapshots)]:
                _unlink_quiet(old)
            return str(d / name)
        finally:
            lock.release()

    @staticmethod
    def _sqlite_copy(src: Path, dest: Path) -> None:
        """Consistent copy via the online backup API, as a rollback-journal
        (non-WAL) file so it is self-contained."""
        s = sqlite3.connect(_ro_uri(src), uri=True, timeout=10.0)
        try:
            t = sqlite3.connect(str(dest))
            try:
                s.backup(t)
                t.execute("PRAGMA journal_mode=DELETE")
                t.commit()
            finally:
                t.close()
        finally:
            s.close()

    def _recover_catalog(self, path: Path) -> Dict[str, Any]:
        """Rebuild a damaged/missing catalog (snapshot + salvage + own session)."""
        from .catalog import SessionCatalog

        cat = self.catalog
        out: Dict[str, Any] = {"recovered": False}
        with FileLock(cat.lock_path, timeout=cat.lock_timeout):
            status, msgs = self._catalog_health(path)
            if status in ("ok", ERROR):
                out["reason"] = (
                    "healthy on re-check" if status == "ok" else "transient error"
                )
                return out
            work = cat.dir / f".catalog.recover-{os.getpid()}.db"
            _unlink_quiet(work, *_sidecars(work))
            try:
                for snap in reversed(self._snapshots()):
                    if sqlite_integrity(snap, quick=False)[0] == "ok":
                        shutil.copyfile(snap, work)
                        out["snapshot"] = str(snap)
                        break
                # Create any table the snapshot lacks (or all, with none).
                scratch = SessionCatalog(cat.dir, target=str(work))
                store = scratch._store()
                try:
                    scratch._ensure_schema(store)
                finally:
                    store.close()
                if path.is_file():
                    out["salvaged"] = self._salvage_rows(path, work)
                conn = sqlite3.connect(str(work))
                try:
                    now = time.time()
                    conn.execute(
                        "INSERT OR IGNORE INTO sessions (fingerprint, project_root, "
                        "token, backend, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            project_fingerprint(self.dbhost.root),
                            canonical_root(self.dbhost.root),
                            self.dbhost.token,
                            self.backend,
                            now,
                            now,
                        ),
                    )
                    row = conn.execute(
                        "SELECT token FROM sessions WHERE fingerprint = ?",
                        (project_fingerprint(self.dbhost.root),),
                    ).fetchone()
                    if row and row[0] != self.dbhost.token:
                        out["token_conflict"] = True
                    conn.commit()
                    conn.execute("PRAGMA journal_mode=DELETE")
                    conn.commit()
                finally:
                    conn.close()
                verdict, vmsgs = sqlite_integrity(work, quick=False)
                if verdict != "ok":
                    out["error"] = "rebuilt catalog failed integrity_check: " + (
                        "; ".join(vmsgs[:3])
                    )
                    return out
                qdir = cat.dir / "quarantine" / f"catalog-{_stamp()}-{os.getpid()}"
                moved = []
                for p in [path, *_sidecars(path)]:
                    if p.exists():
                        qdir.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(p), str(qdir / p.name))
                        moved.append(p.name)
                if moved:
                    out["quarantined"] = str(qdir)
                os.replace(work, path)
                cat._initialized = False
                out["recovered"] = True
            finally:
                _unlink_quiet(work, *_sidecars(work))
        # Outside the catalog lock: the callback registers through the catalog.
        if out["recovered"] and self.on_catalog_restored is not None:
            try:
                self.on_catalog_restored()
            except Exception as exc:
                out["reregister_error"] = str(exc)
        return out

    @staticmethod
    def _salvage_rows(src: Path, work: Path) -> Dict[str, Any]:
        """Copy every readable row of the catalog tables from ``src`` into
        ``work``; unreadable regions are skipped block by block, then row by
        row. Rows from the damaged (newer) file win, except sessions, where the
        snapshot's (the original token mapping) is kept."""
        result: Dict[str, Any] = {}
        try:
            s = sqlite3.connect(_ro_uri(src), uri=True, timeout=5.0)
        except sqlite3.Error as exc:
            return {"error": str(exc)}
        d = sqlite3.connect(str(work))
        probes = 0
        try:
            for table in _CATALOG_TABLES:
                try:
                    src_cols = [
                        r[1] for r in s.execute(f'PRAGMA table_info("{table}")')
                    ]
                except sqlite3.Error:
                    result[table] = {"rows": 0, "error": "schema unreadable"}
                    continue
                dst_cols = [r[1] for r in d.execute(f'PRAGMA table_info("{table}")')]
                cols = [c for c in dst_cols if c in src_cols]
                if not cols:
                    continue
                col_sql = ", ".join(f'"{c}"' for c in cols)
                verb = (
                    "INSERT OR IGNORE" if table == "sessions" else "INSERT OR REPLACE"
                )
                ins = (
                    f'{verb} INTO "{table}" ({col_sql}) '
                    f"VALUES ({', '.join('?' for _ in cols)})"
                )
                sel = f'SELECT {col_sql} FROM "{table}"'
                n, bad = 0, 0
                try:
                    rows = s.execute(sel).fetchall()
                    d.executemany(ins, rows)
                    n = len(rows)
                except sqlite3.DatabaseError:
                    try:
                        lo, hi = s.execute(
                            f'SELECT MIN(rowid), MAX(rowid) FROM "{table}"'
                        ).fetchone()
                    except sqlite3.DatabaseError:
                        lo, hi = None, None
                    if lo is not None and hi is not None:
                        step = 64
                        for start in range(int(lo), int(hi) + 1, step):
                            try:
                                rows = s.execute(
                                    sel + " WHERE rowid BETWEEN ? AND ?",
                                    (start, start + step - 1),
                                ).fetchall()
                                d.executemany(ins, rows)
                                n += len(rows)
                                continue
                            except sqlite3.DatabaseError:
                                pass
                            for rid in range(start, start + step):
                                probes += 1
                                if probes > _MAX_SALVAGE_PROBES:
                                    break
                                try:
                                    row = s.execute(
                                        sel + " WHERE rowid = ?", (rid,)
                                    ).fetchone()
                                except sqlite3.DatabaseError:
                                    bad += 1
                                    continue
                                if row is not None:
                                    d.execute(ins, row)
                                    n += 1
                    else:
                        bad += 1
                result[table] = {"rows": n, "unreadable": bad}
            d.commit()
        finally:
            d.close()
            s.close()
        return result

    # ================================================================== #
    # task: scrub
    # ================================================================== #
    def _task_scrub(
        self, state: Dict[str, Any], report: Dict[str, Any], dry_run: bool
    ) -> Dict[str, Any]:
        repair = self.policy.repair_backups and not dry_run
        rep = self.backups.scrub(
            repair=repair, workers=self.policy.workers, use_go=self.policy.use_go
        )
        self.last_pool = {
            "kind": "verify",
            "engine": rep.get("engine"),
            "workers": rep.get("workers"),
            "jobs": rep.get("checked", 0),
            "at": time.time(),
        }
        now = time.time()
        seen_bad = set()
        dropped = []
        tracked = state["unrecoverable_sets"]
        for s in rep["sets"]:
            if s.get("status") != "unrecoverable":
                continue
            key, ts = s["storage_key"], s["timestamp"]
            ident = f"{key}/{ts}"
            seen_bad.add(ident)
            first = float(tracked.setdefault(ident, now))
            if (
                dry_run
                or not self.policy.drop_unrecoverable_backups
                or now - first < self.policy.unrecoverable_grace
            ):
                continue
            if not self._set_roots_present(key, ts):
                continue  # a shard directory is offline: never delete for that
            freed = self.backups.remove_set(key, ts)
            tracked.pop(ident, None)
            dropped.append({"storage_key": key, "timestamp": ts, "freed_bytes": freed})
            if key not in state["needs_backup"]:
                state["needs_backup"].append(key)
            self._event(state, "backup-set-dropped", storage_key=key, timestamp=ts)
        for ident in list(tracked):
            if ident not in seen_bad:
                tracked.pop(ident)  # repaired or removed meanwhile
        if dropped:
            report["actions"].append({"task": "scrub", "dropped_sets": dropped})
        repaired = [s for s in rep["sets"] if s.get("status") == "repaired"]
        for s in repaired:
            self._event(
                state,
                "backup-set-repaired",
                storage_key=s["storage_key"],
                timestamp=s["timestamp"],
                shards=s.get("repaired_shards"),
            )
        return {
            "status": "ok",
            "checked": rep.get("checked", 0),
            "by_status": rep.get("by_status", {}),
            "repaired": len(repaired),
            "engine": rep.get("engine"),
            "unrecoverable_pending": sorted(
                seen_bad - {f"{d['storage_key']}/{d['timestamp']}" for d in dropped}
            ),
            "dropped": dropped,
        }

    def _set_roots_present(self, key: str, ts: str) -> bool:
        try:
            manifest, _ = self.backups.load_manifest(key, ts)
        except (FileNotFoundError, ValueError):
            return True  # no manifest at all: nothing offline to wait for
        roots = (manifest.get("erasure") or {}).get("roots") or []
        return all(Path(r).is_dir() for r in roots)

    # ================================================================== #
    # task: check
    # ================================================================== #
    def _lineage(self, state: Dict[str, Any], rec: Dict[str, Any]) -> Dict[str, Any]:
        key = rec["storage_key"]
        lin = state["lineage"].get(key)
        if lin is None or lin.get("updated_at") != rec.get("updated_at"):
            lin = {
                "updated_at": rec.get("updated_at"),
                "shas": [rec["sha256"]] if rec.get("sha256") else [],
            }
            state["lineage"][key] = lin
        return lin

    def _entry(self, state: Dict[str, Any], rec: Dict[str, Any]) -> Dict[str, Any]:
        key = rec["storage_key"]
        e = state["databases"].get(key)
        if e is None or e.get("updated_at") != rec.get("updated_at"):
            # First sight, or re-hosted since: forget the cached verdicts.
            e = {"updated_at": rec.get("updated_at")}
            state["databases"][key] = e
            self._lineage(state, rec)
        return e

    def _task_check(
        self, state: Dict[str, Any], report: Dict[str, Any], dry_run: bool
    ) -> Dict[str, Any]:
        now = time.time()
        deep = self._due_deep(state, now)
        recs = self.catalog.list_databases(token=self.dbhost.token)
        seen = set()
        counts: Dict[str, int] = {}
        # Pass 1 (in-process, cheap): stat/header or chunk accounting settles
        # most databases; the rest need hashing + quick/integrity check.
        before: Dict[str, Optional[str]] = {}
        verdicts: Dict[str, Tuple[str, List[str]]] = {}
        full: List[Dict[str, Any]] = []
        for rec in recs:
            key = rec["storage_key"]
            seen.add(key)
            entry = self._entry(state, rec)
            self._lineage(state, rec)
            before[key] = entry.get("status")
            try:
                verdict = check_database(
                    self.dbhost, rec, entry, deep=deep, triage=True
                )
            except Exception as exc:
                verdict = (ERROR, [f"{type(exc).__name__}: {exc}"])
            if verdict is None:
                full.append(rec)
            else:
                verdicts[key] = verdict
        # Pass 2 (worker pool): the expensive checks, concurrently.
        pooled, engine = self._inspect(state, full, deep=deep)
        verdicts.update(pooled)
        for rec in recs:
            key = rec["storage_key"]
            entry = state["databases"][key]
            status, problems = verdicts[key]
            entry["status"] = status
            entry["problems"] = problems
            entry["checked_at"] = now
            if status != MISSING:
                entry.pop("lost_since", None)
            counts[status] = counts.get(status, 0) + 1
            was = before[key]
            if status != was and (status != HEALTHY or was is not None):
                self._event(
                    state,
                    "health-changed",
                    storage_key=key,
                    before=was,
                    after=status,
                    problems=problems[:5],
                )
        for key in [k for k in state["databases"] if k not in seen]:
            state["databases"].pop(key, None)
            state["lineage"].pop(key, None)
            if key in state["needs_backup"]:
                state["needs_backup"].remove(key)
        if deep and not dry_run:
            self._task_state(state, "check")["deep_at"] = now
        return {
            "status": "ok",
            "deep": deep,
            "databases": len(recs),
            "full_checks": len(full),
            "engine": engine,
            "by_status": counts,
        }

    def _due_deep(self, state: Dict[str, Any], now: float) -> bool:
        interval = self.policy.deep_check_interval
        if interval <= 0:
            return False
        ts = self._task_state(state, "check")
        last = ts.get("deep_at")
        if last is None:
            first = ts.setdefault("deep_first_seen", now)
            return now - float(first) >= interval
        return now - float(last) >= interval

    def _check_one(
        self, rec: Dict[str, Any], entry: Dict[str, Any], *, deep: bool
    ) -> Tuple[str, List[str]]:
        verdict = check_database(self.dbhost, rec, entry, deep=deep)
        assert verdict is not None  # only triage=True may defer
        return verdict

    def _inspect(
        self, state: Dict[str, Any], recs: List[Dict[str, Any]], *, deep: bool
    ) -> Tuple[Dict[str, Tuple[str, List[str]]], str]:
        """Fully check ``recs`` concurrently on the worker pool.

        Each job gets a copy of the database's cached health entry and returns
        it updated; the copy replaces the cached entry (same dict object, so
        callers holding it see the update). A job the pool could not run is an
        ``error`` verdict (transient), never a damage verdict.
        """
        if not recs:
            return {}, "none"
        items = [
            {
                "rec": rec,
                "entry": dict(state["databases"].get(rec["storage_key"]) or {}),
                "deep": deep,
            }
            for rec in recs
        ]
        run = self._run_pool("inspect", items)
        verdicts: Dict[str, Tuple[str, List[str]]] = {}
        for rec, res in zip(recs, run["results"]):
            key = rec["storage_key"]
            if res.get("status") is None or not isinstance(res.get("entry"), dict):
                verdicts[key] = (ERROR, [str(res.get("error") or "check did not run")])
                continue
            entry = state["databases"].setdefault(key, {})
            entry.clear()
            entry.update(res["entry"])
            verdicts[key] = (str(res["status"]), [str(m) for m in res["problems"]])
        return verdicts, run["engine"]

    def _run_pool(self, kind: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        from .autopilot_pool import run_jobs

        run = run_jobs(
            self.backups,
            kind,
            items,
            workers=self.policy.workers,
            use_go=self.policy.use_go,
        )
        for line in run["log"]:
            log.debug("%s", line)
        self.last_pool = {
            "kind": kind,
            "engine": run["engine"],
            "workers": run["workers"],
            "jobs": len(items),
            "at": time.time(),
        }
        return run

    # ================================================================== #
    # task: heal
    # ================================================================== #
    def _key_lock(self, key: str) -> FileLock:
        return FileLock(
            self.backups._key_lock_path(key), timeout=self.policy.lock_timeout
        )

    def _task_heal(
        self, state: Dict[str, Any], report: Dict[str, Any], dry_run: bool
    ) -> Dict[str, Any]:
        """Heal every damaged database that is due.

        The work is split so the expensive parts run on the worker pool:

        1. take the key lock of every database to heal (sorted order; a busy
           key is skipped this tick);
        2. deep re-check them all concurrently (``inspect`` jobs) -- a heal
           never acts on a stale verdict;
        3. decide per database (recovered, report, adopt, candidates, ...);
        4. restore + ``integrity_check`` the backup candidates of every
           database needing a restore concurrently (``stage`` jobs), each into
           its own staging file;
        5. install the staged copies one by one (quarantine the damaged
           content, re-host, update lineage) -- installs touch the catalog, so
           they stay sequential.

        A job the pool could not run is a transient ``failed`` result, never a
        reason to escalate (adopt/drop): the heal is retried next tick.
        """
        now = time.time()
        forced = "heal" in self._forced
        results: Dict[str, Dict[str, Any]] = {}
        todo: List[str] = []
        for key, entry in sorted(state["databases"].items()):
            if entry.get("status") not in PROBLEM_STATUSES:
                continue
            last = entry.get("heal_at")
            if (
                last is not None
                and now - float(last) < self.policy.check_interval
                and not forced
            ):
                results[key] = {"storage_key": key, "result": "backoff"}
                continue
            todo.append(key)
        engines = {"check": "none", "stage": "none"}
        if todo:
            with contextlib.ExitStack() as stack:
                locked: List[str] = []
                for key in todo:
                    try:
                        stack.enter_context(self._key_lock(key))
                    except LockTimeout:
                        results[key] = {"storage_key": key, "result": "busy"}
                        continue
                    locked.append(key)
                try:
                    self._heal_locked(state, locked, results, engines, dry_run)
                except Exception as exc:  # never leave a locked key unreported
                    for key in locked:
                        if key not in results:
                            results[key] = self._heal_failed(state, key, exc)
            if not dry_run:
                stamp = time.time()
                for key in todo:
                    entry = state["databases"].get(key)
                    if entry is not None:
                        entry["heal_at"] = stamp
        ordered = [results[k] for k in sorted(results)]
        for res in ordered:
            if res.get("result") in ("restored", "rolled-back", "adopted", "dropped"):
                report["actions"].append({"task": "heal", **res})
        return {"status": "ok", "results": ordered, "engines": engines}

    def _heal_failed(
        self, state: Dict[str, Any], key: str, exc: BaseException
    ) -> Dict[str, Any]:
        if isinstance(exc, LockTimeout):
            return {"storage_key": key, "result": "busy"}
        self._event(state, "heal-failed", storage_key=key, error=str(exc))
        return {
            "storage_key": key,
            "result": "failed",
            "error": f"{type(exc).__name__}: {exc}",
        }

    def _heal_locked(
        self,
        state: Dict[str, Any],
        keys: List[str],
        results: Dict[str, Dict[str, Any]],
        engines: Dict[str, str],
        dry_run: bool,
    ) -> None:
        """Steps 2-5 of :meth:`_task_heal`; the caller holds every key lock."""
        live: List[Dict[str, Any]] = []
        for key in keys:
            try:
                rec = self.catalog.get_database(key)
            except Exception as exc:
                results[key] = self._heal_failed(state, key, exc)
                continue
            entry = state["databases"][key]
            if rec is None:
                state["databases"].pop(key, None)
                state["lineage"].pop(key, None)
                results[key] = {"storage_key": key, "result": "gone"}
            elif rec.get("updated_at") != entry.get("updated_at"):
                # re-hosted since the check
                results[key] = {"storage_key": key, "result": "superseded"}
            else:
                live.append(rec)

        verdicts, engines["check"] = self._inspect(state, live, deep=True)

        plans: List[Dict[str, Any]] = []
        for rec in live:
            key = rec["storage_key"]
            entry = state["databases"][key]
            status, problems = verdicts[key]
            entry["status"], entry["problems"] = status, problems
            try:
                res, plan = self._heal_plan(
                    state, rec, entry, status, problems, dry_run
                )
            except Exception as exc:
                results[key] = self._heal_failed(state, key, exc)
                continue
            if plan is None:
                results[key] = res
            else:
                plans.append(plan)
        if not plans:
            return

        try:
            items = [
                {
                    "storage_key": p["rec"]["storage_key"],
                    "candidates": p["cands"],
                    "dest": str(p["dest"]),
                }
                for p in plans
            ]
            run = self._run_pool("stage", items)
            engines["stage"] = run["engine"]
            for plan, staged in zip(plans, run["results"]):
                key = plan["rec"]["storage_key"]
                try:
                    results[key] = self._heal_finish(state, plan, staged)
                except Exception as exc:
                    results[key] = self._heal_failed(state, key, exc)
        finally:
            for p in plans:
                _unlink_quiet(p["dest"], *_sidecars(p["dest"]))

    def _heal_plan(
        self,
        state: Dict[str, Any],
        rec: Dict[str, Any],
        entry: Dict[str, Any],
        status: str,
        problems: List[str],
        dry_run: bool,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """Decide what to do with one freshly re-checked database.

        Returns ``(result, None)`` when the heal is settled without a restore,
        or ``(partial result, plan)`` when backup candidates must be staged.
        """
        key = rec["storage_key"]
        out: Dict[str, Any] = {"storage_key": key, "status": status}
        if status == HEALTHY:
            out["result"] = "recovered-on-recheck"
            self._event(state, "healthy-on-recheck", storage_key=key)
            return out, None
        if status == ERROR:
            out["result"] = "transient-error"
            out["problems"] = problems
            return out, None
        if status == DRIFTED and self.policy.drift_action == "report":
            out["result"] = "reported"
            return out, None
        if status == DRIFTED and self.policy.drift_action == "adopt":
            return self._adopt(state, rec, entry, out, dry_run), None
        exact, rollback = self._candidates(state, rec)
        cands = [(m, "exact") for m in exact]
        if self.policy.allow_rollback and status != DRIFTED:
            cands += [(m, "rollback") for m in rollback]
        out["candidates"] = [
            {"timestamp": m["timestamp"], "kind": kind} for m, kind in cands
        ]
        if dry_run:
            out["result"] = "would-restore" if cands else "would-escalate"
            return out, None
        if not cands:
            return self._escalate(state, rec, entry, out, status, problems, []), None
        plan = {
            "rec": rec,
            "entry": entry,
            "status": status,
            "problems": problems,
            "out": out,
            "cands": out["candidates"],
            "dest": healing_path(self.dbhost.data_dir, key),
        }
        return out, plan

    def _heal_finish(
        self, state: Dict[str, Any], plan: Dict[str, Any], staged: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Install what a ``stage`` job produced, or escalate."""
        rec, entry, status = plan["rec"], plan["entry"], plan["status"]
        out, cands, dest = plan["out"], plan["cands"], Path(plan["dest"])
        key = rec["storage_key"]
        if not isinstance(staged.get("failures"), list):
            # The job itself did not run (worker crash, pool failure): that is
            # no evidence the backups are bad -- retry next tick, never escalate.
            out["result"] = "failed"
            out["error"] = str(staged.get("error") or "restore staging did not run")
            self._event(state, "heal-failed", storage_key=key, error=out["error"])
            return out
        failures: List[Dict[str, Any]] = list(staged["failures"])
        start = len(cands)
        if staged.get("staged"):
            index = int(staged.get("index", -1))
            if not 0 <= index < len(cands) or Path(staged["staged"]) != dest:
                out["result"] = "failed"
                out["error"] = "restore staging returned an unexpected result"
                self._event(state, "heal-failed", storage_key=key, error=out["error"])
                return out
            cand = cands[index]
            attempt = self._install(
                state, rec, entry, dest, cand["timestamp"], cand["kind"], status
            )
            if attempt.get("installed"):
                return self._healed(out, attempt, cand["kind"], failures)
            failures.append(attempt)
            start = index + 1
        # The staged copy could not be installed: try the older candidates
        # in-process (rare -- only after an install failure).
        for cand in cands[start:]:
            attempt = self._try_restore(state, rec, entry, cand, status, dest)
            if attempt.get("installed"):
                return self._healed(out, attempt, cand["kind"], failures)
            failures.append(attempt)
        return self._escalate(
            state, rec, entry, out, status, plan["problems"], failures
        )

    @staticmethod
    def _healed(
        out: Dict[str, Any],
        attempt: Dict[str, Any],
        kind: str,
        failures: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        out.update(attempt)
        out["result"] = "restored" if kind == "exact" else "rolled-back"
        if failures:
            out["skipped_candidates"] = failures
        return out

    def _escalate(
        self,
        state: Dict[str, Any],
        rec: Dict[str, Any],
        entry: Dict[str, Any],
        out: Dict[str, Any],
        status: str,
        problems: List[str],
        failures: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """No backup could heal the database: adopt, drop, or report it."""
        out["failed_candidates"] = failures
        if status == DRIFTED:
            # Sound SQLite, nothing better to restore: accept it as truth.
            return self._adopt(state, rec, entry, out, False)
        if status == MISSING:
            return self._lost(state, rec, entry, out)
        out["result"] = "unrecoverable"
        self._event(
            state,
            "unrecoverable",
            storage_key=rec["storage_key"],
            problems=problems[:5],
            tried=len(out.get("candidates") or []),
        )
        return out

    def _candidates(
        self, state: Dict[str, Any], rec: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Backup sets of ``rec``, newest first, split into *exact* copies of
        the hosted content (matched by checksum lineage) and *rollback* sets."""
        lineage = self._lineage(state, rec)
        shas = set(lineage.get("shas") or [])
        updated = float(rec.get("updated_at") or 0.0)
        exact, rollback = [], []
        for m in reversed(self.backups.list_backups(rec["storage_key"])):
            src = m.get("source_sha256")
            raw = m.get("raw_sha256")
            if (src and src in shas) or (raw and raw in shas):
                exact.append(m)
            elif not src and float(m.get("created_at") or 0.0) >= updated:
                exact.append(m)
            else:
                rollback.append(m)
        return exact, rollback

    def _try_restore(
        self,
        state: Dict[str, Any],
        rec: Dict[str, Any],
        entry: Dict[str, Any],
        cand: Dict[str, Any],
        status: str,
        dest: Path,
    ) -> Dict[str, Any]:
        """Stage and install one candidate in-process (caller holds the lock)."""
        ts = cand["timestamp"]
        try:
            staged = stage_restore(self.backups, rec["storage_key"], [cand], dest)
            if not staged.get("staged"):
                failures = staged.get("failures") or []
                return (
                    failures[0]
                    if failures
                    else {"timestamp": ts, "error": "restore failed"}
                )
            return self._install(state, rec, entry, dest, ts, cand["kind"], status)
        finally:
            _unlink_quiet(dest, *_sidecars(dest))

    def _install(
        self,
        state: Dict[str, Any],
        rec: Dict[str, Any],
        entry: Dict[str, Any],
        staged: Path,
        ts: str,
        kind: str,
        status: str,
    ) -> Dict[str, Any]:
        """Replace the damaged database with a verified staged copy."""
        key = rec["storage_key"]
        try:
            quarantined = self._quarantine_current(rec, status, ts, entry)
            new_rec = self.dbhost.reinstall(key, staged)
        except Exception as exc:
            return {"timestamp": ts, "error": f"{type(exc).__name__}: {exc}"}
        lineage = self._lineage(state, rec)
        if kind == "exact":
            if new_rec["sha256"] not in lineage["shas"]:
                lineage["shas"].append(new_rec["sha256"])
        else:
            state["lineage"][key] = {
                "updated_at": rec.get("updated_at"),
                "shas": [new_rec["sha256"]],
                "rolled_back_to": ts,
            }
        self._mark_healthy(entry, new_rec)
        self._event(
            state,
            "restored" if kind == "exact" else "rolled-back",
            storage_key=key,
            from_status=status,
            timestamp=ts,
            quarantined=quarantined,
        )
        return {"installed": True, "timestamp": ts, "quarantined": quarantined}

    def _mark_healthy(self, entry: Dict[str, Any], rec: Dict[str, Any]) -> None:
        entry.update({"status": HEALTHY, "problems": [], "sha": rec.get("sha256")})
        entry.pop("lost_since", None)
        if rec.get("dialect") == "sqlite":
            try:
                st = Path(rec["location"]).stat()
                entry.update({"size": st.st_size, "mtime_ns": st.st_mtime_ns})
            except OSError:
                entry.pop("size", None)
        self.backups.suspect_keys.discard(rec["storage_key"])

    def _quarantine_current(
        self, rec: Dict[str, Any], reason: str, ts: str, entry: Dict[str, Any]
    ) -> Optional[str]:
        """Preserve the damaged content before it is replaced (never deleted)."""
        key = rec["storage_key"]
        qdir = self.quarantine_dir / f"{key}.{_stamp()}.{reason}"
        info = {
            "storage_key": key,
            "reason": reason,
            "problems": entry.get("problems", []),
            "replaced_from_backup": ts,
            "at": time.time(),
            "catalog_record": rec,
        }
        if rec.get("dialect") == "sqlite":
            loc = Path(rec.get("location") or "")
            present = [p for p in [loc, *_sidecars(loc)] if p.exists()]
            if not present:
                return None
            qdir.mkdir(parents=True, exist_ok=True)
            for p in present[1:] if present[0] == loc else present:
                shutil.move(str(p), str(qdir / p.name))
            if loc.exists():
                try:
                    os.link(loc, qdir / loc.name)
                except OSError:
                    shutil.copy2(loc, qdir / loc.name)
        else:
            qdir.mkdir(parents=True, exist_ok=True)
            self.dbhost._read_chunks(key, qdir / f"{key}.db")
        atomic_write_text(qdir / "reason.json", json.dumps(info, indent=2, default=str))
        return str(qdir)

    def _adopt(
        self,
        state: Dict[str, Any],
        rec: Dict[str, Any],
        entry: Dict[str, Any],
        out: Dict[str, Any],
        dry_run: bool,
    ) -> Dict[str, Any]:
        key = rec["storage_key"]
        if dry_run:
            out["result"] = "would-adopt"
            return out
        if rec.get("dialect") == "sqlite":
            loc = Path(rec["location"])
            record = dict(rec)
            record["sha256"] = _sha256_file(loc)
            record["size_bytes"] = loc.stat().st_size
            self.catalog.register_database(record)
        else:
            tmp = Path(self.dbhost.data_dir) / f".{key}.adopt.{os.getpid()}.tmp"
            try:
                self.dbhost._read_chunks(key, tmp)
                record = self.dbhost.reinstall(key, tmp)
            finally:
                _unlink_quiet(tmp, *_sidecars(tmp))
        state["lineage"][key] = {
            "updated_at": rec.get("updated_at"),
            "shas": [record["sha256"]],
            "adopted": True,
        }
        self._mark_healthy(entry, record)
        if key not in state["needs_backup"]:
            state["needs_backup"].append(key)
        self._event(state, "adopted", storage_key=key, sha256=record["sha256"])
        out["result"] = "adopted"
        return out

    def _lost(
        self,
        state: Dict[str, Any],
        rec: Dict[str, Any],
        entry: Dict[str, Any],
        out: Dict[str, Any],
    ) -> Dict[str, Any]:
        key = rec["storage_key"]
        now = time.time()
        since = float(entry.setdefault("lost_since", now))
        if now - since < self.policy.lost_grace:
            out["result"] = "lost-pending"
            out["drop_in"] = self.policy.lost_grace - (now - since)
            return out
        self.dbhost.remove(key)
        state["databases"].pop(key, None)
        state["lineage"].pop(key, None)
        self.backups.suspect_keys.discard(key)
        self._event(state, "dropped-lost", storage_key=key, lost_since=since)
        out["result"] = "dropped"
        return out

    # ================================================================== #
    # task: backup
    # ================================================================== #
    def _task_backup(
        self, state: Dict[str, Any], report: Dict[str, Any], dry_run: bool
    ) -> Dict[str, Any]:
        now = time.time()
        by_key: Dict[str, List[Dict[str, Any]]] = {}
        for m in self.backups.list_backups():
            by_key.setdefault(m.get("storage_key"), []).append(m)
        done, planned, errors = [], [], []
        for rec in self.catalog.list_databases(token=self.dbhost.token):
            key = rec["storage_key"]
            entry = state["databases"].get(key)
            if entry is None or entry.get("status") != HEALTHY:
                continue
            exact, _ = self._candidates(state, rec)
            reason = None
            if key in state["needs_backup"]:
                reason = "requested"
            elif not by_key.get(key):
                reason = "no-backups"
            elif not exact:
                reason = "no-exact-backup"
            elif (
                self.policy.backup_max_age is not None
                and now - float(exact[0].get("created_at") or 0.0)
                > self.policy.backup_max_age
            ):
                reason = "stale"
            if reason is None:
                continue
            if dry_run:
                planned.append({"storage_key": key, "reason": reason})
                continue
            try:
                manifest = self.backups.backup_database(key)
            except Exception as exc:
                errors.append({"storage_key": key, "error": f"{exc}"})
                # Something is off with the source: re-verify it fully next check.
                for k in ("size", "mtime_ns"):
                    entry.pop(k, None)
                continue
            if key in state["needs_backup"]:
                state["needs_backup"].remove(key)
            done.append(
                {
                    "storage_key": key,
                    "reason": reason,
                    "timestamp": manifest["timestamp"],
                }
            )
        state["needs_backup"] = [
            k for k in state["needs_backup"] if k in state["databases"]
        ]
        if done:
            report["actions"].append({"task": "backup", "backed_up": done})
        out: Dict[str, Any] = {"status": "ok", "backed_up": done, "errors": errors}
        if dry_run:
            out["would_back_up"] = planned
        return out

    # ================================================================== #
    # task: retention
    # ================================================================== #
    def _task_retention(
        self, state: Dict[str, Any], report: Dict[str, Any], dry_run: bool
    ) -> Dict[str, Any]:
        rep = self.retention.enforce(dry_run=dry_run)
        evicted = [d["storage_key"] for d in rep.get("evicted", [])]
        if not dry_run:
            for key in evicted:
                state["databases"].pop(key, None)
                state["lineage"].pop(key, None)
        if evicted or rep.get("pruned_backups") or rep.get("stray_removed"):
            report["actions"].append({"task": "retention", "evicted": evicted})
        return {
            "status": "ok" if not rep.get("errors") else "partial",
            "evicted": evicted,
            "pruned_backups": len(rep.get("pruned_backups", [])),
            "stray_removed": len(rep.get("stray_removed", [])),
            "freed_bytes": rep.get("freed_bytes", 0),
            "over_budget": rep.get("over_budget", False),
            "errors": rep.get("errors", []),
            "skipped": rep.get("skipped", []),
        }

    # ================================================================== #
    # task: sweep
    # ================================================================== #
    def _task_sweep(
        self, state: Dict[str, Any], report: Dict[str, Any], dry_run: bool
    ) -> Dict[str, Any]:
        now = time.time()
        pol = self.policy
        removed: List[Dict[str, Any]] = []

        def _drop(p: Path, why: str, max_age: float) -> None:
            age = _age(p, now)
            if age is None or age < max_age:
                return
            freed = 0 if dry_run else _remove_path(p)
            removed.append({"path": str(p), "reason": why, "bytes": freed})

        data = Path(self.dbhost.data_dir)
        for pattern in (".*.healing", "*.restoring", ".fa-restore-*.gz", ".*.tmp"):
            for p in data.glob(pattern):
                _drop(p, "partial-file", pol.debris_max_age)
        for root in self.backups._roots():
            if not root.is_dir():
                continue
            for pattern in ("*/*/_tmp.gz", "*/*/*.tmp", "*/*/*.repair"):
                for p in root.glob(pattern):
                    _drop(p, "partial-backup-file", pol.debris_max_age)
        for p in (
            self._snapshot_dir.glob(".*.tmp") if self._snapshot_dir.is_dir() else []
        ):
            _drop(p, "partial-snapshot", pol.debris_max_age)
        for p in self.catalog.dir.glob(".catalog.recover-*"):
            _drop(p, "partial-catalog-recovery", pol.debris_max_age)

        dead = self._sweep_run_dir(now, dry_run, removed)
        pruned_rows = 0
        if not dry_run:
            try:
                before = len(self.catalog.list_servers(prune=False))
                after = len(self.catalog.list_servers(prune=True))
                pruned_rows = max(0, before - after)
            except Exception:
                pruned_rows = 0

        for qroot in (self.quarantine_dir, self.catalog.dir / "quarantine"):
            if qroot.is_dir():
                for p in qroot.iterdir():
                    _drop(p, "quarantine-expired", pol.quarantine_max_age)

        orphans = self._sweep_orphans(state, now, dry_run) if pol.adopt_orphans else {}
        if removed or orphans.get("adopted") or orphans.get("quarantined"):
            report["actions"].append(
                {
                    "task": "sweep",
                    "removed": len(removed),
                    "orphans_adopted": orphans.get("adopted", []),
                    "orphans_quarantined": orphans.get("quarantined", []),
                }
            )
        return {
            "status": "ok",
            "removed": removed,
            "freed_bytes": sum(r["bytes"] for r in removed),
            "dead_servers": dead,
            "server_rows_pruned": pruned_rows,
            "orphans": orphans,
        }

    def _sweep_run_dir(
        self, now: float, dry_run: bool, removed: List[Dict[str, Any]]
    ) -> List[str]:
        """Endpoint/PID files of servers whose process is gone (never ours)."""
        dead: List[str] = []
        for p in list(self.run_dir.glob("endpoint-*.json")) + list(
            self.run_dir.glob("server-*.pid")
        ):
            sid = p.stem.split("-", 1)[1] if "-" in p.stem else ""
            if not sid or sid == self.own_server_id:
                continue
            pid = None
            try:
                text = p.read_text(encoding="utf-8").strip()
                pid = (
                    int(json.loads(text).get("pid") or 0)
                    if p.suffix == ".json"
                    else int(text)
                )
            except (OSError, ValueError, AttributeError):
                pid = None
            if pid and pid_alive(pid):
                continue
            # A server that is just starting writes its pid file first.
            age = _age(p, now)
            if age is None or age < 60.0:
                continue
            if not dry_run:
                _remove_path(p)
            removed.append({"path": str(p), "reason": "dead-server", "bytes": 0})
            if sid not in dead:
                dead.append(sid)
        for p in self.run_dir.glob("server-*.log"):
            sid = p.stem.split("-", 1)[1] if "-" in p.stem else ""
            if not sid or sid == self.own_server_id:
                continue
            if (self.run_dir / f"server-{sid}.pid").exists():
                continue
            age = _age(p, now)
            if age is not None and age >= self.policy.quarantine_max_age:
                freed = 0 if dry_run else _remove_path(p)
                removed.append({"path": str(p), "reason": "old-log", "bytes": freed})
        return dead

    def _sweep_orphans(
        self, state: Dict[str, Any], now: float, dry_run: bool
    ) -> Dict[str, Any]:
        """Re-register this session's hosted files that lost their catalog row."""
        if self.dbhost.is_remote:
            return {}
        known = {
            r["storage_key"]
            for r in self.catalog.list_databases()
            if r.get("storage_key")
        }
        prefix = f"{project_slug(self.dbhost.root)}-{self.dbhost.token}-"
        out: Dict[str, Any] = {"adopted": [], "quarantined": [], "foreign": []}
        for path in sorted(Path(self.dbhost.data_dir).glob("*.db")):
            key = path.stem
            if key in known or path.name.startswith("."):
                continue
            age = _age(path, now)
            if age is None or age < self.policy.debris_max_age:
                continue
            db_name = key[len(prefix) :] if key.startswith(prefix) else ""
            if (
                not db_name
                or sanitize_db_name(db_name) != db_name
                or make_storage_key(self.dbhost.root, self.dbhost.token, db_name) != key
            ):
                out["foreign"].append(path.name)  # not ours to judge: report only
                continue
            if dry_run:
                out["adopted"].append({"storage_key": key, "planned": True})
                continue
            try:
                with self._key_lock(key):
                    if self.catalog.get_database(key) is not None or not path.is_file():
                        continue
                    verdict, msgs = sqlite_integrity(path, quick=False)
                    if verdict == "error":
                        continue
                    if verdict == "ok":
                        rec = self._register_orphan(path, key, db_name)
                        self._lineage(state, rec)
                        out["adopted"].append({"storage_key": key})
                        self._event(state, "orphan-adopted", storage_key=key)
                    else:
                        qdir = self.quarantine_dir / f"{key}.{_stamp()}.orphan-corrupt"
                        qdir.mkdir(parents=True, exist_ok=True)
                        for p in [path, *_sidecars(path)]:
                            if p.exists():
                                shutil.move(str(p), str(qdir / p.name))
                        atomic_write_text(
                            qdir / "reason.json",
                            json.dumps(
                                {
                                    "storage_key": key,
                                    "reason": "orphan failed integrity_check",
                                    "problems": msgs[:20],
                                    "at": time.time(),
                                },
                                indent=2,
                            ),
                        )
                        out["quarantined"].append(
                            {"storage_key": key, "path": str(qdir)}
                        )
                        self._event(state, "orphan-quarantined", storage_key=key)
            except LockTimeout:
                continue
        return out

    def _register_orphan(self, path: Path, key: str, db_name: str) -> Dict[str, Any]:
        st = path.stat()
        record = {
            "storage_key": key,
            "fingerprint": project_fingerprint(self.dbhost.root),
            "token": self.dbhost.token,
            "db_name": db_name,
            "dialect": "sqlite",
            "location": str(path),
            "size_bytes": st.st_size,
            "sha256": _sha256_file(path),
            "n_chunks": None,
            "updated_at": st.st_mtime,
        }
        self.catalog.register_database(record)
        return record
