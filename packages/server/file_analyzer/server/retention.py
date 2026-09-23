"""
Time- and space-based retention for what the server hosts -- the janitor.

Without this, a long-lived server only ever grows: every hosted database stays
forever, and backups are bounded only per database (``--backup-keep``), not in
total. :class:`RetentionManager` enforces a :class:`RetentionPolicy` over one
repo-session's hosted databases *and* their backups:

* **time** -- a hosted database that has been *idle* (neither re-hosted nor read
  through a query/download) for longer than ``max_age`` is evicted, together
  with its backups; backup sets older than ``backup_max_age`` are pruned, but
  the newest set of every database that is still hosted is always kept;
* **space** -- when hosted bytes + backup bytes exceed ``max_total_bytes``, old
  backup sets go first (oldest first, again sparing each live database's newest
  set), then hosted databases are evicted least-recently-active first. The
  single most recently active database is never evicted for space: if it alone
  is over budget, the report says ``over_budget`` rather than wiping everything;
* **debris** -- half-copied uploads and backup sets left behind by a crash
  (no ``manifest.json``) older than ``debris_max_age`` are removed.

Deciding what to remove (:meth:`RetentionManager.plan`) is separate from doing
it (:meth:`RetentionManager.enforce`), so ``dry_run`` reports exactly what a real
run would do. Before evicting a database the janitor re-reads its catalog row
under the database's backup lock and skips it if it was re-hosted or read since
the plan was made. After deleting remote content it asks the backend to reclaim
the space (``VACUUM`` / ``OPTIMIZE TABLE``).

Scope is the server's own session (its token + its project's backup
directory): a server never deletes another repository's data.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .backup import BackupManager
from .dbhost import DatabaseHost
from .locking import FileLock

DAY = 86400.0
#: Evict a hosted database after this long without being re-hosted or read.
DEFAULT_MAX_AGE = 30 * DAY
#: Prune backup sets older than this (each live database keeps its newest set).
DEFAULT_BACKUP_MAX_AGE = 7 * DAY
#: Remove crash leftovers (partial uploads / manifest-less backup sets) after this.
DEFAULT_DEBRIS_MAX_AGE = 3600.0
#: Seconds between janitor passes.
DEFAULT_RETENTION_INTERVAL = 3600.0
#: Backup key used by the native ``pg_dump`` of the whole cluster (not a catalog
#: database); it is treated as permanently live.
PG_CLUSTER_KEY = "pg_cluster_dump"

_SIZE_UNITS = {
    "": 1,
    "B": 1,
    "K": 1024,
    "KB": 1024,
    "KIB": 1024,
    "M": 1024**2,
    "MB": 1024**2,
    "MIB": 1024**2,
    "G": 1024**3,
    "GB": 1024**3,
    "GIB": 1024**3,
    "T": 1024**4,
    "TB": 1024**4,
    "TIB": 1024**4,
}


def parse_size(text: Any) -> Optional[int]:
    """Parse ``"20G"`` / ``"512MB"`` / ``"1048576"`` into bytes (binary units).

    ``None``, ``""``, ``0`` and negative values mean *no limit* (``None``).
    """
    if text is None:
        return None
    if isinstance(text, (int, float)):
        value = int(text)
        return value if value > 0 else None
    raw = str(text).strip().upper().replace(" ", "")
    if not raw:
        return None
    num = raw.rstrip("KMGTIB")
    unit = raw[len(num) :]
    if unit not in _SIZE_UNITS:
        raise ValueError(f"unrecognized size unit in {text!r}")
    try:
        value = int(float(num) * _SIZE_UNITS[unit])
    except ValueError as err:
        raise ValueError(f"not a size: {text!r}") from err
    return value if value > 0 else None


def _limit(value: Optional[float]) -> Optional[float]:
    """Normalize an age/size limit: ``None`` or ``<= 0`` disables it."""
    if value is None:
        return None
    value = float(value)
    return value if value > 0 else None


@dataclass
class RetentionPolicy:
    """What to keep. Any limit set to ``None`` (or ``<= 0``) is disabled."""

    max_age: Optional[float] = DEFAULT_MAX_AGE
    backup_max_age: Optional[float] = DEFAULT_BACKUP_MAX_AGE
    max_total_bytes: Optional[int] = None
    debris_max_age: float = DEFAULT_DEBRIS_MAX_AGE

    def __post_init__(self) -> None:
        self.max_age = _limit(self.max_age)
        self.backup_max_age = _limit(self.backup_max_age)
        total = _limit(self.max_total_bytes)
        self.max_total_bytes = int(total) if total is not None else None
        self.debris_max_age = max(0.0, float(self.debris_max_age))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RetentionManager:
    """Plans and enforces a :class:`RetentionPolicy` for one server's session."""

    def __init__(
        self,
        host: DatabaseHost,
        backups: BackupManager,
        policy: Optional[RetentionPolicy] = None,
    ) -> None:
        self.host = host
        self.backups = backups
        self.policy = policy or RetentionPolicy()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._run_lock = threading.Lock()
        self.last_report: Optional[Dict[str, Any]] = None

    # -- inventory --------------------------------------------------------
    def _databases(self) -> List[Dict[str, Any]]:
        access = self.host.catalog.access_times()
        out = []
        for hosted in self.host.list():
            rec = hosted.record
            updated = float(rec.get("updated_at") or 0.0)
            active = max(updated, access.get(hosted.storage_key, 0.0))
            out.append(
                {
                    "storage_key": hosted.storage_key,
                    "db_name": hosted.db_name,
                    "bytes": self.host.stored_bytes(rec),
                    "updated_at": updated,
                    "active_at": active,
                }
            )
        return out

    def _debris(self) -> List[Dict[str, Any]]:
        """Half-copied uploads in the data directory."""
        out = []
        for p in self.host.data_dir.glob(".*.incoming"):
            try:
                st = p.stat()
            except OSError:
                continue
            out.append({"path": str(p), "bytes": st.st_size, "mtime": st.st_mtime})
        return out

    def usage(self) -> Dict[str, Any]:
        """Current footprint of this session: hosted + backup bytes."""
        dbs = self._databases()
        sets = self.backups.backup_sets()
        hosted = sum(d["bytes"] for d in dbs)
        backup = sum(s["bytes"] for s in sets)
        return {
            "hosted_bytes": hosted,
            "backup_bytes": backup,
            "total_bytes": hosted + backup,
            "databases": len(dbs),
            "backup_sets": len(sets),
            "max_total_bytes": self.policy.max_total_bytes,
        }

    # -- planning (pure: no side effects) -------------------------------
    def plan(self, now: Optional[float] = None) -> Dict[str, Any]:
        """Decide what a retention pass would remove, without removing anything."""
        now = time.time() if now is None else float(now)
        pol = self.policy
        dbs = self._databases()
        sets = self.backups.backup_sets()
        debris = self._debris()

        evict: Dict[str, Dict[str, Any]] = {}
        prune: Dict[tuple, Dict[str, Any]] = {}
        stray: List[Dict[str, Any]] = []

        # Debris: partial uploads + manifest-less (crashed) backup sets.
        for d in debris:
            if now - d["mtime"] >= pol.debris_max_age:
                stray.append({**d, "reason": "partial-upload"})
        for s in sets:
            if not s["complete"] and now - s["created_at"] >= pol.debris_max_age:
                prune[(s["storage_key"], s["timestamp"])] = {
                    **s,
                    "reason": "incomplete",
                }

        # Time: idle databases.
        if pol.max_age is not None:
            for d in dbs:
                if now - d["active_at"] > pol.max_age:
                    evict[d["storage_key"]] = {**d, "reason": "idle"}

        live_keys = {d["storage_key"] for d in dbs if d["storage_key"] not in evict}
        live_keys.add(PG_CLUSTER_KEY)
        # The newest complete set of each surviving database is never pruned.
        protected = set()
        newest: Dict[str, Dict[str, Any]] = {}
        for s in sets:
            if s["complete"] and s["storage_key"] in live_keys:
                newest[s["storage_key"]] = s  # sets are sorted oldest first
        for s in newest.values():
            protected.add((s["storage_key"], s["timestamp"]))

        def _prunable(s: Dict[str, Any]) -> bool:
            ident = (s["storage_key"], s["timestamp"])
            return (
                ident not in protected
                and ident not in prune
                and s["storage_key"] not in evict
            )

        # Time: old backup sets (orphans of vanished databases age out too).
        if pol.backup_max_age is not None:
            for s in sets:
                if _prunable(s) and now - s["created_at"] > pol.backup_max_age:
                    prune[(s["storage_key"], s["timestamp"])] = {**s, "reason": "age"}

        # Space: backups oldest first, then least-recently-active databases.
        over_budget = False
        if pol.max_total_bytes is not None:
            total = sum(d["bytes"] for d in dbs if d["storage_key"] not in evict)
            total += sum(
                s["bytes"]
                for s in sets
                if (s["storage_key"], s["timestamp"]) not in prune
                and s["storage_key"] not in evict
            )
            for s in sets:
                if total <= pol.max_total_bytes:
                    break
                if _prunable(s):
                    prune[(s["storage_key"], s["timestamp"])] = {
                        **s,
                        "reason": "space",
                    }
                    total -= s["bytes"]
            survivors = sorted(
                (d for d in dbs if d["storage_key"] not in evict),
                key=lambda d: d["active_at"],
            )
            # Never evict the most recently active database for space.
            for d in survivors[:-1]:
                if total <= pol.max_total_bytes:
                    break
                key = d["storage_key"]
                own_sets = [
                    s
                    for s in sets
                    if s["storage_key"] == key
                    and (s["storage_key"], s["timestamp"]) not in prune
                ]
                evict[key] = {**d, "reason": "space"}
                total -= d["bytes"] + sum(s["bytes"] for s in own_sets)
            over_budget = total > pol.max_total_bytes

        # Backups of evicted databases are removed with them, not per set.
        prune = {k: v for k, v in prune.items() if k[0] not in evict}
        return {
            "now": now,
            "policy": pol.to_dict(),
            "evict": sorted(evict.values(), key=lambda d: d["active_at"]),
            "prune": sorted(prune.values(), key=lambda s: s["created_at"]),
            "stray": stray,
            "over_budget": over_budget,
        }

    # -- enforcement ------------------------------------------------------
    def _evict(self, entry: Dict[str, Any]) -> Optional[int]:
        """Evict one database if still as planned; bytes freed, or ``None``."""
        key = entry["storage_key"]
        lock = self.backups._key_lock_path(key)
        with FileLock(lock, timeout=60.0):
            rec = self.host.catalog.get_database(key)
            if rec is None:
                return 0
            access = self.host.catalog.access_times().get(key, 0.0)
            active = max(float(rec.get("updated_at") or 0.0), access)
            if active > entry["active_at"]:
                return None  # re-hosted or read since the plan: keep it
            freed = self.host.remove(key)
        # Outside the key lock: remove_backups takes it itself.
        freed += self.backups.remove_backups(key)
        return freed

    def enforce(
        self, *, dry_run: bool = False, now: Optional[float] = None
    ) -> Dict[str, Any]:
        """Run one retention pass; return a report of what was (or would be) removed."""
        with self._run_lock:
            before = self.usage()
            plan = self.plan(now)
            report: Dict[str, Any] = {
                "dry_run": dry_run,
                "policy": plan["policy"],
                "usage_before": before,
                "evicted": [],
                "pruned_backups": [],
                "stray_removed": [],
                "skipped": [],
                "errors": [],
                "freed_bytes": 0,
                "over_budget": plan["over_budget"],
            }
            if dry_run:
                report["evicted"] = [_brief_db(d) for d in plan["evict"]]
                report["pruned_backups"] = [_brief_set(s) for s in plan["prune"]]
                report["stray_removed"] = [_brief_stray(s) for s in plan["stray"]]
                report["freed_bytes"] = (
                    sum(d["bytes"] for d in plan["evict"])
                    + sum(s["bytes"] for s in plan["prune"])
                    + sum(s["bytes"] for s in plan["stray"])
                )
                report["usage_after"] = before
                self.last_report = report
                return report

            for d in plan["evict"]:
                try:
                    freed = self._evict(d)
                except Exception as exc:
                    report["errors"].append(
                        {"storage_key": d["storage_key"], "error": str(exc)}
                    )
                    continue
                if freed is None:
                    report["skipped"].append(
                        {"storage_key": d["storage_key"], "reason": "active-since-plan"}
                    )
                    continue
                report["evicted"].append({**_brief_db(d), "freed_bytes": freed})
                report["freed_bytes"] += freed
            for s in plan["prune"]:
                try:
                    freed = self.backups.remove_set(s["storage_key"], s["timestamp"])
                except Exception as exc:
                    report["errors"].append(
                        {
                            "storage_key": s["storage_key"],
                            "timestamp": s["timestamp"],
                            "error": str(exc),
                        }
                    )
                    continue
                report["pruned_backups"].append({**_brief_set(s), "freed_bytes": freed})
                report["freed_bytes"] += freed
            for s in plan["stray"]:
                try:
                    Path(s["path"]).unlink()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    report["errors"].append({"path": s["path"], "error": str(exc)})
                    continue
                report["stray_removed"].append(_brief_stray(s))
                report["freed_bytes"] += s["bytes"]

            if report["evicted"] and self.host.is_remote:
                report["reclaim"] = self.host.reclaim()
            report["usage_after"] = self.usage()
            if self.policy.max_total_bytes is not None:
                report["over_budget"] = (
                    report["usage_after"]["total_bytes"] > self.policy.max_total_bytes
                )
            self.last_report = report
            return report

    # -- periodic loop ------------------------------------------------------
    def start_periodic(self, interval: float) -> "RetentionManager":
        """Run :meth:`enforce` every ``interval`` seconds on a daemon thread."""
        if self._thread is not None:
            return self
        self._stop.clear()

        def _loop() -> None:
            # Wait first, so a restart never races a just-finished pass.
            while not self._stop.wait(interval):
                try:
                    self.enforce()
                except Exception:
                    # Never let a retention failure kill the loop.
                    pass

        self._thread = threading.Thread(target=_loop, name="fa-retention", daemon=True)
        self._thread.start()
        return self

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None


def _brief_db(d: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "storage_key": d["storage_key"],
        "db_name": d.get("db_name"),
        "bytes": d["bytes"],
        "active_at": d["active_at"],
        "reason": d.get("reason"),
    }


def _brief_set(s: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "storage_key": s["storage_key"],
        "timestamp": s["timestamp"],
        "bytes": s["bytes"],
        "reason": s.get("reason"),
    }


def _brief_stray(s: Dict[str, Any]) -> Dict[str, Any]:
    return {"path": s["path"], "bytes": s["bytes"], "reason": s.get("reason")}
