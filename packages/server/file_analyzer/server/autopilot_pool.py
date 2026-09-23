"""
Worker-pool driver for the autopilot's per-database and per-backup-set work.

The self-healing autopilot (and the backup scrub it schedules) does three kinds
of work that are independent per storage key and dominated by I/O and SQLite's
C code: hashing and ``PRAGMA quick_check``/``integrity_check`` of hosted
databases, block-by-block verification (and Reed-Solomon repair) of backup
sets, and restoring + verifying backup candidates before a heal installs one.
:func:`run_jobs` fans a list of such jobs out across many workers at once. It
mirrors :mod:`~file_analyzer.server.backup_pool`:

* the fast path is the server's **Go worker pool**
  (``file_analyzer/server/go/backup.go``, run with
  ``-module file_analyzer.server.autopilot_worker -kind <kind>``): a fixed set
  of goroutines drains a channel of batches and spawns one
  ``python -m file_analyzer.server.autopilot_worker`` child per batch, giving
  genuine OS-level parallelism. A worker that crashes on a pathologically
  damaged file takes down only its own subprocess, never the server. The
  binary is built on demand and skipped when the Go toolchain is absent;
* the fallback is an **in-process thread pool** that calls the very same
  :func:`~file_analyzer.server.autopilot_worker.execute`, so the pool works on
  a bare interpreter with nothing but the standard library;
* a single job (or ``workers=1``) runs **inline**, with no pool at all.

Job kinds (see :mod:`~file_analyzer.server.autopilot_worker` for the item
shapes):

``inspect``
    Full health check of one hosted database (SHA-256 + quick/integrity check).
    Read-only.
``verify``
    Verify -- or with ``repair`` rebuild -- every backup set of one key, each
    under the key lock.
``stage``
    Restore the backup candidates of one damaged database, in order, into a
    staging file until one passes ``integrity_check``. The caller holds the key
    lock and installs the staged file itself.

Items are partitioned so each job is one storage key, and distinct keys own
disjoint files and locks, so jobs never contend. As in the backup pool, the Go
path is authoritative once it runs: an item it produced no result for is
reported as an error (``{"error": ...}``) and is *not* re-run in-process -- the
autopilot treats that as a transient failure and retries on its next tick.
"""

from __future__ import annotations

import concurrent.futures
import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .backup_pool import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_MIN_WORKERS,
    _clamp_workers,
    _go_binary,
    _partition,
    _readers_roots,
    _run_go,
)

if TYPE_CHECKING:  # avoid an import cycle at runtime
    from .backup import BackupManager

#: Job kinds understood by the autopilot worker.
KINDS = ("inspect", "verify", "stage")

WORKER_MODULE = "file_analyzer.server.autopilot_worker"

NO_RESULT = "autopilot worker produced no result"


def _execute_safe(
    kind: str, manager: "BackupManager", item: Dict[str, Any]
) -> Dict[str, Any]:
    from .autopilot_worker import execute

    try:
        return execute(kind, manager, item)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def _run_python(
    kind: str, manager: "BackupManager", items: List[Dict[str, Any]], workers: int
) -> List[Dict[str, Any]]:
    """Concurrent in-process execution -- the toolchain-free fallback.

    hashlib and sqlite3 release the GIL for their C work, and each job opens
    its own connections and files, so the jobs genuinely overlap.
    """
    results: List[Dict[str, Any]] = [{} for _ in items]

    def _one(idx: int) -> None:
        results[idx] = _execute_safe(kind, manager, items[idx])

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_one, range(len(items))))
    return results


def _stage(
    spec: Dict[str, Any],
    kind: str,
    items: List[Dict[str, Any]],
    batches: List[List[int]],
) -> "tuple[Path, Path, List[int]]":
    run_dir = Path(tempfile.mkdtemp(prefix=f"fa-autopilot-{kind}-"))
    (run_dir / "batches").mkdir(parents=True, exist_ok=True)
    spec_path = run_dir / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    ids: List[int] = []
    for bid, idxs in enumerate(batches):
        payload = {
            "batch_id": bid,
            "kind": kind,
            "items": [{"id": i, "item": items[i]} for i in idxs],
        }
        (run_dir / "batches" / f"batch_{bid}.json").write_text(
            json.dumps(payload, default=str), encoding="utf-8"
        )
        ids.append(bid)
    return run_dir, spec_path, ids


def _collect(run_dir: Path, ids: List[int]) -> Dict[int, Dict[str, Any]]:
    by_id: Dict[int, Dict[str, Any]] = {}
    for bid in ids:
        path = run_dir / "results" / f"result_{bid}.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for row in payload.get("results") or []:
            if isinstance(row, dict) and isinstance(row.get("result"), dict):
                try:
                    by_id[int(row["id"])] = row["result"]
                except (KeyError, TypeError, ValueError):
                    continue
    return by_id


def run_jobs(
    manager: "BackupManager",
    kind: str,
    items: List[Dict[str, Any]],
    *,
    workers: Optional[int] = None,
    use_go: bool = True,
) -> Dict[str, Any]:
    """Run ``kind`` over every item concurrently.

    Returns ``{"engine", "workers", "results", "log"}``. ``results[i]`` is the
    result for ``items[i]``, or ``{"error": ...}`` if the job could not run.
    ``engine`` is ``"go"``, ``"python"`` (thread pool), ``"inline"`` (one
    worker) or ``"none"`` (no items).
    """
    if kind not in KINDS:
        raise ValueError(f"unknown autopilot job kind {kind!r}; expected {KINDS}")
    items = list(items)
    if not items:
        return {"engine": "none", "workers": 0, "results": [], "log": []}

    log: List[str] = []
    n_workers = int(workers or 0) or _clamp_workers(
        len(items), DEFAULT_MIN_WORKERS, DEFAULT_MAX_WORKERS
    )
    n_workers = max(1, min(n_workers, len(items)))

    if n_workers == 1:
        return {
            "engine": "inline",
            "workers": 1,
            "results": [_execute_safe(kind, manager, it) for it in items],
            "log": log,
        }

    exe = _go_binary(log) if use_go else None
    if exe is None:
        return {
            "engine": "python",
            "workers": n_workers,
            "results": _run_python(kind, manager, items, n_workers),
            "log": log,
        }

    # Go path: authoritative once it runs -- never also run the Python path.
    batches = _partition(list(range(len(items))), n_workers)
    run_dir, spec_path, ids = _stage(manager.job_spec(), kind, items, batches)
    rc = _run_go(
        exe,
        spec_path,
        run_dir,
        ids,
        _readers_roots(),
        log,
        module=WORKER_MODULE,
        kind=kind,
        min_workers=min(DEFAULT_MIN_WORKERS, len(batches)),
        max_workers=len(batches),
    )
    by_id = _collect(run_dir, ids)
    results = [by_id.get(i) or {"error": NO_RESULT} for i in range(len(items))]
    if rc == 0 and len(by_id) == len(items):
        shutil.rmtree(run_dir, ignore_errors=True)
    else:
        log.append(f"[autopilot-pool] pool exited {rc}; scratch kept at {run_dir}")
    return {"engine": "go", "workers": len(batches), "results": results, "log": log}
