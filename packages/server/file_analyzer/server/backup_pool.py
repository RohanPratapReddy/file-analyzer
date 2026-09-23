"""
Worker-pool driver for concurrent backups.

When the server backs up everything it hosts, :func:`backup_keys` runs the
per-database backups across many workers at once. It mirrors the monitor's
:class:`~file_analyzer.monitor.pool.UpdateWorkerPool` and the router's plane
design exactly:

* the real fast path is a **Go worker pool** (``file_analyzer/server/go/backup.go``):
  a fixed set of goroutines drains a channel of batches and spawns one
  ``python -m file_analyzer.server.backup_worker`` child process per batch, giving
  genuine OS-level parallelism. The binary is built on demand with ``go build``
  and is simply skipped when the Go toolchain is not on ``PATH``;
* the fallback is an **in-process thread pool**
  (``concurrent.futures.ThreadPoolExecutor``) that calls
  :meth:`BackupManager.backup_database` for each key concurrently, so the backup
  runs on a bare interpreter with nothing but the standard library.

Both paths call the very same :meth:`BackupManager.backup_database`, so a backup
produced by either is byte-for-byte restore-compatible. Concurrency is genuine
and safe because distinct storage keys own disjoint on-disk backup subtrees and
per-key locks (see :meth:`BackupManager._key_lock_path`), so parallel backups of
different databases never contend.

Correctness rule (shared with the SQL injector pool): the two paths are mutually
exclusive. Once the Go pool has run, its per-key results are authoritative and
the Python path is *not* also run -- re-running would create duplicate backup
sets for the keys the Go path already backed up. Keys the Go pool failed to
produce a result for are reported as failures, not silently re-backed-up.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # avoid an import cycle at runtime
    from .backup import BackupManager

DEFAULT_MIN_WORKERS = 4
DEFAULT_MAX_WORKERS = 32

# file_analyzer/server/backup_pool.py -> the server package's own go/ tree.
_GO_DIR = Path(__file__).resolve().parent / "go"


def _clamp_workers(n: int, min_workers: int, max_workers: int) -> int:
    if n <= 0:
        return 0
    workers = min(n, max_workers)
    workers = max(workers, min(n, min_workers))
    return max(1, workers)


def _partition(keys: List[str], groups: int) -> List[List[str]]:
    """Round-robin ``keys`` into ``groups`` non-empty batches."""
    if groups <= 1:
        return [list(keys)] if keys else []
    buckets: List[List[str]] = [[] for _ in range(groups)]
    for i, key in enumerate(keys):
        buckets[i % groups].append(key)
    return [b for b in buckets if b]


def _readers_roots() -> List[str]:
    """Namespace-package roots that make ``file_analyzer.server`` importable.

    For an installed wheel this is a single site-packages dir; for an editable /
    un-installed checkout the ``file_analyzer`` namespace is split across the
    ``packages/*`` dirs, so every portion is forwarded to the worker subprocess.
    """
    roots: List[str] = []
    try:
        import file_analyzer

        for portion in list(getattr(file_analyzer, "__path__", []) or []):
            root = str(Path(portion).resolve().parent)
            if root not in roots:
                roots.append(root)
    except Exception:  # pragma: no cover - defensive
        pass
    return roots


# ---------------------------------------------------------------------------
# Toolchain build (on demand)
# ---------------------------------------------------------------------------
_BUILD_LOCK = threading.Lock()
_BINARY_NAME = "backup-pool.exe" if os.name == "nt" else "backup-pool"


def _binary_fresh(exe: Path) -> bool:
    """True when ``exe`` exists and is newer than every Go source + go.mod."""
    try:
        built = exe.stat().st_mtime
        sources = [*_GO_DIR.glob("*.go"), _GO_DIR / "go.mod"]
        return all(src.stat().st_mtime <= built for src in sources if src.exists())
    except OSError:
        return False


def _go_binary(log: List[str]) -> Optional[Path]:
    """The server pool binary, built on demand (``None`` without a Go toolchain).

    One driver binary serves every server pool (backups and the autopilot's
    inspect/verify/stage jobs). It is rebuilt only when a Go source is newer
    than the binary, and builds are serialized in-process so concurrent pools
    (the periodic backup and an autopilot tick, say) never race on the output
    file.
    """
    if shutil.which("go") is None:
        return None
    exe = _GO_DIR / _BINARY_NAME
    with _BUILD_LOCK:
        if _binary_fresh(exe):
            return exe
        try:
            proc = subprocess.run(
                ["go", "build", "-o", exe.name, "."],
                cwd=_GO_DIR,
                capture_output=True,
                text=True,
            )
        except OSError as err:
            log.append(f"[server-pool] go build error: {err}")
            return None
        if proc.returncode != 0:
            log.append(f"[server-pool] go build failed:\n{proc.stderr}")
            return None
        return exe


def _stage(
    spec: Dict[str, Any],
    batches: List[List[str]],
    *,
    prefix: str = "fa-backup-pool-",
) -> "tuple[Path, Path, List[int]]":
    # Scratch lives outside backup_dir so it never shows up as a bogus backup key.
    run_dir = Path(tempfile.mkdtemp(prefix=prefix))
    (run_dir / "batches").mkdir(parents=True, exist_ok=True)
    spec_path = run_dir / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    ids: List[int] = []
    for i, keys in enumerate(batches):
        (run_dir / "batches" / f"batch_{i}.json").write_text(
            json.dumps({"batch_id": i, "keys": keys}), encoding="utf-8"
        )
        ids.append(i)
    return run_dir, spec_path, ids


def _run_go(
    exe: Path,
    spec_path: Path,
    run_dir: Path,
    ids: List[int],
    roots: List[str],
    log: List[str],
    *,
    module: Optional[str] = None,
    kind: Optional[str] = None,
    min_workers: int = DEFAULT_MIN_WORKERS,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> int:
    """Run the Go pool over the staged batches ``ids``; return its exit code.

    ``module``/``kind`` select the Python worker each goroutine runs (default:
    the backup worker); the pool's output is appended to ``log``.
    """
    cmd = [
        str(exe),
        "-python",
        sys.executable or "python",
        "-spec",
        str(spec_path),
        "-out",
        str(run_dir),
        "-batch-ids",
        ",".join(str(i) for i in ids),
        "-readers-roots",
        os.pathsep.join(roots),
        "-min-workers",
        str(min_workers),
        "-max-workers",
        str(max_workers),
    ]
    if module:
        cmd += ["-module", module]
    if kind:
        cmd += ["-kind", kind]
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(_GO_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as err:
        log.append(f"[server-pool] failed to launch pool: {err}")
        return 1
    assert proc.stdout is not None
    for line in proc.stdout:
        log.append(line.rstrip("\n"))
    return proc.wait()  # always reap the child


def _collect(run_dir: Path, ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
    by_batch: Dict[int, List[Dict[str, Any]]] = {}
    for bid in ids:
        rp = run_dir / "results" / f"result_{bid}.json"
        if not rp.is_file():
            continue
        try:
            payload = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        by_batch[bid] = list(payload.get("results") or [])
    return by_batch


# ---------------------------------------------------------------------------
# In-process (pure-Python) fallback
# ---------------------------------------------------------------------------
def _backup_python(
    manager: "BackupManager", keys: List[str], workers: int
) -> List[Dict[str, Any]]:
    """Concurrent in-process backup -- the toolchain-free fallback.

    Per-key locks make concurrent :meth:`backup_database` calls on distinct keys
    contention-free; SQLite's online backup releases the GIL during its C copy,
    so the work genuinely overlaps.
    """
    results: List[Dict[str, Any]] = [None] * len(keys)  # type: ignore[list-item]

    def _one(idx_key: "tuple[int, str]") -> None:
        idx, key = idx_key
        try:
            results[idx] = manager.backup_database(key)
        except Exception as exc:
            results[idx] = {"storage_key": key, "error": str(exc)}

    pool = max(1, min(workers, len(keys)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=pool) as ex:
        list(ex.map(_one, list(enumerate(keys))))
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def backup_keys(
    manager: "BackupManager",
    keys: List[str],
    *,
    workers: Optional[int] = None,
    use_go: bool = True,
) -> Dict[str, Any]:
    """Back up every key in ``keys`` across the worker pool.

    Returns ``{"engine", "workers", "results": [...], "log": [...]}`` where each
    result is a backup manifest dict or ``{"storage_key", "error"}``. The order
    of ``results`` is not significant (each carries its own ``storage_key``).
    """
    keys = [k for k in keys if k]
    if not keys:
        return {"engine": "none", "workers": 0, "results": [], "log": []}

    log: List[str] = []
    n_workers = workers or _clamp_workers(
        len(keys), DEFAULT_MIN_WORKERS, DEFAULT_MAX_WORKERS
    )
    n_workers = max(1, min(n_workers, len(keys)))

    exe = _go_binary(log) if use_go else None

    if exe is None:
        # Pure-Python fallback: never touched by the Go path, so no double-backup.
        results = _backup_python(manager, keys, n_workers)
        return {
            "engine": "python",
            "workers": n_workers,
            "results": results,
            "log": log,
        }

    # Go path is authoritative once it runs -- we do not also run the Python path.
    batches = _partition(keys, n_workers)
    run_dir, spec_path, ids = _stage(manager.job_spec(), batches)
    roots = _readers_roots()
    rc = _run_go(exe, spec_path, run_dir, ids, roots, log)

    by_batch = _collect(run_dir, ids)
    results: List[Dict[str, Any]] = []
    seen: set = set()
    for bid, batch_keys in zip(ids, batches):
        produced = by_batch.get(bid)
        if produced is None:
            # This batch's worker left no result file: report each key as failed
            # rather than re-running it in Python (which would double-back-up any
            # sibling key the same worker had already committed).
            for key in batch_keys:
                results.append(
                    {"storage_key": key, "error": "backup worker produced no result"}
                )
                seen.add(key)
            continue
        for item in produced:
            results.append(item)
            if isinstance(item, dict) and item.get("storage_key"):
                seen.add(item["storage_key"])
    # Any key that never appeared in a result (defensive) is a failure.
    for key in keys:
        if key not in seen:
            results.append(
                {"storage_key": key, "error": "backup worker produced no result"}
            )

    if rc == 0:
        shutil.rmtree(run_dir, ignore_errors=True)
    else:
        log.append(f"[backup-pool] pool exited {rc}; scratch kept at {run_dir}")

    return {
        "engine": "go",
        "workers": len(batches),
        "results": results,
        "log": log,
    }
