"""
Per-batch autopilot worker (CLI), and the job executor both pool paths share.

This is the unit of work the server's Go worker pool fans out to for the
self-healing autopilot (see :mod:`~file_analyzer.server.autopilot_pool`). Each
worker process is handed one *batch* of jobs of one *kind*, rebuilds an
identical :class:`~file_analyzer.server.backup.BackupManager` (with its
:class:`~file_analyzer.server.dbhost.DatabaseHost` and
:class:`~file_analyzer.server.catalog.SessionCatalog`) from the pool's job
spec, and runs every job with :func:`execute` -- the same function the
in-process thread-pool fallback calls, so a result never depends on which path
produced it.

Kinds and item shapes:

``inspect``  ``{"rec": <catalog record>, "entry": <cached health entry>, "deep": bool}``
    -> ``{"storage_key", "status", "problems", "entry": <updated entry>}``.
    A full check (SHA-256, then ``quick_check`` -- or ``integrity_check`` when
    ``deep``); read-only. The parent merges the returned entry into its state.
``verify``   ``{"storage_key", "timestamps": [...], "repair": bool, "lock_timeout"}``
    -> ``{"storage_key", "sets": [<set report>, ...]}``. Each set is verified
    (or repaired) under the key lock.
``stage``    ``{"storage_key", "candidates": [{"timestamp", "kind"}, ...], "dest"}``
    -> ``{"storage_key", "staged": <path or None>, "timestamp", "kind",
    "index", "failures": [...]}``. The caller already holds the key lock; the
    worker takes no lock.

Layout under the pool's ``--out`` directory::

    <out>/batches/batch_<i>.json   # written by the pool: {"batch_id", "kind", "items"}
    <out>/results/result_<i>.json  # written here: {"batch_id", "results": [{"id", "result"}]}
    <out>/status/<i>.ok | <i>.err  # completion markers

Usage:
    python -m file_analyzer.server.autopilot_worker --kind inspect \\
        --spec <SPEC.json> --out <DIR> --batch <BATCH.json> \\
        [--readers-root <ROOT> ...]
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from .backup import BackupManager

KINDS = ("inspect", "verify", "stage")


def execute(
    kind: str, manager: "BackupManager", item: Dict[str, Any]
) -> Dict[str, Any]:
    """Run one autopilot job against ``manager`` and return its result."""
    from .autopilot import ERROR, check_database, stage_restore

    if kind == "inspect":
        rec = dict(item["rec"])
        entry = dict(item.get("entry") or {})
        try:
            status, problems = check_database(
                manager.host, rec, entry, deep=bool(item.get("deep"))
            )
        except Exception as exc:
            status, problems = ERROR, [f"{type(exc).__name__}: {exc}"]
        return {
            "storage_key": rec["storage_key"],
            "status": status,
            "problems": list(problems),
            "entry": entry,
        }
    if kind == "verify":
        key = item["storage_key"]
        kwargs = {"repair": bool(item.get("repair"))}
        if item.get("lock_timeout") is not None:
            kwargs["lock_timeout"] = float(item["lock_timeout"])
        return {
            "storage_key": key,
            "sets": manager.check_sets(key, list(item["timestamps"]), **kwargs),
        }
    if kind == "stage":
        return stage_restore(
            manager, item["storage_key"], list(item["candidates"]), item["dest"]
        )
    raise ValueError(f"unknown autopilot job kind {kind!r}; expected {KINDS}")


def run_batch(kind: str, spec_file: str, out_dir: str, batch_file: str) -> Path:
    from file_analyzer.server.backup import BackupManager

    spec = json.loads(Path(spec_file).read_text(encoding="utf-8"))
    manager = BackupManager.from_job_spec(spec)

    batch = json.loads(Path(batch_file).read_text(encoding="utf-8"))
    batch_id = batch.get("batch_id")
    if batch.get("kind") not in (None, kind):
        raise ValueError(f"batch is for kind {batch.get('kind')!r}, not {kind!r}")

    results: List[Dict[str, Any]] = []
    for row in batch.get("items") or []:
        try:
            result = execute(kind, manager, row["item"])
        except Exception as exc:  # keep going; report per job
            result = {"error": f"{type(exc).__name__}: {exc}"}
        results.append({"id": row["id"], "result": result})

    results_dir = Path(out_dir) / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_path = results_dir / f"result_{batch_id}.json"
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text(
        json.dumps({"batch_id": batch_id, "results": results}, default=str),
        encoding="utf-8",
    )
    tmp.replace(out_path)  # the pool never sees a half-written result
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="server autopilot batch worker")
    ap.add_argument("--kind", required=True, choices=KINDS, help="job kind")
    ap.add_argument("--spec", required=True, help="path to the job-spec JSON file")
    ap.add_argument("--out", required=True, help="pool output directory")
    ap.add_argument("--batch", required=True, help="path to the batch JSON file")
    ap.add_argument(
        "--readers-root",
        action="append",
        default=[],
        help="path(s) added to sys.path so 'file_analyzer.server' resolves "
        "(repeatable; needed only for an un-installed/editable checkout)",
    )
    args = ap.parse_args(argv)

    for root in args.readers_root:
        resolved = str(Path(root).resolve())
        if resolved not in sys.path:
            sys.path.insert(0, resolved)

    out = Path(args.out)
    status_dir = out / "status"
    status_dir.mkdir(parents=True, exist_ok=True)
    bid = Path(args.batch).stem.replace("batch_", "")
    try:
        out_path = run_batch(args.kind, args.spec, args.out, args.batch)
        (status_dir / f"{bid}.ok").write_text(str(out_path), encoding="utf-8")
        print(f"[autopilot-worker] {args.kind} batch {bid}: OK -> {out_path}")
        return 0
    except Exception:
        tb = traceback.format_exc()
        (status_dir / f"{bid}.err").write_text(tb, encoding="utf-8")
        sys.stderr.write(f"[autopilot-worker] {args.kind} batch {bid}: ERROR\n{tb}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
