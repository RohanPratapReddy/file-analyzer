"""
Per-batch backup worker (CLI).

This is the unit of work the server's Go backup pool fans out to. Each worker
process is handed one *batch* of storage keys and backs up every database in it,
writing the resulting manifests as JSON. It rebuilds an identical
:class:`~file_analyzer.server.backup.BackupManager` (with its
:class:`~file_analyzer.server.dbhost.DatabaseHost` and
:class:`~file_analyzer.server.catalog.SessionCatalog`) from the serialized
*job spec* the pool stages, so a backup produced in a fanned-out subprocess uses
exactly the same online-snapshot / chunk / manifest / rotation logic as an
in-process one -- and therefore restores identically.

Layout under the pool's ``--out`` directory::

    <out>/batches/batch_<i>.json     # written by the pool: {"batch_id", "keys"}
    <out>/results/result_<i>.json    # written here: {"batch_id", "results":[...]}
    <out>/status/<i>.ok | <i>.err    # completion markers

Because distinct storage keys own disjoint on-disk backup subtrees and per-key
locks, batches back up concurrently without contention.

Usage:
    python -m file_analyzer.server.backup_worker \\
        --spec <SPEC.json> --out <DIR> --batch <BATCH.json> \\
        [--readers-root <ROOT> ...]
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List


def run_batch(spec_file: str, out_dir: str, batch_file: str) -> Path:
    from file_analyzer.server.backup import BackupManager

    spec = json.loads(Path(spec_file).read_text(encoding="utf-8"))
    manager = BackupManager.from_job_spec(spec)

    batch = json.loads(Path(batch_file).read_text(encoding="utf-8"))
    batch_id = batch.get("batch_id")
    keys = list(batch.get("keys") or [])

    results: List[Dict[str, Any]] = []
    for key in keys:
        try:
            results.append(manager.backup_database(key))
        except Exception as exc:  # keep going; report per key
            results.append({"storage_key": key, "error": str(exc)})

    results_dir = Path(out_dir) / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_path = results_dir / f"result_{batch_id}.json"
    out_path.write_text(
        json.dumps({"batch_id": batch_id, "results": results}),
        encoding="utf-8",
    )
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="server backup batch worker")
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
        out_path = run_batch(args.spec, args.out, args.batch)
        (status_dir / f"{bid}.ok").write_text(str(out_path), encoding="utf-8")
        print(f"[backup-worker] batch {bid}: OK -> {out_path}")
        return 0
    except Exception:
        tb = traceback.format_exc()
        (status_dir / f"{bid}.err").write_text(tb, encoding="utf-8")
        sys.stderr.write(f"[backup-worker] batch {bid}: ERROR\n{tb}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
