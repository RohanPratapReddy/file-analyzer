"""
Per-batch incremental-update worker (CLI).

This is the unit of work the monitor's Go worker pool (and the Python fallback)
fan out to. Each worker process is handed one *batch* of changed files and
re-analyzes every file in it with :class:`IncrementalUpdateEngine`, writing the
results as JSON. Handing each process a batch (rather than one file per process)
amortizes the interpreter + fleet-import startup cost across many files, which is
what makes a large change set fast.

Layout under the pool's ``--out`` directory::

    <out>/batches/batch_<i>.json     # written by the pool: {"batch_id", "files"}
    <out>/results/result_<i>.json    # written here: {"batch_id", "results":[...]}
    <out>/status/<i>.ok | <i>.err    # completion markers (mirrors router/worker.py)

Usage:
    python -m file_analyzer.monitor.worker --readers-root <ROOT> --out <DIR> --batch <FILE>
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path


def run_batch(readers_root: str, out_dir: str, batch_file: str) -> Path:
    root = str(Path(readers_root).resolve())
    if root not in sys.path:
        sys.path.insert(0, root)

    from file_analyzer.monitor.incremental import IncrementalUpdateEngine

    spec = json.loads(Path(batch_file).read_text(encoding="utf-8"))
    batch_id = spec.get("batch_id")
    files = list(spec.get("files") or [])

    # The pool embeds the monitor's agent configuration into every batch file, so
    # a fanned-out worker runs the soft agent tier exactly like the inline path.
    agents = spec.get("agents") or {}
    engine = IncrementalUpdateEngine(
        readers_root=root,
        enable_agents=bool(agents.get("enable_agents")),
        agents_include=agents.get("agents_include"),
        agents_exclude=agents.get("agents_exclude"),
        discover_agents=bool(agents.get("discover_agents", True)),
        agent_roster=agents.get("agent_roster"),
        project_dir=agents.get("project_dir"),
        max_agent_files=int(agents.get("max_agent_files", 40)),
    )
    results = engine.analyze_many(files)

    results_dir = Path(out_dir) / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_path = results_dir / f"result_{batch_id}.json"
    out_path.write_text(
        json.dumps({"batch_id": batch_id, "results": results}),
        encoding="utf-8",
    )
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="monitor incremental-update batch worker")
    ap.add_argument("--readers-root", required=True)
    ap.add_argument("--out", required=True, help="pool output directory")
    ap.add_argument("--batch", required=True, help="path to the batch JSON file")
    args = ap.parse_args(argv)

    out = Path(args.out)
    status_dir = out / "status"
    status_dir.mkdir(parents=True, exist_ok=True)
    bid = Path(args.batch).stem.replace("batch_", "")
    try:
        out_path = run_batch(args.readers_root, args.out, args.batch)
        (status_dir / f"{bid}.ok").write_text(str(out_path), encoding="utf-8")
        print(f"[monitor-worker] batch {bid}: OK -> {out_path}")
        return 0
    except Exception:
        tb = traceback.format_exc()
        (status_dir / f"{bid}.err").write_text(tb, encoding="utf-8")
        sys.stderr.write(f"[monitor-worker] batch {bid}: ERROR\n{tb}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
