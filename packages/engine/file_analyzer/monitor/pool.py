"""
Worker-pool driver for incremental re-analysis.

When a scan produces a set of changed files, :class:`UpdateWorkerPool` runs the
per-file re-analysis across many workers at once. It mirrors the router's
``RouterPlanes`` design exactly:

* the real fast path is a **Go worker pool** (``file_analyzer/monitor/go/plane.go``): a
  fixed set of goroutines drains a channel of batches and spawns one
  ``python -m file_analyzer.monitor.worker`` child process per batch, giving genuine
  OS-level parallelism. The binary is built on demand with ``go build`` and is
  simply skipped if the Go toolchain is not on ``PATH``;
* the fallback is an **in-process Python pool**
  (``concurrent.futures.ThreadPoolExecutor``) that launches the same worker
  subprocesses concurrently, so the pipeline runs on a bare interpreter.

Pool sizing honours a floor/ceiling: at least ``min_workers`` workers when there
is that much work, never more than ``max_workers`` and never more than one worker
per file. Defaults are 16 / 128, inside the requested ~10-20 min / ~100-200 max
envelope. Files are partitioned round-robin into exactly that many batches, and
each batch becomes one worker process -- so processes run concurrently up to the
pool size.

Zombie-safety: every child is waited on (the Go process waits on its goroutines'
children via ``cmd.Wait``; the Python fallback waits on each ``Popen``). Nothing
is left detached.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_MIN_WORKERS = 16
DEFAULT_MAX_WORKERS = 128


def _clamp_workers(n_files: int, min_workers: int, max_workers: int) -> int:
    if n_files <= 0:
        return 0
    workers = min(n_files, max_workers)
    workers = max(workers, min(n_files, min_workers))
    return max(1, workers)


def _partition(files: List[str], groups: int) -> List[List[str]]:
    """Round-robin ``files`` into ``groups`` non-empty batches."""
    if groups <= 1:
        return [list(files)] if files else []
    buckets: List[List[str]] = [[] for _ in range(groups)]
    for i, f in enumerate(files):
        buckets[i % groups].append(f)
    return [b for b in buckets if b]


class UpdateWorkerPool:
    def __init__(
        self,
        readers_root: os.PathLike,
        out_dir: os.PathLike,
        python_exe: Optional[str] = None,
        min_workers: int = DEFAULT_MIN_WORKERS,
        max_workers: int = DEFAULT_MAX_WORKERS,
        use_go: bool = True,
        agent_config: Optional[Dict[str, Any]] = None,
    ):
        self.readers_root = Path(readers_root).resolve()
        self.out_dir = Path(out_dir).resolve()
        self.python_exe = python_exe or sys.executable or "python"
        self.min_workers = max(1, int(min_workers))
        self.max_workers = max(self.min_workers, int(max_workers))
        self.use_go = use_go
        # Threaded verbatim into every batch file so a fanned-out worker runs the
        # soft agent tier identically to the inline path (empty = agents off).
        self.agent_config = dict(agent_config) if agent_config else None
        self.go_dir = self.readers_root / "file_analyzer" / "monitor" / "go"
        self.log: List[str] = []

    # ------------------------------------------------------------------
    def _go_binary(self) -> Optional[Path]:
        if not self.use_go or shutil.which("go") is None:
            return None
        exe = self.go_dir / ("monitor-pool.exe" if os.name == "nt" else "monitor-pool")
        try:
            proc = subprocess.run(
                ["go", "build", "-o", exe.name, "."],
                cwd=self.go_dir,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                self.log.append(f"[monitor-pool] go build failed:\n{proc.stderr}")
                return None
            return exe
        except OSError as err:
            self.log.append(f"[monitor-pool] go build error: {err}")
            return None

    def _stream_subprocess(self, cmd: List[str], cwd: Path) -> int:
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError as err:
            self.log.append(f"[monitor-pool] failed to launch {cmd[0]}: {err}")
            return 1
        assert proc.stdout is not None
        for line in proc.stdout:
            self.log.append(line.rstrip("\n"))
        return proc.wait()  # always reap the child

    # ------------------------------------------------------------------
    def _write_batches(self, batches: List[List[str]]) -> "tuple[Path, List[int]]":
        run_dir = self.out_dir / f"run_{int(time.time() * 1000)}"
        (run_dir / "batches").mkdir(parents=True, exist_ok=True)
        ids: List[int] = []
        for i, files in enumerate(batches):
            payload: Dict[str, Any] = {"batch_id": i, "files": files}
            if self.agent_config:
                payload["agents"] = self.agent_config
            (run_dir / "batches" / f"batch_{i}.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            ids.append(i)
        return run_dir, ids

    def _run_go(self, exe: Path, run_dir: Path, ids: List[int]) -> int:
        cmd = [
            str(exe),
            "-python",
            self.python_exe,
            "-readers-root",
            str(self.readers_root),
            "-out",
            str(run_dir),
            "-batch-ids",
            ",".join(str(i) for i in ids),
            "-min-workers",
            str(self.min_workers),
            "-max-workers",
            str(self.max_workers),
        ]
        return self._stream_subprocess(cmd, self.go_dir)

    def _run_python(self, run_dir: Path, ids: List[int]) -> int:
        worker_mod = "file_analyzer.monitor.worker"
        pool_size = max(1, min(len(ids), self.max_workers))

        def _one(bid: int) -> int:
            cmd = [
                self.python_exe,
                "-m",
                worker_mod,
                "--readers-root",
                str(self.readers_root),
                "--out",
                str(run_dir),
                "--batch",
                str(run_dir / "batches" / f"batch_{bid}.json"),
            ]
            return self._stream_subprocess(cmd, self.readers_root)

        failures = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as ex:
            for rc in ex.map(_one, ids):
                if rc != 0:
                    failures += 1
        return 1 if failures else 0

    def _collect(self, run_dir: Path, ids: List[int]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for bid in ids:
            rp = run_dir / "results" / f"result_{bid}.json"
            if not rp.is_file():
                continue
            try:
                payload = json.loads(rp.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            results.extend(payload.get("results") or [])
        return results

    # ------------------------------------------------------------------
    def analyze(self, files: List[str]) -> Dict[str, Any]:
        """Re-analyze every path in ``files`` across the worker pool.

        Returns ``{"engine", "workers", "results": [...]}`` where each result is an
        :meth:`IncrementalUpdateEngine.analyze_file` dict.
        """
        files = [f for f in files if f]
        if not files:
            return {"engine": "none", "workers": 0, "results": []}

        workers = _clamp_workers(len(files), self.min_workers, self.max_workers)
        batches = _partition(files, workers)
        run_dir, ids = self._write_batches(batches)

        exe = self._go_binary()
        if exe is not None:
            engine = "go"
            rc = self._run_go(exe, run_dir, ids)
        else:
            engine = "python"
            rc = self._run_python(run_dir, ids)

        results = self._collect(run_dir, ids)
        # Best-effort cleanup of this run's scratch (keep on failure for debugging).
        if rc == 0:
            shutil.rmtree(run_dir, ignore_errors=True)
        return {
            "engine": engine,
            "workers": len(batches),
            "returncode": rc,
            "results": results,
        }
