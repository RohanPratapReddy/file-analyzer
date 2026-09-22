"""
Plane orchestration: launch the Go analysis plane concurrently.

``RouterPlanes`` is the Python-side coordinator that:

    * builds the plane's binary on demand (``go build``),
    * runs the Go plane over the full shard set, fanning out to concurrent
      per-shard worker processes via its ``-workers`` goroutine pool,
    * falls back to an in-process Python worker pool when the Go toolchain is
      unavailable, so the pipeline still completes,
    * verifies, via the ``temp/status`` markers, that every shard produced tables.

The plane itself never touches the database and never reimplements analysis;
it only drives ``file_analyzer/router/worker.py``. Injection into the database is handled
separately by ``RepositoryDatabaseGenerator`` (also concurrently).
"""

import concurrent.futures
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


class PlaneError(RuntimeError):
    """Raised when one or more shards failed to analyze (temp/ is retained)."""


class RouterPlanes:
    def __init__(
        self,
        readers_root: Path,
        temp_dir: Path,
        python_exe: Optional[str] = None,
        workers_per_plane: Optional[int] = None,
    ):
        self.readers_root = Path(readers_root).resolve()
        self.temp_dir = Path(temp_dir).resolve()
        self.python_exe = python_exe or sys.executable or "python"
        self.workers_per_plane = workers_per_plane or max(1, (os.cpu_count() or 2))
        self.router_dir = self.readers_root / "file_analyzer" / "router"
        self.go_dir = self.router_dir / "go"
        self.log: List[str] = []

    # ------------------------------------------------------------------
    # Toolchain build (on demand)
    # ------------------------------------------------------------------
    def _go_binary(self) -> Optional[Path]:
        if shutil.which("go") is None:
            return None
        exe = self.go_dir / (
            "analysis-plane.exe" if os.name == "nt" else "analysis-plane"
        )
        try:
            proc = subprocess.run(
                ["go", "build", "-o", exe.name, "."],
                cwd=self.go_dir,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                self.log.append(f"[planes] go build failed:\n{proc.stderr}")
                return None
            return exe
        except OSError as err:
            self.log.append(f"[planes] go build error: {err}")
            return None

    # ------------------------------------------------------------------
    # Plane runners
    # ------------------------------------------------------------------
    def _run_go_plane(self, exe: Path, shard_ids: List[str]) -> int:
        cmd = [
            str(exe),
            "-python",
            self.python_exe,
            "-readers-root",
            str(self.readers_root),
            "-temp",
            str(self.temp_dir),
            "-shards",
            ",".join(shard_ids),
            "-workers",
            str(self.workers_per_plane),
        ]
        return self._stream_subprocess(cmd, self.go_dir)

    def _run_python_fallback(self, label: str, shard_ids: List[str]) -> int:
        """In-process concurrent fallback when a language toolchain is absent."""
        if not shard_ids:
            return 0
        self.log.append(f"[planes] {label}: python fallback for shards {shard_ids}")
        worker = self.router_dir / "worker.py"

        def _one(shard_id: str) -> int:
            cmd = [
                self.python_exe,
                str(worker),
                "--readers-root",
                str(self.readers_root),
                "--temp",
                str(self.temp_dir),
                "--shard",
                shard_id,
            ]
            return self._stream_subprocess(cmd, self.router_dir)

        failures = 0
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.workers_per_plane
        ) as ex:
            for rc in ex.map(_one, shard_ids):
                if rc != 0:
                    failures += 1
        return 1 if failures else 0

    def run_concordance(
        self,
        shards: List[Dict[str, Any]],
        index_chars: bool = True,
        max_bytes: int = 25_000_000,
    ) -> None:
        """Fan out the per-shard concordance worker (Database 1) over every shard.

        Uses the same one-process-per-shard model as the analysis planes, driving
        ``concordance_worker.py`` concurrently. Raises :class:`PlaneError` (leaving
        temp/ intact) if any shard failed to produce its ``.ok`` marker.
        """
        shard_ids = [s["shard_id"] for s in shards]
        if not shard_ids:
            return
        worker = self.router_dir / "concordance_worker.py"

        def _one(shard_id: str) -> int:
            cmd = [
                self.python_exe,
                str(worker),
                "--readers-root",
                str(self.readers_root),
                "--temp",
                str(self.temp_dir),
                "--shard",
                shard_id,
                "--max-bytes",
                str(max_bytes),
            ]
            if not index_chars:
                cmd.append("--no-index-chars")
            return self._stream_subprocess(cmd, self.router_dir)

        failures = 0
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.workers_per_plane
        ) as ex:
            for rc in ex.map(_one, shard_ids):
                if rc != 0:
                    failures += 1

        status_dir = self.temp_dir / "concordance_status"
        failed = [sid for sid in shard_ids if not (status_dir / f"{sid}.ok").exists()]
        if failed or failures:
            raise PlaneError(
                f"concordance workers reported failures; shards without OK marker: "
                f"{failed}. temp/ retained at {self.temp_dir} for debugging."
            )

    def _stream_subprocess(self, cmd: List[str], cwd: Path) -> int:
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError as err:
            self.log.append(f"[planes] failed to launch {cmd[0]}: {err}")
            return 1
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
        return proc.wait()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self, shards: List[Dict[str, Any]]) -> None:
        """
        Run the full shard set through the Go analysis plane (which fans out to
        concurrent per-shard workers), falling back to an in-process Python
        worker pool when the Go toolchain is unavailable.
        Raises ``PlaneError`` (leaving temp/ intact) if any shard failed.
        """
        shard_ids = [s["shard_id"] for s in shards]
        if not shard_ids:
            return

        go_exe = self._go_binary()

        results: Dict[str, int] = {}
        if go_exe is not None:
            results["go"] = self._run_go_plane(go_exe, shard_ids)
        else:
            results["python"] = self._run_python_fallback("go-plane", shard_ids)

        for line in self.log:
            print(line)

        # Verify every shard produced tables (status markers are authoritative).
        status_dir = self.temp_dir / "status"
        failed = []
        for sid in shard_ids:
            if not (status_dir / f"{sid}.ok").exists():
                failed.append(sid)
        if failed or any(rc != 0 for rc in results.values()):
            raise PlaneError(
                f"analysis planes reported failures; shards without OK marker: {failed}. "
                f"temp/ retained at {self.temp_dir} for debugging."
            )
