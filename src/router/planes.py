"""
Plane orchestration: launch the Go and Java analysis planes concurrently.

``RouterPlanes`` is the Python-side coordinator that:

    * partitions the shard set across the two language planes (Go + Java),
    * builds each plane's binary/class on demand (``go build`` / ``javac``),
    * runs both planes at the same wall-clock time (real cross-language
      parallelism), each fanning out to concurrent per-shard worker processes,
    * falls back to an in-process Python worker pool for any plane whose
      toolchain (go / javac+java) is unavailable, so the pipeline still completes,
    * verifies, via the ``temp/status`` markers, that every shard produced tables.

The planes themselves never touch the database and never reimplement analysis;
they only drive ``src/router/worker.py``. Injection into the database is handled
separately by ``RepositoryDatabaseGenerator`` (also concurrently).
"""

import concurrent.futures
import os
import shutil
import subprocess
import sys
import threading
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
        self.router_dir = self.readers_root / "src" / "router"
        self.go_dir = self.router_dir / "go"
        self.java_dir = self.router_dir / "java"
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

    def _java_class(self) -> Optional[Path]:
        if shutil.which("javac") is None or shutil.which("java") is None:
            return None
        out_dir = self.java_dir / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                ["javac", "-d", str(out_dir), "AnalyzerPlane.java"],
                cwd=self.java_dir,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                self.log.append(f"[planes] javac failed:\n{proc.stderr}")
                return None
            return out_dir
        except OSError as err:
            self.log.append(f"[planes] javac error: {err}")
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

    def _run_java_plane(self, out_dir: Path, shard_ids: List[str]) -> int:
        cmd = [
            "java",
            "-cp",
            str(out_dir),
            "AnalyzerPlane",
            "--python",
            self.python_exe,
            "--readers-root",
            str(self.readers_root),
            "--temp",
            str(self.temp_dir),
            "--shards",
            ",".join(shard_ids),
            "--workers",
            str(self.workers_per_plane),
        ]
        return self._stream_subprocess(cmd, self.java_dir)

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
        Partition shards across the Go and Java planes and run both concurrently.
        Raises ``PlaneError`` (leaving temp/ intact) if any shard failed.
        """
        shard_ids = [s["shard_id"] for s in shards]
        if not shard_ids:
            return

        # Deterministic partition: even indices -> Go, odd indices -> Java.
        go_shards = [sid for i, sid in enumerate(shard_ids) if i % 2 == 0]
        java_shards = [sid for i, sid in enumerate(shard_ids) if i % 2 == 1]

        go_exe = self._go_binary()
        java_out = self._java_class()

        results: Dict[str, int] = {}

        def go_runner():
            if go_exe is not None:
                results["go"] = self._run_go_plane(go_exe, go_shards)
            else:
                results["go"] = self._run_python_fallback("go-plane", go_shards)

        def java_runner():
            if java_out is not None:
                results["java"] = self._run_java_plane(java_out, java_shards)
            else:
                results["java"] = self._run_python_fallback("java-plane", java_shards)

        t_go = threading.Thread(target=go_runner, name="go-plane")
        t_java = threading.Thread(target=java_runner, name="java-plane")
        t_go.start()
        t_java.start()
        t_go.join()
        t_java.join()

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
