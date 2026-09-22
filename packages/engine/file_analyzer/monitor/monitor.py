"""
RepositoryMonitor -- the always-on background layer.

It watches a repository, and on every scan cycle:

    1. snapshots the tree and diffs it against the previous snapshot
       (:class:`Scanner`), detecting files created / modified / deleted by an
       agent, the user, or any third-party tool;
    2. records each change into the FIFO diff database
       (:class:`ChangeDiffDatabase`, last 16 changes);
    3. re-analyzes the created/modified files with the correct analyzer, either
       inline (a handful of files) or fanned out across the Go / Python worker
       pool (:class:`UpdateWorkerPool`) for a large change set;
    4. patches the re-analysis outcome back onto each change row and refreshes the
       live ``file_state`` index.

It runs two ways, both zombie-safe:

* :meth:`start` launches the scan loop on a **daemon thread** (dies with the
  process) -- used inside an agent session and by the MCP server;
* :meth:`run_forever` runs the loop in the foreground with SIGINT/SIGTERM
  handlers and a PID file -- used by ``python -m file_analyzer`` so the layer persists as
  its own process (see ``file_analyzer/__main__.py``).

The worker pool only ever spawns short-lived child processes that are always
waited on, so no defunct children accumulate.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .change_log import ChangeLogStore
from .diff_db import DEFAULT_CAPACITY, ChangeDiffDatabase
from .incremental import IncrementalUpdateEngine
from .pool import DEFAULT_MAX_WORKERS, DEFAULT_MIN_WORKERS, UpdateWorkerPool
from .scanner import Scanner

# Re-analyze inline (in the scan thread) when at most this many files changed;
# above it, fan out across the worker pool. Keeps tiny edits latency-free while
# large change sets (branch switch, bulk tool rewrite) get real parallelism.
DEFAULT_INLINE_THRESHOLD = 8


class RepositoryMonitor:
    def __init__(
        self,
        root: os.PathLike,
        out_dir: Optional[os.PathLike] = None,
        diff_db_path: Optional[os.PathLike] = None,
        interval: float = 2.0,
        capacity: int = DEFAULT_CAPACITY,
        min_workers: int = DEFAULT_MIN_WORKERS,
        max_workers: int = DEFAULT_MAX_WORKERS,
        inline_threshold: int = DEFAULT_INLINE_THRESHOLD,
        use_go: bool = True,
        python_exe: Optional[str] = None,
        readers_root: Optional[os.PathLike] = None,
        record_offline_changes: bool = True,
        reanalyze: bool = True,
        enable_change_log: bool = True,
        change_log_url: Optional[str] = None,
        change_log_path: Optional[os.PathLike] = None,
        enable_agents: bool = False,
        agents_include: Optional[List[str]] = None,
        agents_exclude: Optional[List[str]] = None,
        discover_agents: bool = True,
        agent_roster: Optional[str] = None,
        max_agent_files: int = 40,
    ):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(f"monitor root is not a directory: {self.root}")
        self.out_dir = (
            Path(out_dir).resolve() if out_dir else self.root / ".file-analyzer"
        )
        self.diff_db_path = (
            Path(diff_db_path).resolve()
            if diff_db_path
            else self.out_dir / "monitor" / "changes.db"
        )
        self.interval = max(0.2, float(interval))
        self.capacity = int(capacity)
        self.inline_threshold = max(0, int(inline_threshold))
        self.reanalyze = reanalyze
        self.record_offline_changes = record_offline_changes
        # ``readers_root`` is the directory containing the ``file_analyzer`` package.
        self.readers_root = (
            Path(readers_root).resolve()
            if readers_root
            else Path(__file__).resolve().parents[2]
        )

        self.db = ChangeDiffDatabase(str(self.diff_db_path), capacity=self.capacity)

        # Continuous, append-only change archive (a strict superset of the FIFO
        # ring above): every change the monitor records is also stored here and
        # never deleted, so an event evicted from the 16-deep ring survives. Local
        # SQLite by default; a URL redirects it to any remote SQL server.
        self.enable_change_log = enable_change_log
        self.change_log_url = change_log_url
        self.change_log_path = (
            Path(change_log_path).resolve()
            if change_log_path
            else self.out_dir / "monitor" / "changes_log.db"
        )
        self._change_log = None  # type: ignore[assignment]

        # Soft agent tier: when enabled, every re-analyzed file is additionally
        # enriched via a live MCP provider (the same agent layer a full run uses).
        # Off by default -- it is a no-op unless a provider is actually reachable.
        self.enable_agents = enable_agents
        self.agents_include = list(agents_include) if agents_include else None
        self.agents_exclude = list(agents_exclude) if agents_exclude else None
        self.discover_agents = discover_agents
        self.agent_roster = agent_roster
        self.max_agent_files = int(max_agent_files)
        agent_config = {
            "enable_agents": self.enable_agents,
            "agents_include": self.agents_include,
            "agents_exclude": self.agents_exclude,
            "discover_agents": self.discover_agents,
            "agent_roster": self.agent_roster,
            "project_dir": str(self.root),
            "max_agent_files": self.max_agent_files,
        }

        self.scanner = Scanner(
            self.root,
            extra_ignore_paths=[self.out_dir, self.diff_db_path],
        )
        self.updater = IncrementalUpdateEngine(
            readers_root=str(self.readers_root),
            enable_agents=self.enable_agents,
            agents_include=self.agents_include,
            agents_exclude=self.agents_exclude,
            discover_agents=self.discover_agents,
            agent_roster=self.agent_roster,
            project_dir=str(self.root),
            max_agent_files=self.max_agent_files,
        )
        self.pool = UpdateWorkerPool(
            readers_root=self.readers_root,
            out_dir=self.out_dir / "monitor" / "pool",
            python_exe=python_exe,
            min_workers=min_workers,
            max_workers=max_workers,
            use_go=use_go,
            agent_config=agent_config if self.enable_agents else None,
        )

        self._snapshot: Dict[str, Dict[str, Any]] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scan_lock = threading.Lock()
        self._pid_file: Optional[Path] = None
        self._started = False

    # ------------------------------------------------------------------
    # Baseline
    # ------------------------------------------------------------------
    def initialize(self) -> "RepositoryMonitor":
        self.db.initialize()
        if self.enable_change_log and self._change_log is None:
            try:
                self._change_log = ChangeLogStore(
                    repo=str(self.root),
                    url=self.change_log_url,
                    default_path=str(self.change_log_path),
                ).initialize()
                self.db.set_status(
                    change_log=self._change_log.display,
                    change_log_dialect=self._change_log.dialect,
                )
            except Exception as err:
                # The durable log must never take the monitor down; fall back to
                # FIFO-only and record why.
                self._change_log = None
                self.db.set_status(change_log_error=repr(err))
        self.db.set_status(
            root=str(self.root),
            pid=os.getpid(),
            interval=self.interval,
            capacity=self.capacity,
            running=0,
            started_at=time.time(),
            agents=1 if self.enable_agents else 0,
            agent_roster=self.agent_roster or "",
        )
        # Reconcile against any persisted state so changes that happened while the
        # monitor was down are still surfaced (bounded by the FIFO anyway).
        persisted = self.db.load_file_state()
        self._snapshot = self.scanner.snapshot()
        if persisted and self.record_offline_changes:
            pseudo_old = {
                rel: {
                    "hash": meta.get("hash"),
                    "size": meta.get("size"),
                    "mtime": meta.get("mtime"),
                    "is_binary": False,
                    "text": None,
                }
                for rel, meta in persisted.items()
            }
            offline = self.scanner.diff(pseudo_old, self._snapshot)
            if offline:
                self._process_events(offline, engine_note="offline")
        else:
            # First run (or offline recording disabled): seed the live index
            # silently -- the current tree is the baseline, not a change.
            for rel, entry in self._snapshot.items():
                self.db.upsert_file_state(
                    rel,
                    abs_path=str(self.root / rel),
                    hash=entry.get("hash"),
                    size=entry.get("size"),
                    mtime=entry.get("mtime"),
                    analyzer_class=self.updater.resolve_class(rel),
                    last_seq=None,
                )
        return self

    # ------------------------------------------------------------------
    # One scan cycle
    # ------------------------------------------------------------------
    def scan_once(self) -> Dict[str, Any]:
        """Run one detect -> record -> re-analyze cycle. Returns a batch summary."""
        with self._scan_lock:
            t0 = time.time()
            new_snapshot = self.scanner.snapshot()
            events = self.scanner.diff(self._snapshot, new_snapshot)
            scan_ms = (time.time() - t0) * 1000.0
            self._snapshot = new_snapshot
            if not events:
                self.db.set_status(last_scan_ts=time.time())
                return {"changes": 0, "created": 0, "modified": 0, "deleted": 0}
            return self._process_events(events, scan_ms=scan_ms)

    def _process_events(
        self,
        events: List[Dict[str, Any]],
        scan_ms: Optional[float] = None,
        engine_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        created = sum(1 for e in events if e["change_type"] == "created")
        modified = sum(1 for e in events if e["change_type"] == "modified")
        deleted = sum(1 for e in events if e["change_type"] == "deleted")

        # Fill analyzer_class + provisional update_status before recording so the
        # row is meaningful even if it later falls out of the 16-deep FIFO.
        for e in events:
            e["analyzer_class"] = self.updater.resolve_class(e["rel_path"])
            e["update_status"] = (
                "deleted" if e["change_type"] == "deleted" else "pending"
            )

        batch_id = self.db.begin_batch()
        seqs = self.db.record_events(batch_id, events)
        seq_by_path = {e["abs_path"]: s for e, s in zip(events, seqs)}
        # Stamp seq/batch onto the event dicts so the durable change log records
        # them with the same identity as the FIFO ring.
        for e, s in zip(events, seqs):
            e["seq"] = s
            e["batch_id"] = batch_id

        # Update the live index for created/modified/deleted.
        for e in events:
            if e["change_type"] == "deleted":
                self.db.delete_file_state(e["rel_path"])
            else:
                self.db.upsert_file_state(
                    e["rel_path"],
                    abs_path=e["abs_path"],
                    hash=e["new_hash"],
                    size=e["new_size"],
                    mtime=self._snapshot.get(e["rel_path"], {}).get("mtime"),
                    analyzer_class=e["analyzer_class"],
                    last_seq=seq_by_path.get(e["abs_path"]),
                )

        # Re-analyze created/modified files.
        engine_used = engine_note or "none"
        workers = 0
        upd_ms = None
        if self.reanalyze:
            to_analyze = [
                e["abs_path"]
                for e in events
                if e["change_type"] in ("created", "modified")
            ]
            if to_analyze:
                t1 = time.time()
                outcome = self._reanalyze(to_analyze)
                upd_ms = (time.time() - t1) * 1000.0
                engine_used = outcome["engine"]
                workers = outcome["workers"]
                result_by_path = {r.get("path"): r for r in outcome["results"]}
                for res in outcome["results"]:
                    seq = seq_by_path.get(res.get("path"))
                    if seq is None:
                        continue
                    self.db.update_event_result(
                        seq,
                        update_status=res.get("status", "error"),
                        update_summary=res.get("summary"),
                        detail=res.get("reason") or res.get("error"),
                    )
                # Fold the final outcome onto each event so the durable change log
                # captures the post-re-analysis status, not the provisional one.
                for e in events:
                    res = result_by_path.get(e["abs_path"])
                    if res is not None:
                        e["update_status"] = res.get("status", "error")
                        e["update_summary"] = res.get("summary")
                        e["detail"] = res.get("reason") or res.get("error")

        # Archive EVERY event durably (superset of the FIFO ring): nothing is lost
        # when the 16-deep buffer recycles a slot. Best-effort -- never fatal.
        if self._change_log is not None:
            try:
                self._change_log.append_events(events)
            except Exception as err:
                self.db.set_status(change_log_error=repr(err))

        self.db.finalize_batch(
            batch_id,
            created=created,
            modified=modified,
            deleted=deleted,
            scan_ms=scan_ms,
            update_ms=upd_ms,
            workers=workers,
            engine=engine_used,
        )
        return {
            "batch_id": batch_id,
            "changes": len(events),
            "created": created,
            "modified": modified,
            "deleted": deleted,
            "engine": engine_used,
            "workers": workers,
        }

    def _reanalyze(self, abs_paths: List[str]) -> Dict[str, Any]:
        """Inline for a small change set, else fan out across the worker pool."""
        if len(abs_paths) <= self.inline_threshold:
            results = self.updater.analyze_many(abs_paths)
            return {"engine": "inline", "workers": 1, "results": results}
        return self.pool.analyze(abs_paths)

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception as err:  # a monitor must never die on one bad scan
                self.db.set_status(last_error=repr(err))
            self._stop.wait(self.interval)

    def start(self) -> "RepositoryMonitor":
        """Start the scan loop on a daemon thread (idempotent)."""
        if self._started:
            return self
        if not self._snapshot and not self._started:
            self.initialize()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name=f"repo-monitor:{self.root.name}", daemon=True
        )
        self._thread.start()
        self._started = True
        self.db.set_status(running=1, pid=os.getpid())
        return self

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the loop to stop and join the thread (idempotent, zombie-safe)."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        self._started = False
        try:
            self.db.set_status(running=0, stopped_at=time.time())
        except Exception:
            pass

    def close(self) -> None:
        self.stop()
        self.db.close()
        if self._change_log is not None:
            try:
                self._change_log.close()
            finally:
                self._change_log = None

    # ------------------------------------------------------------------
    # Standalone process mode
    # ------------------------------------------------------------------
    def run_forever(self, pid_file: Optional[os.PathLike] = None) -> int:
        """Run the loop in the foreground with signal handling + a PID file.

        Used by ``python -m file_analyzer`` so the monitoring layer persists as its own
        process. SIGINT / SIGTERM trigger a clean shutdown; the PID file is always
        removed on exit. Returns a process exit code.
        """
        self.initialize()
        self._pid_file = (
            Path(pid_file) if pid_file else (self.out_dir / "monitor" / "monitor.pid")
        )
        self._pid_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._pid_file.write_text(str(os.getpid()), encoding="utf-8")
        except OSError:
            self._pid_file = None

        def _handle(signum, _frame):
            print(f"\n[monitor] signal {signum} received; shutting down cleanly...")
            self._stop.set()

        installed = []
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handle)
                installed.append(sig)
            except (ValueError, OSError):
                # Not in the main thread, or unsupported on this platform.
                pass
        # Best-effort: reap any child that becomes available (POSIX). The pool
        # already waits on its children, but this guarantees no defunct process
        # survives even if a child is orphaned.
        if hasattr(signal, "SIGCHLD"):
            try:
                signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            except (ValueError, OSError):
                pass

        self.db.set_status(running=1, pid=os.getpid(), mode="standalone")
        print(
            f"[monitor] watching {self.root} every {self.interval}s "
            f"(diff db: {self.diff_db_path}); Ctrl-C to stop."
        )
        try:
            while not self._stop.is_set():
                summary = self.scan_once()
                if summary.get("changes"):
                    print(
                        f"[monitor] batch {summary.get('batch_id')}: "
                        f"+{summary['created']} ~{summary['modified']} "
                        f"-{summary['deleted']} "
                        f"(engine={summary.get('engine')}, "
                        f"workers={summary.get('workers')})"
                    )
                self._stop.wait(self.interval)
        finally:
            self.db.set_status(running=0, stopped_at=time.time())
            self.db.close()
            if self._change_log is not None:
                try:
                    self._change_log.close()
                finally:
                    self._change_log = None
            if self._pid_file is not None:
                try:
                    self._pid_file.unlink()
                except OSError:
                    pass
            for sig in installed:
                try:
                    signal.signal(sig, signal.SIG_DFL)
                except (ValueError, OSError):
                    pass
        return 0

    # ------------------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        return self.db.summary()

    def recent_changes(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        return self.db.recent_changes(limit)

    def change_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Most-recent slice of the durable change log (survives FIFO wrap)."""
        if self._change_log is None:
            return []
        return self._change_log.recent(limit)

    def __enter__(self) -> "RepositoryMonitor":
        return self.initialize()

    def __exit__(self, *exc: Any) -> None:
        self.close()
