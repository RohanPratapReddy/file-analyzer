"""
The database-hosting server -- a real, detachable, multi-instance control plane.

``DatabaseServer`` is the second half of the split the SDK exposes: where
``FileAnalyzerMCPServer`` speaks the MCP/agent transport that *builds* databases,
this class *hosts* them and hands clients a way to reach them. It:

* resolves (or reuses) a **session token** for a repository via the shared
  :class:`~file_analyzer.server.catalog.SessionCatalog` -- parallel servers on the
  same repo adopt the same token, so no duplicate database copies are made;
* stores every hosted database under ``PROJECT_ROOT-{token}-{db_name}`` in SQLite
  or Postgres/MySQL via :class:`~file_analyzer.server.dbhost.DatabaseHost`;
* serves a small, token-authenticated JSON control plane over HTTP
  (``http.server.ThreadingHTTPServer`` -- standard library, so the bare-interpreter
  import contract holds) that is the **entrypoint** a client connects to;
* runs **periodic, chunked, rotating backups** in the background
  (:class:`~file_analyzer.server.backup.BackupManager`), optionally
  **Reed-Solomon erasure coded** into ``k`` data + ``m`` parity shards spread
  across several shard directories, with a periodic **scrub** that verifies
  every block and rebuilds lost or corrupt shards
  (:mod:`~file_analyzer.server.sharding`);
* runs a periodic **retention janitor** that evicts idle databases and old
  backups and holds the session to a total size budget
  (:class:`~file_analyzer.server.retention.RetentionManager`);
* runs the **autopilot** (:class:`~file_analyzer.server.autopilot.Autopilot`):
  scheduled health checks of every hosted database and of the catalog,
  automatic healing from verified backups (with quarantine of the damaged
  copy), backup-set scrub/repair, retention, backup freshness and debris /
  orphan sweeps -- so the server maintains and repairs itself;
* can surface the backend **Postgres logs**
  (:class:`~file_analyzer.server.pglog.PostgresLogTailer`);
* **persists detached with a PID** once started on a VPS, and is stopped by PID.

The HTTP surface is intentionally minimal and read-biased; database *queries*
are validated as single read-only statements before they ever touch a file.
"""

from __future__ import annotations

import json
import signal
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .._version import __version__
from ..naming import storage_key
from ..tokens import PathLike, new_server_id, project_fingerprint
from .autopilot import TASKS as AUTOPILOT_TASKS
from .autopilot import Autopilot, AutopilotPolicy
from .backup import DEFAULT_SCRUB_INTERVAL, BackupManager
from .catalog import SessionCatalog, default_catalog_dir
from .daemon import (
    pid_alive,
    python_module_argv,
    read_pid_file,
    remove_pid_file,
    spawn_detached,
    stop_pid,
    write_pid_file,
)
from .dbhost import DEFAULT_CHUNK_BYTES, DatabaseHost
from .locking import FileLock, atomic_write_text
from .pglog import PostgresLogTailer
from .readonly import is_readonly_select
from .retention import (
    DEFAULT_BACKUP_MAX_AGE,
    DEFAULT_MAX_AGE,
    DEFAULT_RETENTION_INTERVAL,
    RetentionManager,
    RetentionPolicy,
)
from .sharding import DEFAULT_BLOCK_BYTES, ErasureConfig

DEFAULT_HOST = "127.0.0.1"
DEFAULT_BACKUP_INTERVAL = 900.0  # 15 minutes
DEFAULT_AUTOPILOT_INTERVAL = 300.0  # 5 minutes between maintenance ticks
HEARTBEAT_INTERVAL = 15.0


def _free_port(host: str) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, 0))
        return s.getsockname()[1]
    finally:
        s.close()


class DatabaseServer:
    """Host + serve a repo-session's databases; run detached; stop by PID."""

    def __init__(
        self,
        root: PathLike = ".",
        *,
        backend: str = "sqlite",
        host: str = DEFAULT_HOST,
        port: int = 0,
        data_dir: Optional[PathLike] = None,
        catalog_dir: Optional[PathLike] = None,
        catalog_target: Optional[str] = None,
        token: Optional[str] = None,
        server_id: Optional[str] = None,
        chunk_bytes: int = DEFAULT_CHUNK_BYTES,
        backup_interval: float = DEFAULT_BACKUP_INTERVAL,
        backup_part_bytes: Optional[int] = None,
        backup_keep: int = 5,
        retention_interval: float = DEFAULT_RETENTION_INTERVAL,
        retention_max_age: Optional[float] = DEFAULT_MAX_AGE,
        backup_max_age: Optional[float] = DEFAULT_BACKUP_MAX_AGE,
        retention_max_bytes: Optional[int] = None,
        rs_data_shards: int = 0,
        rs_parity_shards: int = 2,
        rs_block_bytes: int = DEFAULT_BLOCK_BYTES,
        shard_dirs: Optional[List[PathLike]] = None,
        scrub_interval: float = DEFAULT_SCRUB_INTERVAL,
        autopilot_interval: float = DEFAULT_AUTOPILOT_INTERVAL,
        check_interval: Optional[float] = None,
        deep_check_interval: Optional[float] = None,
        autopilot_startup_delay: Optional[float] = None,
        auto_heal: bool = True,
        allow_rollback: bool = True,
        auto_backup: bool = True,
        drift_action: str = "restore",
        autopilot_workers: Optional[int] = None,
        autopilot_use_go: bool = True,
        autopilot_policy: Optional[AutopilotPolicy] = None,
    ) -> None:
        self.root = str(Path(root).resolve())
        self.backend = backend
        self.host = host
        self.port = int(port)
        self.server_id = server_id or new_server_id()
        self.backup_interval = float(backup_interval)
        self.backup_keep = int(backup_keep)
        self.chunk_bytes = int(chunk_bytes)
        self.retention_interval = float(retention_interval)
        self.scrub_interval = float(scrub_interval)
        # Reed-Solomon backups: off (plain chunked sets) unless data shards > 0.
        self.erasure: Optional[ErasureConfig] = None
        if int(rs_data_shards) > 0:
            self.erasure = ErasureConfig(
                data_shards=rs_data_shards,
                parity_shards=rs_parity_shards,
                block_bytes=rs_block_bytes,
                shard_dirs=[str(d) for d in (shard_dirs or [])],
            )
            for d in self.erasure.shard_dirs:
                Path(d).mkdir(parents=True, exist_ok=True)
        elif shard_dirs:
            raise ValueError(
                "shard_dirs need erasure coding: set rs_data_shards (e.g. 4)"
            )

        self.catalog = SessionCatalog(catalog_dir, target=catalog_target)
        self.fingerprint = project_fingerprint(self.root)

        session = self.catalog.get_or_create_session(self.root, backend=backend)
        # An explicit token overrides only if it matches an existing session; the
        # catalog is authoritative for reuse, so we take what it returned.
        self.token = token or session["token"]
        self.session_created = session["created"]

        base = Path(catalog_dir) if catalog_dir else default_catalog_dir()
        self.home = base.parent  # ~/.file-analyzer
        self.data_dir = Path(data_dir) if data_dir else base / self.fingerprint / "data"
        self.backup_dir = base / self.fingerprint / "backups"
        self.run_dir = base / self.fingerprint / "run"
        for d in (self.data_dir, self.backup_dir, self.run_dir):
            d.mkdir(parents=True, exist_ok=True)

        self.dbhost = DatabaseHost(
            root=self.root,
            token=self.token,
            data_dir=self.data_dir,
            catalog=self.catalog,
            backend=backend,
            chunk_bytes=self.chunk_bytes,
        )
        part_bytes = backup_part_bytes or max(self.chunk_bytes, 16 * 1024 * 1024)
        self.backups = BackupManager(
            self.dbhost,
            backup_dir=self.backup_dir,
            part_bytes=part_bytes,
            keep=self.backup_keep,
            erasure=self.erasure,
        )
        self.retention = RetentionManager(
            self.dbhost,
            self.backups,
            RetentionPolicy(
                max_age=retention_max_age,
                backup_max_age=backup_max_age,
                max_total_bytes=retention_max_bytes,
            ),
        )
        # Content swaps of a key (re-host, heal) serialize with its backups.
        self.dbhost.key_lock_factory = lambda k: FileLock(
            self.backups._key_lock_path(k), timeout=600.0
        )
        # Damaged databases flagged by the autopilot are never backed up (by
        # this process, a parallel instance or a Go-pool backup worker).
        self.backups.suspect_file = self.run_dir / "suspect.json"

        self.autopilot_interval = float(autopilot_interval or 0.0)
        if autopilot_policy is None:
            defaults = AutopilotPolicy()
            autopilot_policy = AutopilotPolicy(
                interval=self.autopilot_interval or defaults.interval,
                startup_delay=(
                    defaults.startup_delay
                    if autopilot_startup_delay is None
                    else autopilot_startup_delay
                ),
                check_interval=(
                    defaults.check_interval
                    if check_interval is None
                    else check_interval
                ),
                deep_check_interval=(
                    defaults.deep_check_interval
                    if deep_check_interval is None
                    else deep_check_interval
                ),
                # The autopilot takes over the retention + scrub schedules.
                retention_interval=self.retention_interval,
                scrub_interval=self.scrub_interval,
                heal=auto_heal,
                allow_rollback=allow_rollback,
                drift_action=drift_action,
                ensure_backups=auto_backup,
                workers=autopilot_workers,
                use_go=autopilot_use_go,
                backup_max_age=(
                    2 * self.backup_interval + 60 if self.backup_interval > 0 else None
                ),
            )
        self.autopilot = Autopilot(
            self.dbhost,
            self.backups,
            self.retention,
            run_dir=self.run_dir,
            policy=autopilot_policy,
            quarantine_dir=base / self.fingerprint / "quarantine",
            own_server_id=self.server_id,
            backend=self.backend,
            on_catalog_restored=self._reregister,
        )
        self._serving = False

        self._httpd: Optional[ThreadingHTTPServer] = None
        self._stop = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None

    # -- file locations -------------------------------------------------
    @property
    def pid_file(self) -> Path:
        return self.run_dir / f"server-{self.server_id}.pid"

    @property
    def endpoint_file(self) -> Path:
        return self.run_dir / f"endpoint-{self.server_id}.json"

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # -- hosting convenience -------------------------------------------
    def host_database(self, source_db_path: PathLike, db_name: str) -> Dict[str, Any]:
        """Store a database file under this session; return its catalog record."""
        hosted = self.dbhost.host(source_db_path, db_name)
        return hosted.record

    def storage_key_for(self, db_name: str) -> str:
        return storage_key(self.root, self.token, db_name)

    def databases(self) -> List[Dict[str, Any]]:
        return [h.record for h in self.dbhost.list()]

    # -- serving (foreground) ------------------------------------------
    def serve(self, *, contained: bool = True) -> int:
        """Run the control plane in the foreground until stopped. Returns exit code.

        With ``contained=True`` the bare-metal containment guard is enforced first
        (serving is a runnable surface, like the MCP server and the monitor).
        Installs SIGINT/SIGTERM handlers, writes a PID + endpoint file, registers
        in the shared catalog, starts the heartbeat and the periodic backup loop,
        and cleans all of that up on exit.
        """
        if contained:
            from ..runtime_guard import require_virtualized

            require_virtualized(context="file_analyzer.server")

        if self.port == 0:
            self.port = _free_port(self.host)

        httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        httpd.daemon_threads = True
        httpd.app = self  # type: ignore[attr-defined]
        self._httpd = httpd
        # server_address reflects the actually-bound port.
        self.port = httpd.server_address[1]

        self._write_endpoint()
        write_pid_file(self.pid_file)
        self._register()
        self._serving = True
        self._start_heartbeat()
        if self.backup_interval > 0:
            self.backups.start_periodic(
                self.backup_interval,
                database_url=self.backend if self.dbhost.is_remote else None,
            )
        if self.autopilot_interval > 0:
            # The autopilot schedules retention and the backup scrub itself,
            # between its checks and heals, so they never race each other.
            self.autopilot.start()
        else:
            if self.retention_interval > 0:
                self.retention.start_periodic(self.retention_interval)
            if self.erasure is not None and self.scrub_interval > 0:
                self.backups.start_scrub(
                    self.scrub_interval,
                    workers=self.autopilot.policy.workers,
                    use_go=self.autopilot.policy.use_go,
                )

        self._install_signals(httpd)
        print(
            f"[server] hosting {self.root}\n"
            f"[server] session token: {self.token}\n"
            f"[server] listening on {self.url} (backend={self.backend}, "
            f"pid={read_pid_file(self.pid_file)})\n"
            f"[server] connect a client with the token above; Ctrl-C to stop.",
            flush=True,
        )
        try:
            httpd.serve_forever(poll_interval=0.5)
        finally:
            self._teardown(httpd)
        return 0

    def _install_signals(self, httpd: ThreadingHTTPServer) -> None:
        def _handle(signum, _frame):
            print(f"\n[server] signal {signum}; shutting down...", flush=True)
            threading.Thread(target=httpd.shutdown, daemon=True).start()

        for sig in (signal.SIGINT, getattr(signal, "SIGTERM", signal.SIGINT)):
            try:
                signal.signal(sig, _handle)
            except (ValueError, OSError):
                pass  # not the main thread / unsupported

    def _write_endpoint(self) -> None:
        info = {
            "server_id": self.server_id,
            "pid": None,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "backend": self.backend,
            "token": self.token,
            "project_root": self.root,
            "fingerprint": self.fingerprint,
            "data_dir": str(self.data_dir),
            "started_at": time.time(),
        }
        import os

        info["pid"] = os.getpid()
        atomic_write_text(self.endpoint_file, json.dumps(info, indent=2))

    def _register(self) -> None:
        import os

        self.catalog.register_server(
            {
                "server_id": self.server_id,
                "pid": os.getpid(),
                "host": self.host,
                "port": self.port,
                "backend": self.backend,
                "data_dir": str(self.data_dir),
                "fingerprint": self.fingerprint,
                "project_root": self.root,
                "token": self.token,
                "url": self.url,
                "started_at": time.time(),
                "heartbeat_at": time.time(),
            }
        )

    def _reregister(self) -> None:
        """Re-add this server's row after the autopilot rebuilt the catalog."""
        if self._serving:
            self._register()

    def _start_heartbeat(self) -> None:
        def _beat() -> None:
            while not self._stop.wait(HEARTBEAT_INTERVAL):
                try:
                    self.catalog.heartbeat(self.server_id)
                except Exception:
                    pass

        self._hb_thread = threading.Thread(
            target=_beat, name="fa-server-heartbeat", daemon=True
        )
        self._hb_thread.start()

    def _teardown(self, httpd: ThreadingHTTPServer) -> None:
        self._stop.set()
        self._serving = False
        try:
            self.autopilot.stop()
        except Exception:
            pass
        try:
            self.retention.stop()
        except Exception:
            pass
        try:
            self.backups.stop()
        except Exception:
            pass
        try:
            self.catalog.unregister_server(self.server_id)
        except Exception:
            pass
        try:
            httpd.server_close()
        except Exception:
            pass
        remove_pid_file(self.pid_file)
        try:
            self.endpoint_file.unlink()
        except OSError:
            pass

    # -- detached lifecycle --------------------------------------------
    def start_detached(self) -> Dict[str, Any]:
        """Launch this server as a detached background process; return its info.

        The child runs ``python -m file_analyzer.server run ...`` with the same
        configuration and the already-resolved session token, so it comes up with
        the identical token namespace. This call waits until the child has bound
        its port (its endpoint file appears) and then returns
        ``{server_id, pid, url, token, backend, ...}``.
        """
        if self.port == 0:
            self.port = _free_port(self.host)
        # ``root`` is a positional argument of the ``run`` subcommand; the catalog
        # location is forwarded explicitly so the child coordinates through the
        # very same catalog (and therefore adopts the already-resolved token).
        argv = python_module_argv(
            "file_analyzer.server",
            "run",
            self.root,
            "--backend",
            self.backend,
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--catalog-dir",
            str(self.catalog.dir),
            "--catalog-target",
            str(self.catalog.target),
            "--server-id",
            self.server_id,
            "--token",
            self.token,
            "--chunk-bytes",
            str(self.chunk_bytes),
            "--backup-interval",
            str(self.backup_interval),
            "--backup-keep",
            str(self.backup_keep),
            *self._retention_argv(),
            *self._erasure_argv(),
            *self._autopilot_argv(),
        )
        log_path = self.run_dir / f"server-{self.server_id}.log"
        pid = spawn_detached(argv, cwd=self.root, log_path=log_path)
        # Wait for the child to bind + publish its endpoint file.
        info = self._await_endpoint(pid, timeout=20.0)
        info["log"] = str(log_path)
        return info

    def _retention_argv(self) -> List[str]:
        """The retention policy as ``run`` flags (0 = disabled), for the child."""
        pol = self.retention.policy
        return [
            "--retention-interval",
            str(self.retention_interval),
            "--retention-days",
            str((pol.max_age or 0) / 86400.0),
            "--backup-retention-days",
            str((pol.backup_max_age or 0) / 86400.0),
            "--max-total-size",
            str(pol.max_total_bytes or 0),
        ]

    def _autopilot_argv(self) -> List[str]:
        """The autopilot configuration as ``run`` flags, for the child."""
        pol = self.autopilot.policy
        argv = [
            "--autopilot-interval",
            str(self.autopilot_interval),
            "--check-interval",
            str(pol.check_interval),
            "--deep-check-interval",
            str(pol.deep_check_interval),
            "--autopilot-startup-delay",
            str(pol.startup_delay),
            "--drift-action",
            pol.drift_action,
        ]
        if not pol.heal:
            argv.append("--no-auto-heal")
        if not pol.allow_rollback:
            argv.append("--no-rollback")
        if not pol.ensure_backups:
            argv.append("--no-auto-backup")
        if pol.workers:
            argv += ["--autopilot-workers", str(pol.workers)]
        if not pol.use_go:
            argv.append("--no-go-workers")
        return argv

    def _erasure_argv(self) -> List[str]:
        """The Reed-Solomon backup config as ``run`` flags, for the child."""
        if self.erasure is None:
            return []
        argv = [
            "--rs-data-shards",
            str(self.erasure.data_shards),
            "--rs-parity-shards",
            str(self.erasure.parity_shards),
            "--rs-block-size",
            str(self.erasure.block_bytes),
            "--scrub-interval",
            str(self.scrub_interval),
        ]
        for d in self.erasure.shard_dirs:
            argv += ["--shard-dir", d]
        return argv

    def _await_endpoint(self, pid: int, timeout: float) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.endpoint_file.is_file():
                try:
                    info = json.loads(self.endpoint_file.read_text(encoding="utf-8"))
                    self.port = int(info.get("port", self.port))
                    return info
                except (OSError, ValueError):
                    pass
            if not pid_alive(pid):
                raise RuntimeError(
                    "detached server exited before it started listening; "
                    f"see log at {self.run_dir / f'server-{self.server_id}.log'}"
                )
            time.sleep(0.1)
        raise TimeoutError("timed out waiting for the detached server to start")

    def stop(
        self, *, all_for_repo: bool = False, timeout: float = 10.0
    ) -> Dict[str, Any]:
        """Stop this server (by its PID) or all servers hosting this repo."""
        stopped: List[Dict[str, Any]] = []
        targets: List[Dict[str, Any]]
        if all_for_repo:
            targets = self.catalog.list_servers(self.root, prune=False)
        else:
            pid = read_pid_file(self.pid_file)
            targets = [{"server_id": self.server_id, "pid": pid}] if pid else []
        for row in targets:
            pid = row.get("pid")
            ok = stop_pid(int(pid), timeout=timeout) if pid else True
            try:
                self.catalog.unregister_server(row["server_id"])
            except Exception:
                pass
            stopped.append(
                {"server_id": row.get("server_id"), "pid": pid, "stopped": ok}
            )
        return {"stopped": stopped}

    def status(self) -> Dict[str, Any]:
        """Live status: running servers for this repo + hosted databases."""
        servers = self.catalog.list_servers(self.root, prune=True)
        return {
            "project_root": self.root,
            "fingerprint": self.fingerprint,
            "token": self.token,
            "backend": self.backend,
            "servers": servers,
            "databases": self.databases(),
            "data_dir": str(self.data_dir),
            "backup_dir": str(self.backup_dir),
            "retention": self.retention_status(),
            "backups": self.backup_status(),
            "autopilot": self.autopilot_status(),
        }

    # -- autopilot (self-healing maintenance) --------------------------
    def autopilot_status(self) -> Dict[str, Any]:
        """Schedule, per-database health, suspect keys and recent events."""
        st = self.autopilot.status()
        st["enabled"] = self.autopilot_interval > 0
        return st

    def run_maintenance(
        self,
        *,
        dry_run: bool = False,
        tasks: Optional[List[str]] = None,
        force: bool = True,
        wait: bool = True,
    ) -> Dict[str, Any]:
        """Run one autopilot tick now (all tasks unless ``tasks`` names some).

        ``force`` ignores the task schedules; ``dry_run`` only reports what
        would be checked/healed/removed; ``wait`` waits for a tick already in
        progress (in any process) instead of skipping.
        """
        if tasks:
            bad = [t for t in tasks if t not in AUTOPILOT_TASKS]
            if bad:
                raise ValueError(
                    f"unknown maintenance task(s) {bad}; valid: {list(AUTOPILOT_TASKS)}"
                )
        return self.autopilot.run_once(
            dry_run=dry_run, tasks=tasks, force=force, wait=wait
        )

    def check_health(self) -> Dict[str, Any]:
        """Check the catalog and every hosted database now; repairs nothing."""
        return self.run_maintenance(tasks=["catalog", "check"])

    # -- backups --------------------------------------------------------
    def backup_status(self) -> Dict[str, Any]:
        """Backup format, erasure-coding config and the last integrity scrub."""
        return {
            "format": "reed-solomon" if self.erasure else "chunked",
            "interval": self.backup_interval,
            "keep": self.backup_keep,
            "erasure": self.erasure.summary() if self.erasure else None,
            "shard_roots": (
                [str(r) for r in self.backups.shard_roots()] if self.erasure else []
            ),
            "scrub_interval": self.scrub_interval if self.erasure else None,
            "last_scrub": self.backups.last_scrub,
        }

    def verify_backups(
        self, storage_key: Optional[str] = None, timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """Check every (or one) backup set block by block; modifies nothing."""
        pol = self.autopilot.policy
        return self.backups.verify_backups(
            storage_key, timestamp, workers=pol.workers, use_go=pol.use_go
        )

    def repair_backups(
        self, storage_key: Optional[str] = None, timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """Rebuild lost/corrupt shards of erasure-coded backup sets."""
        pol = self.autopilot.policy
        return self.backups.repair_backups(
            storage_key, timestamp, workers=pol.workers, use_go=pol.use_go
        )

    def restore_backup(
        self, storage_key: str, dest: PathLike, timestamp: Optional[str] = None
    ) -> Path:
        """Restore a backup set (newest if ``timestamp`` is None) into ``dest``."""
        return self.backups.restore(storage_key, timestamp, dest)

    # -- retention ------------------------------------------------------
    def retention_status(self) -> Dict[str, Any]:
        """Policy, janitor interval, current usage and the last pass's summary."""
        last = self.retention.last_report
        return {
            "policy": self.retention.policy.to_dict(),
            "interval": self.retention_interval,
            "usage": self.retention.usage(),
            "last_run": (
                None
                if last is None
                else {
                    "dry_run": last["dry_run"],
                    "freed_bytes": last["freed_bytes"],
                    "evicted": len(last["evicted"]),
                    "pruned_backups": len(last["pruned_backups"]),
                    "over_budget": last["over_budget"],
                }
            ),
        }

    def enforce_retention(self, *, dry_run: bool = False) -> Dict[str, Any]:
        """Run one retention pass now (or report what it would do)."""
        return self.retention.enforce(dry_run=dry_run)

    # -- postgres logs --------------------------------------------------
    def postgres_logs(self, lines: int = 100) -> Dict[str, Any]:
        if not self.dbhost.is_remote or self.dbhost.dialect != "postgresql":
            return {
                "message": "Postgres logs are only available on a postgresql backend.",
                "lines": [],
            }
        return PostgresLogTailer(self.backend).tail(lines)


# ====================================================================== #
# HTTP control-plane handler
# ====================================================================== #
class _Handler(BaseHTTPRequestHandler):
    server_version = f"file-analyzer-server/{__version__}"

    # Quiet by default; the server prints its own lifecycle lines.
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return

    @property
    def app(self) -> DatabaseServer:
        return self.server.app  # type: ignore[attr-defined]

    # -- helpers --------------------------------------------------------
    def _send_json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, filename: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def _authed(self) -> bool:
        header = self.headers.get("Authorization", "")
        token = ""
        if header.startswith("Bearer "):
            token = header[len("Bearer ") :].strip()
        # Compare in constant time.
        import hmac

        return hmac.compare_digest(token, self.app.token)

    def _body_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return {}

    # -- routing --------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)
        try:
            if path == "/health":
                return self._send_json(200, self._health())
            if not self._authed():
                return self._send_json(401, {"error": "unauthorized"})
            if path == "/session":
                return self._send_json(200, self._session())
            if path == "/databases":
                return self._send_json(200, {"databases": self.app.databases()})
            if path.startswith("/databases/") and path.endswith("/download"):
                key = path[len("/databases/") : -len("/download")]
                return self._download(key)
            if path == "/backups":
                key = qs.get("storage_key", [None])[0]
                return self._send_json(
                    200, {"backups": self.app.backups.list_backups(key)}
                )
            if path == "/retention":
                return self._send_json(200, self.app.retention_status())
            if path == "/backups/status":
                return self._send_json(200, self.app.backup_status())
            if path == "/autopilot":
                return self._send_json(200, self.app.autopilot_status())
            if path == "/pglogs":
                lines = int(qs.get("lines", ["100"])[0])
                return self._send_json(200, self.app.postgres_logs(lines))
            if path == "/servers":
                return self._send_json(
                    200,
                    {"servers": self.app.catalog.list_servers(self.app.root)},
                )
            return self._send_json(404, {"error": f"no such route: {path}"})
        except Exception as exc:  # pragma: no cover - defensive
            return self._send_json(500, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)
        try:
            if not self._authed():
                return self._send_json(401, {"error": "unauthorized"})
            if path == "/databases":
                return self._host_from_path()
            if path == "/databases/upload":
                return self._host_from_upload(qs)
            if path == "/query":
                return self._query()
            if path == "/backup":
                return self._backup()
            if path in ("/backups/verify", "/backups/repair"):
                body = self._body_json()
                action = (
                    self.app.verify_backups
                    if path.endswith("verify")
                    else self.app.repair_backups
                )
                return self._send_json(
                    200, action(body.get("storage_key"), body.get("timestamp"))
                )
            if path == "/retention":
                body = self._body_json()
                return self._send_json(
                    200,
                    self.app.enforce_retention(dry_run=bool(body.get("dry_run"))),
                )
            if path == "/autopilot/run":
                body = self._body_json()
                tasks = body.get("tasks")
                if tasks is not None and not (
                    isinstance(tasks, list) and all(isinstance(t, str) for t in tasks)
                ):
                    raise ValueError("tasks must be a list of task names")
                return self._send_json(
                    200,
                    self.app.run_maintenance(
                        dry_run=bool(body.get("dry_run")),
                        tasks=tasks or None,
                        force=bool(body.get("force", True)),
                    ),
                )
            return self._send_json(404, {"error": f"no such route: {path}"})
        except FileNotFoundError as exc:
            return self._send_json(404, {"error": str(exc)})
        except KeyError as exc:
            return self._send_json(404, {"error": str(exc).strip("'\"")})
        except ValueError as exc:
            return self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover - defensive
            return self._send_json(500, {"error": str(exc)})

    # -- endpoint implementations --------------------------------------
    def _health(self) -> Dict[str, Any]:
        # Liveness must not depend on the catalog: a damaged catalog is the
        # autopilot's job to repair, not a reason for a supervisor to restart.
        try:
            n_databases: Optional[int] = len(self.app.databases())
        except Exception:
            n_databases = None
        last = self.app.autopilot.last_report
        return {
            "status": "ok",
            "service": "file-analyzer-database-server",
            "version": __version__,
            "backend": self.app.backend,
            "server_id": self.app.server_id,
            "project_root": self.app.root,
            "databases": n_databases,
            "autopilot": {
                "running": self.app.autopilot.running,
                "healthy": None if last is None else last.get("healthy"),
                "problems": None if last is None else len(last.get("problems", [])),
            },
        }

    def _session(self) -> Dict[str, Any]:
        return {
            "token": self.app.token,
            "project_root": self.app.root,
            "fingerprint": self.app.fingerprint,
            "backend": self.app.backend,
            "data_dir": str(self.app.data_dir),
        }

    def _download(self, key: str) -> None:
        data = self.app.dbhost.read_bytes(key)
        self._send_bytes(data, f"{key}.db")

    def _host_from_path(self) -> None:
        body = self._body_json()
        source = body.get("source_path")
        db_name = body.get("db_name")
        if not source or not db_name:
            raise ValueError("source_path and db_name are required")
        rec = self.app.host_database(source, db_name)
        self._send_json(200, {"hosted": rec})

    def _host_from_upload(self, qs: Dict[str, List[str]]) -> None:
        db_name = qs.get("db_name", [None])[0]
        if not db_name:
            raise ValueError("db_name query parameter is required")
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            raise ValueError("empty upload body")
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
            remaining = length
            while remaining > 0:
                block = self.rfile.read(min(1024 * 1024, remaining))
                if not block:
                    break
                tmp.write(block)
                remaining -= len(block)
            tmp_path = tmp.name
        try:
            rec = self.app.host_database(tmp_path, db_name)
        finally:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
        self._send_json(200, {"hosted": rec})

    def _query(self) -> None:
        body = self._body_json()
        key = body.get("storage_key")
        sql = body.get("sql")
        limit = int(body.get("limit", 100) or 100)
        if not key or not sql:
            raise ValueError("storage_key and sql are required")
        if not is_readonly_select(sql):
            raise ValueError("only a single read-only SELECT/WITH query is allowed")
        result = self.app.dbhost.query(key, sql, limit=limit)
        self._send_json(200, result)

    def _backup(self) -> None:
        body = self._body_json()
        key = body.get("storage_key")
        if key:
            self._send_json(200, {"manifest": self.app.backups.backup_database(key)})
        else:
            self._send_json(200, {"manifests": self.app.backups.backup_all()})
