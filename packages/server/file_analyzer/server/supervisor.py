"""
ServerSupervisor -- keep a detached hosting server alive (auto-restart).

The autopilot heals the *data*; the supervisor heals the *process*. It watches
a server started with :meth:`DatabaseServer.start_detached` from the launching
process and restarts it when it

* has **exited** (crash, OOM kill, ``kill -9``) -- detected immediately, also
  for a zombie child (it is reaped with ``waitpid``), or
* **stops answering** ``GET /health`` for ``failure_threshold`` consecutive
  probes (hung, deadlocked, ``SIGSTOP``-ed) -- the process is killed first.

A restart reuses the same server id and session token (so clients keep
connecting the same way), cleans the dead instance's PID/endpoint files and
catalog row, and retries on a fresh port if the old one cannot be bound.
Restarts back off exponentially and are capped at ``max_restarts`` per
``restart_window`` seconds; past that the supervisor gives up (``gave_up``) so a
server that crashes on startup does not spin forever. Everything is recorded in
:meth:`status`.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any, Deque, Dict, List, Optional

from .daemon import pid_alive, read_pid_file, remove_pid_file, stop_pid

if TYPE_CHECKING:  # pragma: no cover
    from .server import DatabaseServer

log = logging.getLogger("file_analyzer.server.supervisor")


def _reap(pid: int) -> Optional[bool]:
    """Reap ``pid`` if it is our exited child.

    Returns True if it had exited (and is now reaped), False if it is still
    running, None if it is not our child (the caller must use ``pid_alive``).
    """
    if not hasattr(os, "WNOHANG"):
        return None  # Windows: no zombies to reap
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return None
    except OSError:
        return None
    return done == pid


def process_alive(pid: Optional[int]) -> bool:
    """Liveness that does not mistake our own zombie child for a live one."""
    if not pid:
        return False
    reaped = _reap(int(pid))
    if reaped is True:
        return False
    if reaped is False:
        return True
    return pid_alive(int(pid))


class ServerSupervisor:
    """Watch one detached :class:`DatabaseServer` and restart it when it dies."""

    def __init__(
        self,
        server: "DatabaseServer",
        *,
        interval: float = 5.0,
        failure_threshold: int = 3,
        max_restarts: int = 5,
        restart_window: float = 3600.0,
        backoff: float = 1.0,
        max_backoff: float = 60.0,
        health_timeout: float = 5.0,
        stop_timeout: float = 10.0,
    ) -> None:
        self.server = server
        self.interval = max(0.2, float(interval))
        self.failure_threshold = max(1, int(failure_threshold))
        self.max_restarts = max(0, int(max_restarts))
        self.restart_window = float(restart_window)
        self.backoff = max(0.0, float(backoff))
        self.max_backoff = max(self.backoff, float(max_backoff))
        self.health_timeout = float(health_timeout)
        self.stop_timeout = float(stop_timeout)
        self.info: Optional[Dict[str, Any]] = None
        self.failures = 0
        self.restarts: Deque[float] = deque()
        self.history: List[Dict[str, Any]] = []
        self.gave_up = False
        self.last_check: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- probes ---------------------------------------------------------
    def _pid(self) -> Optional[int]:
        pid = read_pid_file(self.server.pid_file)
        if pid is None and self.info:
            pid = self.info.get("pid")
        return int(pid) if pid else None

    def _healthy(self) -> Optional[str]:
        """None when ``/health`` answers ok, else the failure reason."""
        from ..client import ServerClient

        try:
            res = ServerClient(
                self.server.url, self.server.token, timeout=self.health_timeout
            ).health()
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"
        if not isinstance(res, dict) or res.get("status") != "ok":
            return f"unexpected /health answer: {res!r}"[:200]
        return None

    def check_once(self) -> Dict[str, Any]:
        """Probe once; restart if needed. Returns what was observed/done."""
        with self._lock:
            now = time.time()
            pid = self._pid()
            out: Dict[str, Any] = {"at": now, "pid": pid}
            if self.gave_up:
                out["state"] = "gave-up"
            elif not process_alive(pid):
                out["state"] = "dead"
                out["restart"] = self._restart("process exited")
            else:
                reason = self._healthy()
                if reason is None:
                    self.failures = 0
                    out["state"] = "healthy"
                else:
                    self.failures += 1
                    out["state"] = "unresponsive"
                    out["failures"] = self.failures
                    out["reason"] = reason
                    if self.failures >= self.failure_threshold:
                        out["restart"] = self._restart(
                            f"unresponsive x{self.failures}: {reason}"
                        )
            self.last_check = out
            return out

    # -- restart --------------------------------------------------------
    def _restart(self, reason: str) -> Dict[str, Any]:
        now = time.time()
        while self.restarts and now - self.restarts[0] > self.restart_window:
            self.restarts.popleft()
        if len(self.restarts) >= self.max_restarts:
            self.gave_up = True
            ev = {
                "at": now,
                "reason": reason,
                "result": "gave-up",
                "restarts_in_window": len(self.restarts),
            }
            self.history.append(ev)
            log.error("supervisor giving up on %s: %s", self.server.server_id, reason)
            return ev
        # Exponential backoff between consecutive restarts.
        delay = min(self.max_backoff, self.backoff * (2 ** len(self.restarts)))
        if delay and self.restarts and self._stop.wait(delay):
            return {"at": now, "reason": reason, "result": "cancelled"}
        old_pid = self._pid()
        if old_pid and process_alive(old_pid):
            stop_pid(old_pid, timeout=self.stop_timeout)
        if old_pid:
            _reap(old_pid)
        remove_pid_file(self.server.pid_file)
        try:
            self.server.endpoint_file.unlink()
        except OSError:
            pass
        try:
            self.server.catalog.unregister_server(self.server.server_id)
        except Exception:
            pass
        ev: Dict[str, Any] = {"at": now, "reason": reason, "old_pid": old_pid}
        try:
            info = self.server.start_detached()
        except Exception as first:
            # The old port may still be held (TIME_WAIT, another process):
            # retry on a fresh one.
            ev["first_error"] = f"{type(first).__name__}: {first}"
            self.server.port = 0
            remove_pid_file(self.server.pid_file)
            try:
                info = self.server.start_detached()
            except Exception as exc:
                self.restarts.append(time.time())
                ev["result"] = "failed"
                ev["error"] = f"{type(exc).__name__}: {exc}"
                self.history.append(ev)
                log.error("supervisor restart failed: %s", exc)
                return ev
        self.restarts.append(time.time())
        self.info = info
        self.failures = 0
        ev.update({"result": "restarted", "pid": info.get("pid"), "url": info["url"]})
        self.history.append(ev)
        self.history = self.history[-100:]
        log.warning("supervisor restarted %s (%s)", self.server.server_id, reason)
        return ev

    # -- lifecycle ------------------------------------------------------
    def start(self, info: Optional[Dict[str, Any]] = None) -> "ServerSupervisor":
        """Begin watching (``info`` is what ``start_detached`` returned)."""
        if info is not None:
            self.info = info
        if self._thread is not None:
            return self
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.wait(self.interval):
                try:
                    self.check_once()
                except Exception:  # the watchdog itself must never die
                    log.exception("supervisor check failed")

        self._thread = threading.Thread(
            target=_loop, name="fa-server-supervisor", daemon=True
        )
        self._thread.start()
        return self

    def stop(self, timeout: float = 30.0) -> None:
        """Stop watching (the server itself keeps running)."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "server_id": self.server.server_id,
            "pid": self._pid(),
            "url": self.server.url,
            "interval": self.interval,
            "failure_threshold": self.failure_threshold,
            "consecutive_failures": self.failures,
            "restarts_in_window": len(self.restarts),
            "max_restarts": self.max_restarts,
            "restart_window": self.restart_window,
            "gave_up": self.gave_up,
            "last_check": self.last_check,
            "history": self.history[-20:],
        }
