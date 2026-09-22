"""
Cross-platform process detachment, PID files, and liveness -- stdlib only.

The hosting server must, once launched on a VPS, *persist detached with a PID*
until the user stops it. This module provides the primitives for that on both
POSIX and Windows without any third-party daemonization library:

* :func:`spawn_detached` launches a command as a fully detached child that
  outlives the launching process. On POSIX it uses ``start_new_session=True``
  (which calls ``setsid``, breaking the controlling-terminal association -- the
  key step of daemonization); on Windows it uses
  ``DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`` creation flags. In both cases
  stdio is redirected to a log file (or the null device) and the real child PID
  is returned. This is the modern, dependency-free equivalent of the classic
  double-fork, and unlike a bare double-fork it hands back a usable PID.
* :func:`pid_alive` / :func:`stop_pid` check and terminate a process by PID on
  either platform (``os.kill(pid, 0)`` / ``SIGTERM`` -> ``SIGKILL`` on POSIX;
  ``OpenProcess`` / ``TerminateProcess`` via ``ctypes`` on Windows).
* :func:`write_pid_file` / :func:`read_pid_file` / :func:`remove_pid_file`
  manage a PID file the way :mod:`file_analyzer.monitor` already does.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence, Union

PathLike = Union[str, "os.PathLike[str]"]

_POSIX = os.name == "posix"

# Windows creation flags (defined here so the module imports on POSIX too).
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW = 0x08000000


# ---------------------------------------------------------------------- #
# PID files
# ---------------------------------------------------------------------- #
def write_pid_file(path: PathLike, pid: Optional[int] = None) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(str(pid if pid is not None else os.getpid()), encoding="utf-8")


def read_pid_file(path: PathLike) -> Optional[int]:
    try:
        text = Path(path).read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None
    try:
        return int(text)
    except ValueError:
        return None


def remove_pid_file(path: PathLike) -> None:
    try:
        Path(path).unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------- #
# Liveness / termination
# ---------------------------------------------------------------------- #
def pid_alive(pid: int) -> bool:
    """True if a process with ``pid`` currently exists."""
    if pid <= 0:
        return False
    if _POSIX:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists but owned by another user
        return True
    # Windows: OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION.
    import ctypes  # local import: only needed on Windows

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, ctypes.c_uint(pid)
    )
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return code.value == STILL_ACTIVE
        return True
    finally:
        kernel32.CloseHandle(handle)


def stop_pid(pid: int, timeout: float = 10.0) -> bool:
    """Ask a process to stop, escalating to a forced kill; return True if gone."""
    if not pid_alive(pid):
        return True
    if _POSIX:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not pid_alive(pid):
                return True
            time.sleep(0.1)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.2)
        return not pid_alive(pid)
    # Windows.
    import ctypes

    PROCESS_TERMINATE = 0x0001
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, ctypes.c_uint(pid))
    if not handle:
        return not pid_alive(pid)
    try:
        kernel32.TerminateProcess(handle, 1)
    finally:
        kernel32.CloseHandle(handle)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.1)
    return not pid_alive(pid)


# ---------------------------------------------------------------------- #
# Detached spawn
# ---------------------------------------------------------------------- #
def spawn_detached(
    argv: Sequence[str],
    *,
    cwd: Optional[PathLike] = None,
    env: Optional[dict] = None,
    log_path: Optional[PathLike] = None,
) -> int:
    """Launch ``argv`` as a detached, terminal-independent child; return its PID.

    The child keeps running after the launching process exits. stdout/stderr go
    to ``log_path`` if given, otherwise to the platform null device; stdin is the
    null device. Works identically from an interactive shell or from within
    another server process.
    """
    argv = [str(a) for a in argv]
    stdin = open(os.devnull, "rb")
    if log_path is not None:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        out = open(log_path, "ab", buffering=0)
        err = out
    else:  # pragma: no cover - exercised only when no log requested
        out = open(os.devnull, "ab")
        err = out
    try:
        kwargs: dict = dict(
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=stdin,
            stdout=out,
            stderr=err,
            close_fds=True,
        )
        if _POSIX:
            kwargs["start_new_session"] = True  # setsid -> detach from terminal
        else:  # pragma: no cover - platform-specific
            kwargs["creationflags"] = (
                _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW
            )
        proc = subprocess.Popen(argv, **kwargs)
        return proc.pid
    finally:
        # The child has inherited its own copies of these descriptors, so the
        # parent closes its own. ``err`` may be the same object as ``out``; a set
        # avoids double-closing it.
        for fh in {id(stdin): stdin, id(out): out, id(err): err}.values():
            try:
                fh.close()
            except OSError:
                pass


def python_module_argv(module: str, *args: str) -> List[str]:
    """Build an argv that re-invokes this interpreter on ``-m module`` + args."""
    return [sys.executable, "-m", module, *[str(a) for a in args]]
