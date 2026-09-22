"""
Cross-platform advisory file locking and atomic writes -- standard library only.

The database-hosting server can run as several parallel instances against the
same repository session (see :mod:`file_analyzer.server.catalog`). Coordinating
them -- so two servers never mint two session tokens for the same repo, or write
the shared catalog at the same time -- needs a real inter-process lock that works
on both POSIX and Windows without any third-party dependency.

This module implements that with the two facilities the standard library already
ships: ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on Windows. Following the
approach distilled from the cross-platform-locking write-ups (see the module
references in the server package docstring), the lock is taken on a *disposable
sidecar* file (``<name>.lock``) rather than on the data file itself, so the data
file is never held open for the duration of a critical section and the platform
branch collapses to a few lines.

Everything here is import-safe on a bare interpreter: only stdlib modules, and
the platform-specific module (`fcntl`/`msvcrt`) is imported at module load on the
platform that has it.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, "os.PathLike[str]"]

_POSIX = os.name == "posix"

if _POSIX:  # pragma: no cover - platform-specific import
    import fcntl
else:  # pragma: no cover - platform-specific import
    import msvcrt


class LockTimeout(TimeoutError):
    """Raised when a :class:`FileLock` cannot be acquired within its timeout."""


class FileLock:
    """A cross-process exclusive lock backed by a sidecar lock file.

    Use it as a context manager around a critical section that touches a shared
    resource (the session catalog, a hosted-database registration, a backup
    rotation)::

        with FileLock(catalog_dir / "catalog.lock"):
            ...  # mutate the shared catalog atomically

    The lock is *advisory* on POSIX (``fcntl.flock``) and mandatory on Windows
    (``msvcrt.locking``); every cooperating process in this project goes through
    :class:`FileLock`, so advisory semantics are sufficient. Acquisition polls
    with a short sleep until ``timeout`` seconds elapse, then raises
    :class:`LockTimeout`.
    """

    def __init__(
        self, path: PathLike, timeout: float = 30.0, poll_interval: float = 0.05
    ) -> None:
        self.path = Path(path)
        self.timeout = float(timeout)
        self.poll_interval = float(poll_interval)
        self._fd: Optional[int] = None

    # -- acquisition ----------------------------------------------------
    def _open(self) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_RDWR so Windows msvcrt.locking (which needs a writable handle) works;
        # O_CREAT so the sidecar springs into existence on first use.
        return os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o644)

    def _try_lock(self, fd: int) -> bool:
        try:
            if _POSIX:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:  # pragma: no cover - platform-specific
                # Lock one byte at offset 0; the region is arbitrary but must be
                # consistent across processes. LK_NBLCK = non-blocking exclusive.
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def acquire(self) -> "FileLock":
        if self._fd is not None:
            return self  # re-entrant no-op within one process/thread
        fd = self._open()
        deadline = time.monotonic() + self.timeout
        while True:
            if self._try_lock(fd):
                self._fd = fd
                # Record the holder for debugging; best-effort.
                try:
                    os.ftruncate(fd, 0)
                    os.write(fd, str(os.getpid()).encode("ascii"))
                    os.fsync(fd)
                except OSError:
                    pass
                return self
            if time.monotonic() >= deadline:
                os.close(fd)
                raise LockTimeout(
                    f"could not acquire lock {self.path} within {self.timeout}s"
                )
            time.sleep(self.poll_interval)

    def release(self) -> None:
        fd = self._fd
        if fd is None:
            return
        try:
            if _POSIX:
                fcntl.flock(fd, fcntl.LOCK_UN)
            else:  # pragma: no cover - platform-specific
                os.lseek(fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            self._fd = None

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, *exc: object) -> None:
        self.release()


def atomic_write_bytes(path: PathLike, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically (temp file in the same dir + rename).

    ``os.replace`` is atomic on both POSIX and Windows when source and target are
    on the same filesystem, so a reader never sees a half-written file.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def atomic_write_text(path: PathLike, text: str, encoding: str = "utf-8") -> None:
    """Text convenience wrapper around :func:`atomic_write_bytes`."""
    atomic_write_bytes(path, text.encode(encoding))
