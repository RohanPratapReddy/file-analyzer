"""
Concurrent SQLite injector: drive the Go bulk loader, with a Python fallback.

:class:`~file_analyzer.core.db_generator.RepositoryDatabaseGenerator` builds the
table *structure* once and then must inject the generated ``INSERT`` section into
the ``.db``. That section is partitioned into independent per-table blocks (see
``_split_inserts_into_blocks``); this module injects those blocks concurrently.

It mirrors :mod:`file_analyzer.views.native_reader` (the reads counterpart) and
the router/monitor planes:

* the fast path is a **Go injector** (``file_analyzer/core/go/injector.go``): a
  goroutine pool applies one block per connection, built on demand with
  ``go build`` and simply skipped when the Go toolchain is not on ``PATH``;
* the fallback is an **in-process thread pool** (``ThreadPoolExecutor``) that
  opens one ``sqlite3`` connection per block and applies it, so the load runs on
  a bare interpreter with no toolchain.

Both paths are equivalent: every block targets a distinct table and is applied in
its own transaction, so concurrent writers never conflict; SQLite (WAL +
``busy_timeout``) serializes the physical page writes. On any block failure the
whole injection is reported as failed (the caller raises), because a partial load
is not a valid database.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# file_analyzer/core/inject_pool.py -> parents[1] == the file_analyzer package dir.
_GO_DIR = Path(__file__).resolve().parent / "go"


# ---------------------------------------------------------------------------
# In-process fallback (pure stdlib) -- one connection per block.
# ---------------------------------------------------------------------------
def _inject_block_python(db_path: str, sql_text: str) -> Optional[str]:
    """Apply one block on its own connection; return an error string or None."""
    c = sqlite3.connect(db_path, timeout=60.0)
    try:
        # busy_timeout FIRST: in WAL only one writer runs at a time, so concurrent
        # block writers must *wait* for the lock rather than fail fast -- without
        # this the second writer raises "database is locked" immediately.
        c.execute("PRAGMA busy_timeout = 60000")
        c.execute("PRAGMA synchronous = OFF")
        c.execute("PRAGMA foreign_keys = OFF")
        c.execute("BEGIN IMMEDIATE")
        c.executescript(sql_text)
        c.commit()
        return None
    except Exception as err:  # surface, do not swallow
        try:
            c.rollback()
        except Exception:
            pass
        return f"{type(err).__name__}: {err}"
    finally:
        c.close()


def _ensure_wal(db_path: str) -> None:
    """Put the database in WAL mode once, before any concurrent writers start.

    WAL is a *persistent* database property, so setting it here (on a single
    connection with no contention) means the worker connections never race to
    change the journal mode -- a concurrent ``PRAGMA journal_mode=WAL`` is exactly
    what can raise "database is locked" during startup. In the real pipeline the
    structure-build step already sets WAL; this makes the fallback self-sufficient.
    """
    c = sqlite3.connect(db_path, timeout=60.0)
    try:
        c.execute("PRAGMA busy_timeout = 60000")
        c.execute("PRAGMA journal_mode = WAL")
        c.commit()
    finally:
        c.close()


def inject_blocks_python(
    db_path: str, blocks: List[Tuple[str, str]], workers: int
) -> List[Tuple[str, str]]:
    """Inject every ``(label, sql_text)`` block across a thread pool.

    Returns the list of ``(label, error)`` failures (empty on success).
    """
    failures: List[Tuple[str, str]] = []
    if not blocks:
        return failures
    _ensure_wal(db_path)
    pool = max(1, min(workers, len(blocks)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=pool) as ex:
        futs = {
            ex.submit(_inject_block_python, db_path, sql_text): label
            for label, sql_text in blocks
        }
        for fut in concurrent.futures.as_completed(futs):
            label = futs[fut]
            err = fut.result()
            if err is not None:
                failures.append((label, err))
    return failures


# ---------------------------------------------------------------------------
# Go toolchain build (on demand) -- mirrors file_analyzer/views/native_reader.py
# ---------------------------------------------------------------------------
def _go_binary(log: List[str]) -> Optional[Path]:
    if shutil.which("go") is None:
        return None
    exe = _GO_DIR / ("repo-injector.exe" if os.name == "nt" else "repo-injector")
    try:
        proc = subprocess.run(
            ["go", "build", "-o", exe.name, "."],
            cwd=_GO_DIR,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            log.append(f"[inject] go build failed:\n{proc.stderr}")
            return None
        return exe
    except OSError as err:
        log.append(f"[inject] go build error: {err}")
        return None


def _stage_blocks(blocks: List[Tuple[str, str]], stage_dir: Path) -> List[Dict]:
    """Write each block to ``block_<id>.sql`` + a manifest; return the manifest."""
    stage_dir.mkdir(parents=True, exist_ok=True)
    entries: List[Dict] = []
    for i, (label, sql_text) in enumerate(blocks):
        fname = f"block_{i}.sql"
        (stage_dir / fname).write_text(sql_text, encoding="utf-8")
        entries.append({"id": i, "label": label, "file": fname})
    (stage_dir / "manifest.json").write_text(
        json.dumps({"blocks": entries}), encoding="utf-8"
    )
    return entries


def _run_go(
    exe: Path, db_path: str, stage_dir: Path, workers: int, log: List[str]
) -> Optional[Dict]:
    """Run the Go injector in -json mode; return its parsed summary or None."""
    cmd = [
        str(exe),
        "-db",
        db_path,
        "-blocks-dir",
        str(stage_dir),
        "-workers",
        str(workers),
        "-json",
    ]
    try:
        proc = subprocess.run(cmd, cwd=_GO_DIR, capture_output=True, text=True)
    except OSError as err:
        log.append(f"[inject] go injector launch error: {err}")
        return None
    if proc.stderr.strip():
        log.append(proc.stderr.strip())
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        log.append(
            f"[inject] go injector produced non-JSON stdout (exit {proc.returncode})"
        )
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def inject_blocks(
    db_path: str,
    blocks: List[Tuple[str, str]],
    workers: Optional[int] = None,
    use_go: bool = True,
) -> Dict:
    """Inject every per-table block into ``db_path`` concurrently.

    Prefers the Go injector (built on demand). The pure-Python thread pool is the
    fallback taken **only when Go never touched the database** -- i.e. the
    toolchain is unavailable or the binary could not be built. Once the Go
    injector has run against the file, its result stands (re-running the blocks in
    Python would double-insert the ones Go already committed), so the returned
    ``failures`` reflect exactly what Go reported. Returns
    ``{"engine", "workers", "blocks", "failures": [(label, error), ...], "log"}``.
    """
    workers = workers or max(1, (os.cpu_count() or 2))
    log: List[str] = []
    if not blocks:
        return {
            "engine": "none",
            "workers": 0,
            "blocks": 0,
            "failures": [],
            "log": log,
        }

    exe = _go_binary(log) if use_go else None
    if exe is not None:
        with tempfile.TemporaryDirectory(prefix="fa-inject-") as tmpd:
            stage = Path(tmpd) / f"blocks_{int(time.time() * 1000)}"
            _stage_blocks(blocks, stage)
            summary = _run_go(exe, db_path, stage, workers, log)
        # Go ran against the db -> its result is authoritative. Never re-run the
        # blocks in Python afterwards (that would duplicate committed rows).
        if summary is not None:
            failures = [
                (label, msg) for label, msg in (summary.get("failures") or {}).items()
            ]
            injected = int(summary.get("injected", 0))
            if not failures and injected != len(blocks):
                # No per-block error but not everything landed: treat the shortfall
                # as a failure so the caller raises rather than shipping a partial db.
                failures.append(
                    (
                        "<go-injector>",
                        f"only {injected}/{len(blocks)} blocks accounted for",
                    )
                )
            return {
                "engine": "go",
                "workers": workers,
                "blocks": len(blocks),
                "failures": failures,
                "log": log,
            }
        # summary is None: the binary launched but its output was unparseable, so
        # its effect on the db is indeterminate. Surface it as a failure instead of
        # risking a double-insert with a Python re-run.
        return {
            "engine": "go",
            "workers": workers,
            "blocks": len(blocks),
            "failures": [("<go-injector>", "unparseable injector output")],
            "log": log,
        }

    failures = inject_blocks_python(db_path, blocks, workers)
    return {
        "engine": "python",
        "workers": workers,
        "blocks": len(blocks),
        "failures": failures,
        "log": log,
    }
