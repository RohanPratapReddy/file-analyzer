"""
Filesystem snapshot + change detection for the repository monitor.

:class:`Scanner` walks a repository root and produces a *snapshot*: a mapping of
``rel_path -> entry`` where each entry carries the file's ``size``, ``mtime``,
content ``hash`` and (for small text files) a cached copy of its text so a real
unified diff can be computed the next time it changes.

:meth:`Scanner.diff` compares two snapshots and returns a list of change-event
dicts (``created`` / ``modified`` / ``deleted``) shaped for
:meth:`ChangeDiffDatabase.record_events`, with ``lines_added`` / ``lines_removed``
and a bounded unified-diff snippet filled in for text files. Changes made by an
agent, the user, or any third-party tool are all detected identically -- the
scanner only looks at the bytes on disk.

Everything here is standard library (``os``, ``hashlib``, ``difflib``,
``fnmatch``), so it imports cheaply and runs on a bare interpreter.
"""

from __future__ import annotations

import difflib
import fnmatch
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# Directories never worth watching (VCS internals, caches, virtualenvs, build
# output). Matched by exact directory name at any depth.
DEFAULT_IGNORE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        ".idea",
        ".vscode",
        ".file-analyzer",  # the monitor's own artifact dir
    }
)

# File name globs never worth watching.
DEFAULT_IGNORE_GLOBS = frozenset(
    {
        "*.pyc",
        "*.pyo",
        "*.swp",
        "*.tmp",
        "*~",
        ".DS_Store",
        "*.sqlite-wal",
        "*.sqlite-shm",
        "*.db-wal",
        "*.db-shm",
    }
)

# A file larger than this is fingerprinted by (size, mtime) only; its bytes are
# not hashed and its text is not cached (keeps the scan cheap and bounded).
DEFAULT_MAX_HASH_BYTES = 8 * 1024 * 1024
# A text file larger than this is not cached for line-level diffing.
DEFAULT_CACHE_TEXT_BYTES = 1 * 1024 * 1024
# Cap on the unified-diff snippet stored per change event.
DEFAULT_DIFF_SNIPPET_CHARS = 4000


def _looks_binary(chunk: bytes) -> bool:
    if b"\x00" in chunk:
        return True
    try:
        chunk.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


class Scanner:
    def __init__(
        self,
        root: os.PathLike,
        ignore_dirs: Optional[set] = None,
        ignore_globs: Optional[set] = None,
        extra_ignore_paths: Optional[List[os.PathLike]] = None,
        max_hash_bytes: int = DEFAULT_MAX_HASH_BYTES,
        cache_text_bytes: int = DEFAULT_CACHE_TEXT_BYTES,
        diff_snippet_chars: int = DEFAULT_DIFF_SNIPPET_CHARS,
        follow_symlinks: bool = False,
    ):
        self.root = Path(root).resolve()
        self.ignore_dirs = set(ignore_dirs or DEFAULT_IGNORE_DIRS)
        self.ignore_globs = set(ignore_globs or DEFAULT_IGNORE_GLOBS)
        # Absolute paths (files or dirs) never to watch -- e.g. the diff DB and
        # the analysis temp/out dir, so the monitor never reacts to its own writes.
        self.extra_ignore_paths = [
            Path(p).resolve() for p in (extra_ignore_paths or [])
        ]
        self.max_hash_bytes = int(max_hash_bytes)
        self.cache_text_bytes = int(cache_text_bytes)
        self.diff_snippet_chars = int(diff_snippet_chars)
        self.follow_symlinks = follow_symlinks

    # ------------------------------------------------------------------
    def _is_ignored_path(self, abs_path: Path) -> bool:
        for ig in self.extra_ignore_paths:
            try:
                if abs_path == ig or ig in abs_path.parents:
                    return True
            except OSError:
                continue
        return False

    def _is_ignored_name(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name, g) for g in self.ignore_globs)

    def _read_entry(self, abs_path: Path, rel_path: str) -> Optional[Dict[str, Any]]:
        try:
            st = abs_path.stat()
        except OSError:
            return None
        size = st.st_size
        mtime = st.st_mtime
        entry: Dict[str, Any] = {
            "size": size,
            "mtime": mtime,
            "hash": None,
            "is_binary": False,
            "text": None,
        }
        if size > self.max_hash_bytes:
            # Too big to hash every scan: fingerprint by (size, mtime) only.
            entry["hash"] = f"sig:{size}:{mtime:.6f}"
            entry["is_binary"] = True
            return entry
        try:
            data = abs_path.read_bytes()
        except OSError:
            return None
        entry["hash"] = hashlib.sha256(data).hexdigest()
        is_bin = _looks_binary(data[:8192])
        entry["is_binary"] = is_bin
        if not is_bin and size <= self.cache_text_bytes:
            try:
                entry["text"] = data.decode("utf-8")
            except UnicodeDecodeError:
                entry["text"] = None
        return entry

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        """Walk the tree and return ``{rel_path: entry}`` for every watched file."""
        out: Dict[str, Dict[str, Any]] = {}
        root = self.root
        for dirpath, dirnames, filenames in os.walk(
            root, followlinks=self.follow_symlinks
        ):
            dpath = Path(dirpath)
            # Prune ignored / self-owned directories in place (os.walk honours this).
            dirnames[:] = [
                d
                for d in dirnames
                if d not in self.ignore_dirs and not self._is_ignored_path(dpath / d)
            ]
            for fn in filenames:
                if self._is_ignored_name(fn):
                    continue
                abs_path = dpath / fn
                if self._is_ignored_path(abs_path):
                    continue
                if not self.follow_symlinks and abs_path.is_symlink():
                    continue
                entry = self._read_entry(abs_path, "")
                if entry is None:
                    continue
                rel = abs_path.relative_to(root).as_posix()
                out[rel] = entry
        return out

    def refresh_entry(self, rel_path: str) -> Optional[Dict[str, Any]]:
        """Re-read a single file's entry (used to confirm a detected change)."""
        return self._read_entry(self.root / rel_path, rel_path)

    # ------------------------------------------------------------------
    def _unified(
        self, old_text: Optional[str], new_text: Optional[str], rel_path: str
    ) -> "tuple[int, int, Optional[str]]":
        """Return (lines_added, lines_removed, snippet) for a text change."""
        if old_text is None and new_text is None:
            return 0, 0, None
        old_lines = (old_text or "").splitlines(keepends=True)
        new_lines = (new_text or "").splitlines(keepends=True)
        added = removed = 0
        pieces: List[str] = []
        for line in difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
            lineterm="",
        ):
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1
            pieces.append(line if line.endswith("\n") else line + "\n")
        snippet = "".join(pieces)
        if len(snippet) > self.diff_snippet_chars:
            snippet = snippet[: self.diff_snippet_chars] + "\n... (diff truncated)\n"
        return added, removed, (snippet or None)

    def diff(
        self,
        old: Dict[str, Dict[str, Any]],
        new: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Compare two snapshots -> list of change-event dicts (created/modified/deleted).

        Event dicts are shaped for :meth:`ChangeDiffDatabase.record_events`. The
        expensive analyzer re-run and ``analyzer_class`` routing are done later by
        the update engine; this only computes byte/line-level facts.
        """
        events: List[Dict[str, Any]] = []
        old_keys = set(old)
        new_keys = set(new)

        for rel in sorted(new_keys - old_keys):  # created
            e = new[rel]
            added, removed, snippet = self._unified(None, e.get("text"), rel)
            events.append(
                {
                    "rel_path": rel,
                    "abs_path": str(self.root / rel),
                    "change_type": "created",
                    "old_hash": None,
                    "new_hash": e.get("hash"),
                    "old_size": None,
                    "new_size": e.get("size"),
                    "is_binary": e.get("is_binary"),
                    "lines_added": added,
                    "lines_removed": removed,
                    "diff_snippet": snippet,
                }
            )

        for rel in sorted(old_keys - new_keys):  # deleted
            e = old[rel]
            events.append(
                {
                    "rel_path": rel,
                    "abs_path": str(self.root / rel),
                    "change_type": "deleted",
                    "old_hash": e.get("hash"),
                    "new_hash": None,
                    "old_size": e.get("size"),
                    "new_size": None,
                    "is_binary": e.get("is_binary"),
                    "lines_added": 0,
                    "lines_removed": len((e.get("text") or "").splitlines()),
                    "diff_snippet": None,
                }
            )

        for rel in sorted(old_keys & new_keys):  # possibly modified
            oe, ne = old[rel], new[rel]
            if oe.get("hash") == ne.get("hash"):
                continue  # unchanged
            added, removed, snippet = self._unified(oe.get("text"), ne.get("text"), rel)
            events.append(
                {
                    "rel_path": rel,
                    "abs_path": str(self.root / rel),
                    "change_type": "modified",
                    "old_hash": oe.get("hash"),
                    "new_hash": ne.get("hash"),
                    "old_size": oe.get("size"),
                    "new_size": ne.get("size"),
                    "is_binary": ne.get("is_binary") or oe.get("is_binary"),
                    "lines_added": added,
                    "lines_removed": removed,
                    "diff_snippet": snippet,
                }
            )

        return events
