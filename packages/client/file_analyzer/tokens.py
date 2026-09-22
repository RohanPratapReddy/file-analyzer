"""
Session-token minting and repository identity -- standard library only.

The database-hosting server identifies a *repo-session* by a stable fingerprint
of the repository's absolute path, and issues a cryptographically strong
**session token** that a client presents to connect. Token reuse across parallel
servers (so the same repo-session never gets two token namespaces) is handled one
layer up in :mod:`file_analyzer.server.catalog`; this module only mints tokens and
derives the deterministic identity pieces.

Design notes grounded in the ``secrets`` guidance:

* tokens come from :func:`secrets.token_urlsafe`, which returns a URL-safe
  base64 string from ``os.urandom`` -- the recommended way to make session
  tokens in modern Python (never ``random``);
* the repository *fingerprint* is a short, stable SHA-256 slice of the canonical
  (resolved, case-folded on case-insensitive platforms) absolute path, so two
  processes referring to the same directory by different spellings still land on
  the same session;
* the *slug* is a human-readable, filesystem-safe rendering of the project root
  (its basename plus a short fingerprint) -- this is the ``PROJECT_ROOT`` piece of
  the ``PROJECT_ROOT-{session-token}-{db_name}`` storage-naming convention.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from pathlib import Path
from typing import Union

PathLike = Union[str, "os.PathLike[str]"]

#: Number of random bytes behind a session token (token_urlsafe emits ~1.3 chars
#: per byte, so 24 bytes -> a 32-character URL-safe token, ~192 bits of entropy).
DEFAULT_TOKEN_BYTES = 24

_SLUG_STRIP = re.compile(r"[^A-Za-z0-9._-]+")
_SLUG_COLLAPSE = re.compile(r"-{2,}")


def canonical_root(root: PathLike) -> str:
    """Return the canonical absolute path used to identify a repository.

    Resolves symlinks and ``..`` segments. On case-insensitive filesystems
    (Windows, default macOS) the path is case-folded so ``C:\\Repo`` and
    ``c:\\repo`` fingerprint identically; POSIX paths are left case-sensitive.
    """
    resolved = str(Path(root).resolve())
    if os.name != "posix":
        return resolved.casefold()
    return resolved


def project_fingerprint(root: PathLike, length: int = 12) -> str:
    """A short, stable hex fingerprint of the repository's canonical path."""
    digest = hashlib.sha256(canonical_root(root).encode("utf-8")).hexdigest()
    return digest[: max(4, length)]


def _sanitize(text: str, fallback: str = "x") -> str:
    cleaned = _SLUG_STRIP.sub("-", text).strip("-._")
    cleaned = _SLUG_COLLAPSE.sub("-", cleaned)
    return cleaned or fallback


def project_slug(root: PathLike) -> str:
    """A filesystem-safe, human-readable id for the project root.

    Combines the directory's basename with a short fingerprint so that two
    same-named directories in different locations never collide::

        /home/alice/file-analyzer  ->  file-analyzer-1a2b3c4d
    """
    p = Path(root)
    base = _sanitize(p.name or p.anchor or "repo", fallback="repo")
    return f"{base}-{project_fingerprint(root, 8)}"


def sanitize_db_name(db_name: str) -> str:
    """Normalize a logical database name into a storage-safe token."""
    return _sanitize(str(db_name), fallback="db")


def new_session_token(nbytes: int = DEFAULT_TOKEN_BYTES) -> str:
    """Mint a fresh, cryptographically strong URL-safe session token."""
    return secrets.token_urlsafe(max(16, int(nbytes)))


def new_server_id(nbytes: int = 8) -> str:
    """Mint a short unique id for one running server instance."""
    return secrets.token_hex(max(4, int(nbytes)))
