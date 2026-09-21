"""
Dispatch layer for the ``document`` analysis plane.

Maps a file extension to its real, structure-aware child parser (see
:mod:`.parsers`), reads the payload with the shared byte helpers, and returns a
``profile`` dict in the exact canonical shape the DocumentAnalyzer flattens
(document -> sections -> records -> fields + file-level properties). This module
owns the plane's *extension universe* (``known_exts`` / ``routing_suffixes``);
the router derives the ``document`` route set from it after subtracting every
higher-priority plane.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

from ..text import textual_formats as tf
from . import parsers as _p

_REGISTRY: Dict[str, _p.DocumentTypeParser] = _p.build_registry()


def known_exts() -> frozenset:
    """Every extension the document plane owns (lower-case, dot-prefixed)."""
    return frozenset(_REGISTRY)


def routing_suffixes() -> Tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def analyze(path: str, ext: str) -> Dict[str, Any]:
    """Parse one document file and return its normalized profile dict."""
    e = ext.lower()
    parser = _REGISTRY.get(e)
    p = Path(path)
    fam, label = parser.meta(e) if parser else ("document", e.lstrip("."))
    kind = parser.KIND if parser else "document"
    if parser is None:  # never routed here, but stay honest
        return tf._empty(kind, fam, label, 0)

    data, truncated = tf._read_bytes(p)
    if not data:
        return tf._empty(kind, fam, label, 0)

    text, encoding = tf._decode(data)
    line_count = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    try:
        profile = parser.parse(p, data, text, e, encoding, line_count)
    except Exception as exc:  # honest partial, never a fabricated table
        profile = tf._forensic(
            kind,
            fam,
            label,
            data,
            len(data),
            f"{label}: parser raised {type(exc).__name__}: {exc}",
        )
    if truncated:
        profile.setdefault("notes", "")
        profile["properties"] = list(profile.get("properties", [])) + [
            ("file", "truncated", "payload exceeded read budget")
        ]
    return profile


def parser_for(ext: str):
    return _REGISTRY.get(ext.lower())
