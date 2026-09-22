"""
Optional local-analysis bridge for the client wheel.

The client wheel (``file-analyzer-client``) is deliberately tiny: connect to a
hosted server, and read/query a local ``.db`` offline. Running an analysis
*locally* is an optional capability that needs the analyzer fleet, which ships in
the separate engine wheel (``file-analyzer-engine``). Rather than depend on that
heavy wheel, the client detects it at runtime: if it is installed, local analysis
is enabled; if not, :func:`analyze` raises a clear, actionable error instead of a
bare ``ImportError``.

This keeps the default client install free of the engine's bloat while letting a
user opt in simply by ``pip install file-analyzer-engine`` alongside the client.
"""

from __future__ import annotations

import importlib
import importlib.util
from typing import Any

__all__ = ["has_engine", "analyze", "EngineNotInstalled"]

#: The engine wheel's public-API package (created by ``file-analyzer-engine``).
_ENGINE_MODULE = "file_analyzer.engine"

_INSTALL_HINT = (
    "local analysis needs the analyzer engine, which is not installed. "
    "Install it with:\n\n    pip install file-analyzer-engine\n\n"
    "(the client wheel stays small by not bundling the engine; the client can "
    "still connect to a hosted server and read a local .db without it)."
)


class EngineNotInstalled(RuntimeError):
    """Raised when a local-analysis call is made without the engine wheel."""


def has_engine() -> bool:
    """Return ``True`` when the analyzer engine wheel is importable.

    Uses :func:`importlib.util.find_spec` so it does not actually import the
    (heavy) engine merely to answer the question.
    """
    try:
        return importlib.util.find_spec(_ENGINE_MODULE) is not None
    except (ImportError, ValueError):  # pragma: no cover - env-dependent
        return False


def _load_engine() -> Any:
    """Import and return the engine's public-API module, or raise a helpful error."""
    if not has_engine():
        raise EngineNotInstalled(_INSTALL_HINT)
    try:
        return importlib.import_module(_ENGINE_MODULE)
    except ImportError as exc:  # pragma: no cover - env-dependent
        raise EngineNotInstalled(_INSTALL_HINT) from exc


def analyze(path: Any = ".", **kwargs: Any) -> Any:
    """Analyze a repository *locally*, if the engine wheel is installed.

    This is the optional local-analysis path: it delegates to the engine's
    ``analyze`` one-shot helper (``file_analyzer.engine.analyze``) and returns its
    ``AnalysisResult``. When the engine wheel is absent it raises
    :class:`EngineNotInstalled` with install instructions rather than failing with
    an opaque import error.
    """
    engine = _load_engine()
    return engine.analyze(path, **kwargs)
