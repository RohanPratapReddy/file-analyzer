"""
tabgen routing package.

Routes every repository file to its analyzer engine and drives per-shard analysis
across two concurrent language planes (Go + Java, with a Python fallback). The
routing decision and staging are pure Python (``routing``); the per-shard analysis
unit is ``worker`` (invoked as a subprocess by each plane); ``planes`` orchestrates
the two planes.
"""

from .routing import (
    ANALYZER_CLASSES,
    resolve_analyzer,
    reconstruct_paths,
    build_mapping,
    group_into_shards,
)
from .planes import RouterPlanes, PlaneError

__all__ = [
    "ANALYZER_CLASSES",
    "resolve_analyzer",
    "reconstruct_paths",
    "build_mapping",
    "group_into_shards",
    "RouterPlanes",
    "PlaneError",
]
