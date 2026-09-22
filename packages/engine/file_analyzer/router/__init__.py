"""
tabgen routing package.

Routes every repository file to its analyzer engine and drives per-shard analysis
across the concurrent Go plane (with a Python fallback). The routing decision and
staging are pure Python (``routing``); the per-shard analysis unit is ``worker``
(invoked as a subprocess by the plane); ``planes`` orchestrates the Go plane.
"""

from .planes import PlaneError, RouterPlanes
from .routing import (
    ANALYZER_CLASSES,
    build_mapping,
    group_into_shards,
    reconstruct_paths,
    resolve_analyzer,
)

__all__ = [
    "ANALYZER_CLASSES",
    "resolve_analyzer",
    "reconstruct_paths",
    "build_mapping",
    "group_into_shards",
    "RouterPlanes",
    "PlaneError",
]
