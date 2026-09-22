"""Orchestration glue for the analysis pipeline (the ``core`` subpackage).

These four modules tie the per-domain analyzers together:

    repository_analyzer  the repository census (folders / extensions / files)
    import_linkage       cross-file import + symbol linkage
    db_generator         RepositoryDatabaseGenerator (.sql dump + .db build)
    analysis_engine      AnalysisEngine: census -> router planes -> DB + views

The package top level (``file_analyzer/__init__.py``) re-exports the public classes, so
``from file_analyzer import AnalysisEngine`` keeps working exactly as before this move.
"""

from .analysis_engine import AnalysisEngine
from .db_generator import RepositoryDatabaseGenerator
from .import_linkage import ImportLinkageAnalyzer
from .repository_analyzer import RepositoryAnalyzer

__all__ = [
    "RepositoryAnalyzer",
    "ImportLinkageAnalyzer",
    "RepositoryDatabaseGenerator",
    "AnalysisEngine",
]
