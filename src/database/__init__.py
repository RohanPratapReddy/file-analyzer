"""Database-store analysis sub-package.

Exposes :class:`DatabaseAnalyzer`, which turns on-disk database *files* into
normalized ``database_*`` tables that merge schema structure (tables/columns/
types/keys/relations/indexes) with a data profile (row/null/distinct/min/max/
samples) where the store is readable, and degrades to an honest forensic byte
profile otherwise.
"""

from .database_analyzer import DatabaseAnalyzer

__all__ = ["DatabaseAnalyzer"]
