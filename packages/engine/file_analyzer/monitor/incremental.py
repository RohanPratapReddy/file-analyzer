"""
Incremental per-file re-analysis for the repository monitor.

When the scanner reports that a file was created or modified, the *update engine*
re-runs the correct analyzer over just that one file and returns a compact
summary (which analyzer claimed it, how many rows each of its tables produced).
This is the "update module for RepositoryAnalyzer / the Analyzer classes / the
Parser classes" -- it reuses the exact same engine contract the router's
per-shard worker uses (``engine_cls(file_paths=[path], dump_file_type="memory")``
then ``.analyze()``), so no analysis logic is duplicated or stubbed.

Routing is done by :func:`file_analyzer.router.routing.resolve_analyzer`, the same function
the full pipeline uses, so a file is always handed to the identical analyzer it
would get in a full run. Classes that are not driven by the file-list engine
contract (``archive`` -> extract-and-recurse, ``binary`` -> deep struct parse,
and unrouted files) are recorded honestly with ``status="skipped"`` rather than
being force-fit through an incompatible constructor.

Heavy analyzer imports happen lazily inside :meth:`_engines`, so importing this
module is cheap and does not pull in the fleet until a file is actually analyzed.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# Analyzer classes that accept ``file_paths=[...]`` + ``.analyze()`` (mirrors
# file_analyzer/router/worker.py). archive / binary are intentionally absent -- they have
# different constructors and dedicated post-planes stages.
_FILE_ENGINE_CLASSES = (
    "code",
    "schema",
    "database",
    "data",
    "config",
    "text",
    "markup",
    "document",
    "document_parser",
    "misc",
)

_ENGINES_CACHE: Optional[Dict[str, Any]] = None


def _engines(readers_root: Optional[str] = None) -> Dict[str, Any]:
    """Lazily import and cache the {analyzer_class -> engine class} map."""
    global _ENGINES_CACHE
    if _ENGINES_CACHE is not None:
        return _ENGINES_CACHE
    if readers_root:
        root = str(Path(readers_root).resolve())
        if root not in sys.path:
            sys.path.insert(0, root)
    from file_analyzer.engine import (  # noqa: E402  (heavy fleet import, deferred to first use)
        ConfigAnalyzer,
        DataAnalyzer,
        DatabaseAnalyzer,
        DocumentAnalyzer,
        DocumentParser,
        MarkupAnalyzer,
        MiscAnalyzer,
        PolyglotCodeAnalyzer,
        SchemaAnalyzer,
        TextualAnalyzer,
    )

    _ENGINES_CACHE = {
        "code": PolyglotCodeAnalyzer,
        "schema": SchemaAnalyzer,
        "database": DatabaseAnalyzer,
        "data": DataAnalyzer,
        "config": ConfigAnalyzer,
        "text": TextualAnalyzer,
        "markup": MarkupAnalyzer,
        "document": DocumentAnalyzer,
        "document_parser": DocumentParser,
        "misc": MiscAnalyzer,
    }
    return _ENGINES_CACHE


def _summarize_tables(tables: Any) -> Dict[str, Any]:
    """Reduce an engine's in-memory tables to per-table row counts + a total."""
    per_table: Dict[str, int] = {}
    total = 0
    if isinstance(tables, dict):
        for name, rows in tables.items():
            try:
                n = len(rows)
            except TypeError:
                n = 0
            per_table[str(name)] = n
            total += n
    return {"tables": per_table, "total_rows": total, "table_count": len(per_table)}


class IncrementalUpdateEngine:
    """Re-analyze individual changed files, one at a time, on demand.

    A file is always first re-run through its deterministic analyzer (the same
    engine contract the full pipeline uses). When ``enable_agents`` is set, the
    re-analyzed file is *additionally* handed to the soft MCP agent tier
    (:class:`file_analyzer.core.mcp_enrichment.McpEnrichmentEngine`) -- the very same
    agent layer a full run uses -- so a live MCP provider enriches the change
    with a summary, quality/security findings and symbol docs. The agent tier is
    strictly additive: if no provider is reachable it degrades to a no-op and the
    deterministic result stands unchanged, so the toggle is a real capability
    rather than a stub.
    """

    def __init__(
        self,
        readers_root: Optional[str] = None,
        *,
        enable_agents: bool = False,
        agents_include: Optional[List[str]] = None,
        agents_exclude: Optional[List[str]] = None,
        discover_agents: bool = True,
        agent_roster: Optional[str] = None,
        project_dir: Optional[str] = None,
        max_agent_files: int = 40,
    ):
        self.readers_root = readers_root
        self.enable_agents = enable_agents
        self.agents_include = list(agents_include) if agents_include else None
        self.agents_exclude = list(agents_exclude) if agents_exclude else None
        self.discover_agents = discover_agents
        self.agent_roster = agent_roster
        self.project_dir = project_dir
        self.max_agent_files = max_agent_files
        # Resolve the registry once and cache it (None until first use / when the
        # agent tier is off).
        self._registry: Optional[Any] = None
        self._registry_resolved = False

    def resolve_class(self, path: str) -> Optional[str]:
        from file_analyzer.router.routing import resolve_analyzer

        return resolve_analyzer(path)

    def analyze_file(self, abs_path: str) -> Dict[str, Any]:
        """Re-run the appropriate analyzer over one file. Never raises.

        Returns a dict with: ``path``, ``analyzer_class``, ``status``
        (reanalyzed | skipped | error | missing), and either ``summary`` (row
        counts) or ``error`` (traceback string). When the agent tier is enabled
        and the file was re-analyzed, ``summary["agent"]`` carries the soft
        agent-tier outcome.
        """
        p = Path(abs_path)
        cls = self.resolve_class(abs_path)
        result: Dict[str, Any] = {"path": str(p), "analyzer_class": cls}
        if not p.is_file():
            result["status"] = "missing"
            return result
        if cls is None or cls not in _FILE_ENGINE_CLASSES:
            result["status"] = "skipped"
            result["reason"] = (
                "unrouted" if cls is None else f"{cls} has no file-list engine"
            )
            return result
        try:
            engine_cls = _engines(self.readers_root)[cls]
            engine = engine_cls(file_paths=[str(p)], dump_file_type="memory")
            tables = engine.analyze()
            result["status"] = "reanalyzed"
            summary = _summarize_tables(tables)
            if self.enable_agents:
                summary["agent"] = self._run_agent_tier(str(p), cls, tables)
            result["summary"] = summary
        except Exception:
            result["status"] = "error"
            result["error"] = traceback.format_exc()
        return result

    def analyze_many(self, abs_paths: List[str]) -> List[Dict[str, Any]]:
        return [self.analyze_file(p) for p in abs_paths]

    # ------------------------------------------------------------------
    # Soft agent tier
    # ------------------------------------------------------------------
    def _resolve_registry(self) -> Optional[Any]:
        """Discover + narrow the MCP agent registry once (cached). Soft.

        Mirrors ``AnalysisEngine._resolve_agent_registry``: when ``discover_agents``
        is set the desktop/CLI-configured MCP servers are discovered, then the
        registry is narrowed by include/exclude. Any failure degrades to ``None``
        so the agent tier simply becomes a no-op.
        """
        if self._registry_resolved:
            return self._registry
        self._registry_resolved = True
        registry: Optional[Any] = None
        try:
            from file_analyzer.document.agent_mcp import AgentRegistry

            if self.discover_agents:
                registry = AgentRegistry.from_desktop(project_dir=self.project_dir)
            else:
                registry = AgentRegistry(discover=False, project_dir=self.project_dir)
            if (self.agents_include or self.agents_exclude) and hasattr(
                registry, "select"
            ):
                registry = registry.select(self.agents_include, self.agents_exclude)
        except Exception:
            registry = None
        self._registry = registry
        return registry

    def _run_agent_tier(
        self, abs_path: str, cls: Optional[str], tables: Any
    ) -> Dict[str, Any]:
        """Enrich one re-analyzed file via the soft MCP agent tier. Never raises.

        Returns a compact outcome dict: whether a provider was reachable and how
        many agent-derived rows (summaries, findings, symbol docs) it produced.
        When nothing is reachable this reports ``invoked: False`` and leaves the
        deterministic result untouched.
        """
        outcome: Dict[str, Any] = {
            "requested": True,
            "invoked": False,
            "agent_calls": 0,
        }
        try:
            from file_analyzer.core.mcp_enrichment import McpEnrichmentEngine

            mapping = [{"file_location": abs_path, "file_id": 1, "analyzer_class": cls}]
            # Feed the deterministic code tables so symbol-doc + undocumented
            # symbol enrichment reaches the agent prompt, exactly as a full run.
            code_tables = (
                tables if (cls == "code" and isinstance(tables, dict)) else None
            )
            eng = McpEnrichmentEngine(
                mapping,
                repository_files=[{"file_id": 1, "file_name": Path(abs_path).name}],
                code_tables=code_tables,
                registry=self._resolve_registry(),
                roster=self.agent_roster,
                agents_include=self.agents_include,
                agents_exclude=self.agents_exclude,
                enable_agent=True,
                project_dir=self.project_dir,
                max_agent_files=self.max_agent_files,
            ).analyze()
        except Exception:
            outcome["error"] = "agent tier failed"
            return outcome

        calls = eng.agent_calls
        providers = sorted({str(c.get("provider")) for c in calls if c.get("provider")})
        outcome.update(
            {
                "invoked": bool(calls),
                "agent_calls": len(calls),
                "providers": providers,
                "summaries": len(eng.summaries),
                "quality_findings": len(eng.quality_findings),
                "security_flags": len(eng.security_flags),
                "symbol_docs": len(eng.symbol_docs),
            }
        )
        return outcome
