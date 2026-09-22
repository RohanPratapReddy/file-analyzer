"""Document analysis plane.

Covers the eight residual *document* content kinds (manifest, query, makefile,
certificate_text, notebook, document, license, diff) with a parent
:class:`DocumentAnalyzer` super-class dispatching each file to its own
per-type child parser class (see :mod:`.parsers`), each stitched to its own
extension set, normalizing every file into
``document -> sections -> records -> fields`` tables.
"""

from . import document_formats, evaluation_metrics, parsers
from .agent_mcp import (
    AgentConnector,
    AgentRegistry,
    default_provider_specs,
    discover_mcp_servers,
)
from .document_analyzer import DocumentAnalyzer
from .document_db import DocumentParserDatabaseGenerator
from .document_parser import DocumentParser
from .dynamic_engine import DynamicAnalysisEngine, FieldSpec
from .evaluation_engine import EvalCase, EvaluationEngine

__all__ = [
    "DocumentAnalyzer",
    "DocumentParser",
    "DocumentParserDatabaseGenerator",
    "DynamicAnalysisEngine",
    "FieldSpec",
    "EvaluationEngine",
    "EvalCase",
    "evaluation_metrics",
    "AgentConnector",
    "AgentRegistry",
    "default_provider_specs",
    "discover_mcp_servers",
    "document_formats",
    "parsers",
]
