"""Markup analysis plane.

Covers the residual *markup* content kind (HTML/XHTML, the ~200 XML application
vocabularies, OFX SGML, and wiki/gemtext/roff/typst/MIF/markdown/lightweight
markups) with real, per-extension, structure-aware parsers that normalize each
document into ``document -> elements (+ attributes + namespaces) -> sections +
properties`` tables describing which tags/sections are present and the metrics
of the content within them.
"""

from . import markup_formats
from .markup_analyzer import MarkupAnalyzer

__all__ = ["MarkupAnalyzer", "markup_formats"]
