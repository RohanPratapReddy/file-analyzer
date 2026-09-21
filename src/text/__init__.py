"""Text-record analysis plane.

Covers the seven residual *text-record* content kinds (data_text, text, log,
documentation, template, scientific_data, subtitle) with real, per-extension,
structure-aware parsers that normalize each file into
``document -> sections -> records -> fields`` tables.
"""

from . import textual_formats
from .textual_analyzer import TextualAnalyzer

__all__ = ["TextualAnalyzer", "textual_formats"]
