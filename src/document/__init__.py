"""Document analysis plane.

Covers the eight residual *document* content kinds (manifest, query, makefile,
certificate_text, notebook, document, license, diff) with a parent
:class:`DocumentAnalyzer` super-class dispatching each file to its own
per-type child parser class (see :mod:`.parsers`), each stitched to its own
extension set, normalizing every file into
``document -> sections -> records -> fields`` tables.
"""
from .document_analyzer import DocumentAnalyzer
from . import document_formats
from . import parsers

__all__ = ["DocumentAnalyzer", "document_formats", "parsers"]
