"""Misc analysis plane -- the terminal plane, run last after ``document``.

Covers the residual structured-text content kinds no earlier plane claims
(Qt style sheets, OpenShot / Camtasia video-editor projects, PostgreSQL
pg_dump scripts) with a parent :class:`MiscAnalyzer` super-class dispatching
each file to its own per-type child parser class (see :mod:`.parsers`), each
stitched to its own extension set, normalizing every file into
``document -> sections -> records -> fields`` tables.
"""
from .misc_analyzer import MiscAnalyzer
from . import misc_formats
from . import parsers

__all__ = ["MiscAnalyzer", "misc_formats", "parsers"]
