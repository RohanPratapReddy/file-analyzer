"""config -- configuration-file analyzer plane.

Real, pure-stdlib parsers for the 345 ``config``-type residual extensions
(~57 syntax families) plus a normalized relational decomposition of every parsed
file into ``config_*`` tables.  See :mod:`.config_formats` for the parsers and
:mod:`.config_analyzer` for the table-emitting analyzer.
"""

from .config_analyzer import ConfigAnalyzer
from . import config_formats

__all__ = ["ConfigAnalyzer", "config_formats"]
