"""tabgen repository-analysis pipeline (split from the former code_analyzer.py).

Public API is unchanged: the same class names import from this package top level.
Internally the modules are grouped into three analysis-domain subpackages plus
the orchestration glue that ties them together:

    prog_lang/  per-language {Lang}Analyzer classes + engine bases + PolyglotCodeAnalyzer
    data/       DataAnalyzer (data-file profiler)
    schema/     SchemaAnalyzer (DB-schema parser)
    core/       RepositoryAnalyzer -> ImportLinkageAnalyzer -> RepositoryDatabaseGenerator
                + AnalysisEngine (orchestration glue)
"""
from .core.repository_analyzer import RepositoryAnalyzer
from .core.import_linkage import ImportLinkageAnalyzer
from .core.db_generator import RepositoryDatabaseGenerator

from .prog_lang import *          # noqa: F401,F403  (all {Lang}Analyzers + bases + polyglot)
from .prog_lang import __all__ as _prog_all
from .prog_lang import PolyglotCodeAnalyzer  # noqa: F401
from .data import DataAnalyzer
from .schema import SchemaAnalyzer
from .database import DatabaseAnalyzer
from .archive import ArchiveAnalyzer
from .binary import MachineCodeAnalyzer, BinaryForensicsAnalyzer, BinaryFormatParser
from .shell import *              # noqa: F401,F403  (shell/command-language analyzers + ShellScriptAnalyzer)
from .shell import __all__ as _shell_all
from .shell import ShellScriptAnalyzer, SHELL_EXT_MAP  # noqa: F401
from .convert import FormatConverter, TextAnalyzer  # noqa: F401  (opaque/legacy -> renderable transcoder + artifact analyzer)
from .config import ConfigAnalyzer  # noqa: F401  (configuration-file analyzer plane)
from .text import TextualAnalyzer  # noqa: F401  (text-record analyzer plane)
from .markup import MarkupAnalyzer  # noqa: F401  (markup analyzer plane)
from .document import DocumentAnalyzer  # noqa: F401  (document analyzer plane)
from .misc import MiscAnalyzer  # noqa: F401  (terminal misc analyzer plane)

from .core.analysis_engine import AnalysisEngine

__all__ = [
    "RepositoryAnalyzer",
    "ImportLinkageAnalyzer",
    "RepositoryDatabaseGenerator",
    "DataAnalyzer",
    "SchemaAnalyzer",
    "DatabaseAnalyzer",
    "ArchiveAnalyzer",
    "MachineCodeAnalyzer",
    "BinaryForensicsAnalyzer",
    "BinaryFormatParser",
    "AnalysisEngine",
    "FormatConverter",
    "TextAnalyzer",
    "ConfigAnalyzer",
    "TextualAnalyzer",
    "MarkupAnalyzer",
    "DocumentAnalyzer",
    "MiscAnalyzer",
    "SHELL_EXT_MAP",
    *_prog_all,
    *_shell_all,
]
