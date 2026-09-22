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

from ._version import __version__  # noqa: F401  (SDK version; single source of truth)
from .archive import ArchiveAnalyzer
from .binary import BinaryForensicsAnalyzer, BinaryFormatParser, MachineCodeAnalyzer
from .config import ConfigAnalyzer  # noqa: F401  (configuration-file analyzer plane)
from .convert import (  # noqa: F401  (opaque/legacy -> renderable transcoder + artifact analyzer)
    FormatConverter,
    TextAnalyzer,
)
from .core.analysis_engine import AnalysisEngine
from .core.db_generator import RepositoryDatabaseGenerator
from .core.guardrails import (  # noqa: F401  (IP-safety / secret-PII redaction / acceptable-use)
    ACCEPTABLE_USE,
    PROHIBITED_USES,
    acceptable_use_banner,
    scrub,
)
from .core.import_linkage import ImportLinkageAnalyzer
from .core.repository_analyzer import RepositoryAnalyzer
from .data import DataAnalyzer
from .database import DatabaseAnalyzer
from .document import DocumentAnalyzer  # noqa: F401  (document analyzer plane)
from .document import DocumentParser  # noqa: F401  (document-format analyzer plane)
from .document import (  # noqa: F401  (DocumentParser's two-database generator)
    DocumentParserDatabaseGenerator,
)
from .markup import MarkupAnalyzer  # noqa: F401  (markup analyzer plane)
from .misc import MiscAnalyzer  # noqa: F401  (terminal misc analyzer plane)
from .prog_lang import *  # noqa: F401,F403  (all {Lang}Analyzers + bases + polyglot)
from .prog_lang import PolyglotCodeAnalyzer  # noqa: F401
from .prog_lang import __all__ as _prog_all
from .schema import SchemaAnalyzer
from .shell import *  # noqa: F401,F403  (shell analyzers + ShellScriptAnalyzer)
from .shell import SHELL_EXT_MAP, ShellScriptAnalyzer  # noqa: F401
from .shell import __all__ as _shell_all
from .text import TextualAnalyzer  # noqa: F401  (text-record analyzer plane)

__all__ = [
    "__version__",
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
    "DocumentParser",
    "DocumentParserDatabaseGenerator",
    "MiscAnalyzer",
    "SHELL_EXT_MAP",
    "ACCEPTABLE_USE",
    "PROHIBITED_USES",
    "acceptable_use_banner",
    "scrub",
    *_prog_all,
    *_shell_all,
]
