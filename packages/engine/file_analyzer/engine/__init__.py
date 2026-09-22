"""
``file_analyzer.engine`` -- the analyzer fleet's public API (the engine wheel).

This subpackage is the public face of the ``file-analyzer-engine`` wheel: the
repository analyzers, the orchestration engine, and the high-level SDK classes
that *build* databases. It is the one import surface the fleet exposes::

    from file_analyzer.engine import RepositoryAnalyzer, AnalysisEngine, analyze

The heavy analyzer modules still live at the top of the shared ``file_analyzer``
namespace (``file_analyzer.core``, ``file_analyzer.prog_lang``, ...); this module
re-exports them under one name. Importing it pulls in the analyzer fleet on
purpose -- that is the whole point of the engine wheel. The small client wheel
(:mod:`file_analyzer.client`) never imports this, so a client-only install stays
lightweight; :func:`file_analyzer.client.has_engine` detects whether this wheel
is installed (it keys on ``file_analyzer.engine`` being importable).

The three wheels share the ``file_analyzer`` namespace via PEP 420:

* ``file-analyzer-client`` -- ``file_analyzer.client`` + the stdlib foundation
  (``_version``, ``runtime_guard``, ``tokens``, ``naming``, ``store``).
* ``file-analyzer-server`` -- ``file_analyzer.server`` (the DB-hosting server).
* ``file-analyzer-engine`` -- ``file_analyzer.engine`` + the analyzer fleet
  (this wheel).

The database-**hosting** server (``FileAnalyzerServer``) is intentionally *not*
re-exported here: it ships in the server wheel. ``FileAnalyzerClient.server()``
lazily imports it and raises a helpful error if that wheel is absent.
"""

from .._version import __version__  # noqa: F401  (single source of truth)
from ..archive import ArchiveAnalyzer
from ..binary import BinaryForensicsAnalyzer, BinaryFormatParser, MachineCodeAnalyzer
from ..config import ConfigAnalyzer  # noqa: F401  (configuration-file analyzer plane)
from ..convert import (  # noqa: F401  (opaque/legacy -> renderable transcoder)
    FormatConverter,
    TextAnalyzer,
)
from ..core.analysis_engine import AnalysisEngine
from ..core.db_generator import RepositoryDatabaseGenerator
from ..core.guardrails import (  # noqa: F401  (IP-safety / secret-PII redaction)
    ACCEPTABLE_USE,
    PROHIBITED_USES,
    acceptable_use_banner,
    scrub,
)
from ..core.import_linkage import ImportLinkageAnalyzer
from ..core.repository_analyzer import RepositoryAnalyzer
from ..data import DataAnalyzer
from ..database import DatabaseAnalyzer
from ..document import DocumentAnalyzer  # noqa: F401  (document analyzer plane)
from ..document import DocumentParser  # noqa: F401  (document-format analyzer plane)
from ..document import (  # noqa: F401  (DocumentParser's database generator)
    DocumentParserDatabaseGenerator,
)
from ..markup import MarkupAnalyzer  # noqa: F401  (markup analyzer plane)
from ..misc import MiscAnalyzer  # noqa: F401  (terminal misc analyzer plane)
from ..prog_lang import *  # noqa: F401,F403  (all {Lang}Analyzers + bases + polyglot)
from ..prog_lang import PolyglotCodeAnalyzer  # noqa: F401
from ..prog_lang import __all__ as _prog_all
from ..schema import SchemaAnalyzer
from ..sdk import (  # noqa: F401  (high-level object-oriented SDK surface)
    AnalysisResult,
    FileAnalyzerAgent,
    FileAnalyzerClient,
    FileAnalyzerDatabase,
    FileAnalyzerMCPServer,
    FileAnalyzerMonitor,
)
from ..sdk import analyze as analyze  # noqa: F401  (one-shot convenience helper)
from ..sdk import open_database as open_database  # noqa: F401  (read-only db opener)
from ..shell import *  # noqa: F401,F403  (shell analyzers + ShellScriptAnalyzer)
from ..shell import SHELL_EXT_MAP, ShellScriptAnalyzer  # noqa: F401
from ..shell import __all__ as _shell_all
from ..text import TextualAnalyzer  # noqa: F401  (text-record analyzer plane)

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
    # High-level object-oriented SDK surface
    "FileAnalyzerClient",
    "FileAnalyzerMCPServer",
    "FileAnalyzerAgent",
    "FileAnalyzerMonitor",
    "FileAnalyzerDatabase",
    "AnalysisResult",
    "analyze",
    "open_database",
    *_prog_all,
    *_shell_all,
]
