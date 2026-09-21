# py.shell -- real, syntax-aware analyzers for the shell / command-language /
# automation-script families catalogued in docs/shell_scripts.json.
#
# Design mirrors py.prog_lang exactly:
#   * every family has a concrete `<X>Analyzer` that subclasses either
#     `ShellScriptBase` (regex / command-language grammar) or, for the six
#     Python-syntax recipe DSLs, `PythonEmbeddedAnalyzer` (real `ast` parse);
#   * all emit the identical `code`-domain relational tables, so shell files
#     fold into the single `code` routing class with no schema changes;
#   * `SHELL_EXT_MAP` maps each owned extension to its analyzer class, and
#     `ShellScriptAnalyzer` is a standalone polyglot dispatcher over that map
#     (reusing PolyglotCodeAnalyzer's id-reconciliation machinery verbatim).
#
# The pipeline itself routes these extensions by merging `SHELL_EXT_MAP` into
# `PolyglotCodeAnalyzer.EXT_MAP` (see py.prog_lang.polyglot), which the router
# derives its `code` extension universe from -- so registration alone routes
# every shell extension to `code`.
#
# NOTE on import order: `SHELL_EXT_MAP` is built BEFORE `polyglot` is imported.
# `polyglot.py` imports `SHELL_EXT_MAP` from this module at its own bottom to
# self-register the shell extensions, so building the map first breaks the cycle
# no matter which of the two modules is imported first.  None of the analyzer
# modules imported here reach back into `polyglot`.
from .shell_base import ShellScriptBase
from .posix_shell import PosixShellAnalyzer
from .bitbake import BitBakeAnalyzer
from .python_dsls import (
    ConanRecipeAnalyzer, SConsBuildAnalyzer, SpackRecipeAnalyzer,
    SageScriptAnalyzer, AbaqusJournalAnalyzer, StarlarkAnalyzer,
)
from .tcl_family import TclAnalyzer
from .statistics import StataAnalyzer, SasAnalyzer, SpssAnalyzer
from .math_scripting import GapAnalyzer, PariGpAnalyzer, MapleAnalyzer
from .text_processing import AwkAnalyzer, SedAnalyzer
from .modern_shells import ElvishAnalyzer, NushellAnalyzer
from .windows_scripting import VbScriptAnalyzer, WsfAnalyzer
from .automation import AutoItAnalyzer, AutoHotkeyAnalyzer, GdbInitAnalyzer
from .installers import InnoSetupAnalyzer, NsisAnalyzer
from .mainframe import (
    JclAnalyzer, RexxAnalyzer, ClistAnalyzer, ClpAnalyzer, DclAnalyzer,
)
from .build_scripts import M4Analyzer, JenkinsfileAnalyzer, VagrantfileAnalyzer
from .misc_langs import CsxAnalyzer, ElixirMixAnalyzer, NimScriptAnalyzer
from .domain_scripts import (
    NukeAnalyzer, PainlessAnalyzer, WeztermAnalyzer, ProxyAutoConfigAnalyzer,
)
from .binary_template import BinaryTemplateAnalyzer
from .compiled_scripts import CompiledScriptAnalyzer
from .applescript import AppleScriptAnalyzer


# ----------------------------------------------------------------------------
# Extension -> analyzer class.  Built from each analyzer's own EXTENSIONS tuple
# so this map can never drift out of sync with the analyzers themselves.
# ----------------------------------------------------------------------------
_ANALYZERS = (
    PosixShellAnalyzer, BitBakeAnalyzer,
    ConanRecipeAnalyzer, SConsBuildAnalyzer, SpackRecipeAnalyzer,
    SageScriptAnalyzer, AbaqusJournalAnalyzer, StarlarkAnalyzer,
    TclAnalyzer, StataAnalyzer, SasAnalyzer, SpssAnalyzer,
    GapAnalyzer, PariGpAnalyzer, MapleAnalyzer,
    AwkAnalyzer, SedAnalyzer, ElvishAnalyzer, NushellAnalyzer,
    VbScriptAnalyzer, WsfAnalyzer,
    AutoItAnalyzer, AutoHotkeyAnalyzer, GdbInitAnalyzer,
    InnoSetupAnalyzer, NsisAnalyzer,
    JclAnalyzer, RexxAnalyzer, ClistAnalyzer, ClpAnalyzer, DclAnalyzer,
    M4Analyzer, JenkinsfileAnalyzer, VagrantfileAnalyzer,
    CsxAnalyzer, ElixirMixAnalyzer, NimScriptAnalyzer,
    NukeAnalyzer, PainlessAnalyzer, WeztermAnalyzer, ProxyAutoConfigAnalyzer,
    BinaryTemplateAnalyzer, CompiledScriptAnalyzer, AppleScriptAnalyzer,
)

SHELL_EXT_MAP = {}
for _cls in _ANALYZERS:
    for _ext in _cls.EXTENSIONS:
        _key = _ext.lower()
        if _key in SHELL_EXT_MAP and SHELL_EXT_MAP[_key] is not _cls:
            raise RuntimeError(
                f"shell extension collision on {_key}: "
                f"{SHELL_EXT_MAP[_key].__name__} vs {_cls.__name__}")
        SHELL_EXT_MAP[_key] = _cls


# Imported only now that SHELL_EXT_MAP exists, so that when `polyglot` is the
# module imported first, its bottom `from ..shell import SHELL_EXT_MAP` finds a
# fully-built map instead of a half-initialised module.
from ..prog_lang.polyglot import PolyglotCodeAnalyzer


class ShellScriptAnalyzer(PolyglotCodeAnalyzer):
    """Standalone polyglot dispatcher over the shell / script analyzers.

    Identical machinery to ``PolyglotCodeAnalyzer`` (cross-analyzer id
    reconciliation, per-analyzer failure isolation, one merged relational
    dataset) but keyed on ``SHELL_EXT_MAP``.  Used for standalone analysis and
    testing of the shell subpackage; the production pipeline instead merges
    ``SHELL_EXT_MAP`` into ``PolyglotCodeAnalyzer.EXT_MAP`` so shell files are
    analyzed in the same ``code`` pass as programming-language files.
    """
    EXT_MAP = dict(SHELL_EXT_MAP)

    def __init__(self, file_paths, dump_file_path="shell_analysis.json",
                 dump_file_type="json"):
        super().__init__(file_paths=file_paths, dump_file_path=dump_file_path,
                         dump_file_type=dump_file_type)


__all__ = [
    "ShellScriptBase", "ShellScriptAnalyzer", "SHELL_EXT_MAP",
    "PosixShellAnalyzer", "BitBakeAnalyzer",
    "ConanRecipeAnalyzer", "SConsBuildAnalyzer", "SpackRecipeAnalyzer",
    "SageScriptAnalyzer", "AbaqusJournalAnalyzer", "StarlarkAnalyzer",
    "TclAnalyzer", "StataAnalyzer", "SasAnalyzer", "SpssAnalyzer",
    "GapAnalyzer", "PariGpAnalyzer", "MapleAnalyzer",
    "AwkAnalyzer", "SedAnalyzer", "ElvishAnalyzer", "NushellAnalyzer",
    "VbScriptAnalyzer", "WsfAnalyzer",
    "AutoItAnalyzer", "AutoHotkeyAnalyzer", "GdbInitAnalyzer",
    "InnoSetupAnalyzer", "NsisAnalyzer",
    "JclAnalyzer", "RexxAnalyzer", "ClistAnalyzer", "ClpAnalyzer", "DclAnalyzer",
    "M4Analyzer", "JenkinsfileAnalyzer", "VagrantfileAnalyzer",
    "CsxAnalyzer", "ElixirMixAnalyzer", "NimScriptAnalyzer",
    "NukeAnalyzer", "PainlessAnalyzer", "WeztermAnalyzer",
    "ProxyAutoConfigAnalyzer",
    "BinaryTemplateAnalyzer", "CompiledScriptAnalyzer", "AppleScriptAnalyzer",
]
