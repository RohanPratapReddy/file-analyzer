# `script` plane -- mainstream command-language / build-script dialects.
#
# These are the residual `script`-kind extensions (bash/sh/zsh/ksh, fish,
# PowerShell, batch, CMake, Gradle, Bazel Starlark, F# script, Perl).  Scripts
# ARE code -- they define functions, variables and sourced/imported files and
# emit the exact same relational tables as every programming-language analyzer.
# So, exactly like the `shell` subpackage, this plane folds into the single
# `code` domain: `SCRIPT_EXT_MAP` (ext -> analyzer class) is merged into
# `PolyglotCodeAnalyzer.EXT_MAP`, which is what routes every script extension to
# the code plane (the router derives its code universe lazily from that map).
#
# Where a script dialect exactly matches a language that already has a real
# parser (Groovy/Starlark/F#/Perl/POSIX-shell), the analyzer subclasses that
# parser and only changes the owned extension -- never a placeholder.  Genuine
# gaps (PowerShell, batch, CMake, fish) get their own real hand-written parsers.
from .build_tools import (
    BazelExtensionAnalyzer,
    CMakeAnalyzer,
    GradleBuildAnalyzer,
)
from .reused import FSharpScriptAnalyzer, PerlScriptAnalyzer
from .shells import FishShellAnalyzer, PosixScriptShellAnalyzer
from .windows import BatchScriptAnalyzer, PowerShellAnalyzer

__all__ = [
    "PosixScriptShellAnalyzer",
    "FishShellAnalyzer",
    "PowerShellAnalyzer",
    "BatchScriptAnalyzer",
    "CMakeAnalyzer",
    "GradleBuildAnalyzer",
    "BazelExtensionAnalyzer",
    "FSharpScriptAnalyzer",
    "PerlScriptAnalyzer",
    "SCRIPT_EXT_MAP",
]

_ANALYZERS = (
    PosixScriptShellAnalyzer,
    FishShellAnalyzer,
    PowerShellAnalyzer,
    BatchScriptAnalyzer,
    CMakeAnalyzer,
    GradleBuildAnalyzer,
    BazelExtensionAnalyzer,
    FSharpScriptAnalyzer,
    PerlScriptAnalyzer,
)

# Extension -> analyzer class, built from each analyzer's own EXTENSIONS tuple so
# the map can never drift out of sync with the analyzers themselves.
SCRIPT_EXT_MAP = {}
for _cls in _ANALYZERS:
    for _ext in _cls.EXTENSIONS:
        _key = _ext.lower()
        if _key in SCRIPT_EXT_MAP and SCRIPT_EXT_MAP[_key] is not _cls:
            raise RuntimeError(
                f"script extension collision on {_key}: "
                f"{SCRIPT_EXT_MAP[_key].__name__} vs {_cls.__name__}"
            )
        SCRIPT_EXT_MAP[_key] = _cls
