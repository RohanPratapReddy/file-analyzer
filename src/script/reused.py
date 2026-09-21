# Script dialects that ARE an existing analysed language -- handled by the real
# parser for that language, differing only in the owned extension.
#
#   .fsx        F# script            -> real FSharpAnalyzer
#   .pl .t      Perl script / test   -> real PerlAnalyzer
#
# `.pl`/`.t` are, in practice, overwhelmingly Perl (a `.t` file is a Perl
# Test::More script; `.pl` is a Perl program).  Genuine Prolog source keeps the
# dedicated `.prolog` extension, which the code plane already routes to the real
# `PrologAnalyzer`; so Perl is the correct, non-ambiguous default here.
from ..prog_lang.fsharp_analyzer import FSharpAnalyzer
from ..prog_lang.perl_analyzer import PerlAnalyzer


class FSharpScriptAnalyzer(FSharpAnalyzer):
    """`.fsx` scripting files share F#'s grammar (`open`, `let`, `type`,
    `member`), extracted in full by the inherited real parser."""

    LANG_KEY = "fsharp-script"
    EXTENSIONS = (".fsx",)


class PerlScriptAnalyzer(PerlAnalyzer):
    """`.pl` programs and `.t` test scripts -- Perl (`use`/`require`, `package`,
    `sub`, `my/our` variables), handled by the inherited real Perl parser."""

    LANG_KEY = "perl"
    EXTENSIONS = (".pl", ".t")
