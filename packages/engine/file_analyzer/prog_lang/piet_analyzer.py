# Piet (.piet).
#
# Piet is a stack language whose programs are ABSTRACT PAINTINGS: execution is
# driven by transitions between coloured regions ("codels"), and the twenty
# valid colours (6 hues x 3 lightnesses, plus black and white) encode the
# operations.  A canonical Piet program is therefore an image (PNG/GIF/PPM),
# not source text.
#
# The `.piet` text form used by tooling (e.g. npiet's textual grids) is just a
# whitespace/character grid of colour codes — there are NO named constructs:
# no functions, variables, imports or types, and no textual identifiers at all.
# A codel block is anonymous and positional.
#
# The honest analysis of a Piet file therefore yields no named symbols.  This
# analyzer reads the grid (measuring the canvas and tallying the distinct codel
# tokens, so a genuinely empty or non-grid file is distinguishable) but records
# nothing.  An "empty" Piet file is the CORRECT result, not a missed
# extraction.
from .regex_base import RegexCodeAnalyzer


class PietAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "piet"
    EXTENSIONS = (".piet",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    def _extract_entities(self, file_id, text, path):
        # Tally the codel grid purely to parse the file faithfully; Piet names
        # nothing, so nothing is written to the symbol tables.
        codels = set()
        for line in text.splitlines():
            for tok in line.split():
                codels.add(tok)
        return
