# Ook! (.ook).
#
# Ook! is a trivial re-encoding of Brainfuck for orang-utans: every Brainfuck
# command is written as a pair of the three tokens `Ook.`  `Ook?`  `Ook!`
#
#       Ook. Ook?   ->  >        Ook? Ook.   ->  <
#       Ook. Ook.   ->  +        Ook! Ook!   ->  -
#       Ook! Ook.   ->  .        Ook. Ook!   ->  ,
#       Ook! Ook?   ->  [        Ook? Ook!   ->  ]
#
# Because it is Brainfuck under the skin, Ook! has NO named constructs at all —
# no functions, variables, imports or types.  The honest analysis yields no
# named symbols.  This analyzer tokenizes the `Ook<punct>` stream for real
# (pairing tokens into Brainfuck commands and validating bracket balance) but
# records nothing, because the language names nothing.  An "empty" Ook! file is
# the CORRECT result.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_OOK = re.compile(r"Ook([.?!])")
# token-pair -> brainfuck command
_PAIRS = {
    (".", "?"): ">", ("?", "."): "<", (".", "."): "+", ("!", "!"): "-",
    ("!", "."): ".", (".", "!"): ",", ("!", "?"): "[", ("?", "!"): "]",
}


class OokAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ook"
    EXTENSIONS = (".ook",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    def _extract_entities(self, file_id, text, path):
        toks = [m.group(1) for m in _OOK.finditer(text)]
        depth = 0
        for i in range(0, len(toks) - 1, 2):
            cmd = _PAIRS.get((toks[i], toks[i + 1]))
            if cmd == "[":
                depth += 1
            elif cmd == "]":
                depth = max(0, depth - 1)
        # tokens validated; Ook! declares no named entity, so emit nothing.
        return
