# Stim stabilizer-circuit file (.stim).
#
# Stim (Craig Gidney / Google Quantum AI) describes a stabilizer circuit as a
# flat, largely symbol-free instruction stream:
#
#     QUBIT_COORDS(0, 0) 0
#     H 0
#     CX 0 1
#     TICK
#     REPEAT 5 {
#         CX 0 1
#         MR 1
#         DETECTOR(1, 0) rec[-1] rec[-2]
#     }
#     M 0
#     OBSERVABLE_INCLUDE(0) rec[-1]
#
# Gate applications (`H`, `CX`, `M`, ...), `TICK`, `REPEAT ... { }` and
# coordinate annotations name nothing.  The only constructs that *define* a
# named, referenceable logical entity are:
#   * `OBSERVABLE_INCLUDE(k) ...`  -> a logical observable  `observable_<k>`
#     (a function: it is the target the decoder reconstructs).
# Everything else is an unnamed circuit instruction, so a Stim file with no
# OBSERVABLE_INCLUDE is legitimately empty of symbols -- that is the CORRECT
# outcome, exactly as for the esolang analyzers.
import re

from .regex_base import RegexCodeAnalyzer


class StimAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "stim"
    EXTENSIONS = (".stim",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    _OBS = re.compile(r"(?m)^[ \t]*OBSERVABLE_INCLUDE\s*\(\s*(\d+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)
        seen = set()
        for m in self._OBS.finditer(clean):
            idx = m.group(1)
            if idx in seen:
                continue
            seen.add(idx)
            self._add_function(
                file_id,
                f"observable_{idx}",
                [],
                [],
                description="Stim logical observable",
            )
