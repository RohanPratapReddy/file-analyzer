# Blackbird photonic program (.blackbird).
#
# Blackbird (Xanadu) is the quantum assembly language for photonic / continuous
# variable circuits executed by Strawberry Fields:
#
#     name my_program
#     version 1.0
#     target gaussian (shots=20)
#
#     float alpha = 0.3423
#     float array phis[2] =
#         0.1, 0.2
#
#     Sgate(0.5, 0.0) | 0
#     BSgate(alpha) | [0, 1]
#     MeasureFock() | [0, 1]
#
# The recovered symbols:
#   * `name <prog>`                    -> class (the named program/blueprint)
#   * `version` / `target`             -> variable (program metadata)
#   * typed declarations
#       `float|int|complex|bool|str [array] NAME[..] = ...`  -> variable
# Gate applications (`Sgate(...) | 0`) apply operations to a register wire and
# introduce no name, so they are not recorded.  `#` starts a comment.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class BlackbirdAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "blackbird"
    EXTENSIONS = (".blackbird",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _NAME = re.compile(r"(?m)^[ \t]*name\s+(" + _ID + r")\s*$")
    _META = re.compile(r"(?m)^[ \t]*(version|target)\s+(\S+)")
    _DECL = re.compile(r"(?m)^[ \t]*(?:float|int|complex|bool|str)\s+"
                       r"(?:array\s+)?(" + _ID + r")\s*(?:\[[^\]]*\])?\s*=")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._NAME.finditer(clean):
            self._add_class(file_id, m.group(1),
                            description="Blackbird program")
        seen_v = set()
        for m in self._META.finditer(clean):
            key = m.group(1)
            if key not in seen_v:
                seen_v.add(key)
                self._add_variable(file_id, key, m.group(2), scope="metadata")
        for m in self._DECL.finditer(clean):
            name = m.group(1)
            if name not in seen_v:
                seen_v.add(name)
                self._add_variable(file_id, name, None, scope="module")
