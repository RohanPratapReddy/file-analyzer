# INTERCAL (.intercal / .i).
#
# INTERCAL (the "Compiler Language With No Pronounceable Acronym") is a
# deliberately perverse imperative language.  Its statements are introduced by
# `DO`, `PLEASE`, or `PLEASE DO` (optionally `... NOT` / `N'T` to abstain):
#
#     (1000) PLEASE DO .1 <- #65535
#            DO :1 <- .1~:2
#            DO (1000) NEXT
#            PLEASE COME FROM (2000)
#            DO READ OUT ,1
#
# The two named constructs are:
#   * Line labels `(nnnn)` prefixing a statement  -> a jump target (function).
#     The SAME `(nnnn)` used as the operand of NEXT / COME FROM / ABSTAIN /
#     REINSTATE is a *reference*, not a definition.
#   * Variables, distinguished by a leading sigil immediately before digits:
#         .n  16-bit "spot"        :n  32-bit "twospot"
#         ,n  16-bit "tail" array  ;n  32-bit "hybrid" array
#     (Constants use `#`; `'`/`"` are grouping "sparks"/"ears", `~` select,
#      `$`/`¢` mingle — none of these introduce a name.)
#
# This analyzer extracts labels as functions (references to undefined labels
# become imports) and every distinct sigil+number as a variable.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

# a label that DEFINES a statement: `(n)` followed by DO / PLEASE
_LABEL_DEF = re.compile(r"(?mi)^\s*\((\d+)\)\s*(?:PLEASE|DO)\b")
# a label used as an operand of a transfer/abstention statement
_LABEL_REF = re.compile(r"(?i)\b(?:NEXT|COME\s+FROM|ABSTAIN\s+FROM|REINSTATE)\b"
                        r"|\((\d+)\)")
_LABEL_TARGET = re.compile(r"\((\d+)\)")
_VAR = re.compile(r"(?<![0-9])([.,:;])(\d+)")
# statements that transfer/abstain by label — their `(n)` operands are refs
_XFER_LINE = re.compile(r"(?mi)^.*\b(?:NEXT|COME\s+FROM|ABSTAIN|REINSTATE)\b.*$")


class IntercalAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "intercal"
    EXTENSIONS = (".intercal",)
    LINE_COMMENTS = ()          # INTERCAL has no comment syntax
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()          # '/" are grouping operators, not strings

    def _extract_entities(self, file_id, text, path):
        defined = set()
        for m in _LABEL_DEF.finditer(text):
            defined.add(int(m.group(1)))

        # collect label references that appear in transfer/abstain statements
        referenced = set()
        for line in _XFER_LINE.finditer(text):
            for t in _LABEL_TARGET.finditer(line.group(0)):
                referenced.add(int(t.group(1)))

        for lbl in sorted(defined):
            self._add_function(file_id, f"label_{lbl}", [], [],
                               description="INTERCAL line label")
        for lbl in sorted(referenced - defined):
            self._add_import(file_id, f"label_{lbl}", f"label_{lbl}")

        seen = set()
        for m in _VAR.finditer(text):
            name = m.group(1) + m.group(2)
            if name in seen:
                continue
            seen.add(name)
            kind = {".": "spot", ":": "twospot",
                    ",": "tail-array", ";": "hybrid-array"}[m.group(1)]
            self._add_variable(file_id, name, None, scope=kind)
