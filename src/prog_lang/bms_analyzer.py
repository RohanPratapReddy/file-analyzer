# CICS Basic Mapping Support (.bms).
#
# A BMS source member is IBM assembler-macro syntax that defines terminal
# screen layouts.  Three macros carry every named symbol:
#
#     MAPSET   DFHMSD TYPE=&SYSPARM,MODE=INOUT,LANG=COBOL,TIOAPFX=YES
#     MENUMAP  DFHMDI SIZE=(24,80),LINE=1,COLUMN=1
#     ACCTNO   DFHMDF POS=(3,20),LENGTH=8,ATTRB=(UNPROT,IC)
#              DFHMSD TYPE=FINAL
#              END
#
#   * a label (cols 1-8) + DFHMSD  -> the map SET   (class)
#   * a label + DFHMDI             -> a MAP          (class, member of the set)
#   * a label + DFHMDF             -> a screen FIELD (variable, scope="map")
#   * COPY member                  -> import
#
# `DFHMSD TYPE=FINAL` and the trailing `END` are terminators (no label) and are
# ignored.  Unlabeled `DFHMDF` cards are filler fields (no name) and are skipped.
# Column-1 `*` starts an assembler comment line; operand lists continue onto the
# next card when column 72 is non-blank, but the label + macro always sit on the
# first card, which is all symbol extraction needs.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_NM = r"[A-Za-z$#@][A-Za-z0-9$#@]*"


class BmsAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "bms"
    EXTENSIONS = (".bms",)
    LINE_COMMENTS = ()          # column-1 `*` handled in _decomment
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'",)

    _MAPSET = re.compile(r"(?m)^(" + _NM + r")\s+DFHMSD\b")
    _MAP = re.compile(r"(?m)^(" + _NM + r")\s+DFHMDI\b")
    _FIELD = re.compile(r"(?m)^(" + _NM + r")\s+DFHMDF\b")
    _COPY = re.compile(r"(?m)^\s*COPY\s+(" + _NM + r")")
    _POS = re.compile(r"POS=\(\s*(\d+)\s*,\s*(\d+)\s*\)")
    _LEN = re.compile(r"LENGTH=(\d+)")

    def _decomment(self, text: str) -> str:
        # assembler comment cards start with `*` in column 1
        out = []
        for line in text.splitlines():
            if line[:1] == "*":
                out.append("")
            else:
                out.append(line)
        return "\n".join(out)

    def _register_types(self, file_id, text, path):
        clean = self._decomment(text)
        for m in self._MAPSET.finditer(clean):
            self._register_class(m.group(1))
        for m in self._MAP.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._decomment(text)

        for m in self._COPY.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        for m in self._MAPSET.finditer(clean):
            self._add_class(file_id, m.group(1), description="BMS map set")
        for m in self._MAP.finditer(clean):
            self._add_class(file_id, m.group(1), description="BMS map")

        for m in self._FIELD.finditer(clean):
            name = m.group(1)
            line = clean[m.start():clean.find("\n", m.start()) if
                         clean.find("\n", m.start()) != -1 else len(clean)]
            pos = self._POS.search(line)
            ln = self._LEN.search(line)
            desc = "BMS field"
            if pos:
                desc += f" @({pos.group(1)},{pos.group(2)})"
            if ln:
                desc += f" len={ln.group(1)}"
            self._add_variable(file_id, name, desc, scope="map")
