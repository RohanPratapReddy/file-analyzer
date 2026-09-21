# Yaskawa Motoman INFORM robot job (.jbi).
#
# A `.jbi` is a Motoman/Yaskawa INFORM III teach-pendant job.  Its structure is
# a sequence of `//`-prefixed section headers followed by instruction cards:
#
#     /JOB
#     //NAME PICKPLACE
#     //POS
#     ///NPOS 2,0,0,0,0,0
#     ///TOOL 0
#     C00000=1000.0,0.0,500.0,0.0,90.0,0.0
#     //INST
#     ///DATE 2021/03/01 10:00
#     NOP
#     *loop
#     MOVJ C00000 VJ=25.00
#     DOUT OT#(1) ON
#     CALL JOB:SUBJOB
#     JUMP *loop
#     END
#
#   //NAME name         -> function (the job routine itself)
#   *label              -> function (a jump-target label)
#   CALL JOB:name       -> import (invokes another job)
#   Cxxxxx=... / SET Vnnn -> variable (position & user variables)
#
# The `//`, `///` prefixes are structural section markers, NOT comments; INFORM
# comments start with a leading apostrophe (`'`).  Instruction mnemonics (MOVJ,
# DOUT, NOP, ...) are statements and carry no named symbol.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class JbiAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "inform-jbi"
    EXTENSIONS = (".jbi",)
    LINE_COMMENTS = ("'",)      # `//` are section headers, not comments
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _NAME = re.compile(r"(?m)^//NAME\s+(\S+)")
    _LABEL = re.compile(r"(?m)^\s*\*(\S+)")
    _CALL = re.compile(r"(?mi)^\s*CALL\s+JOB\s*:\s*(\S+)")
    _POSVAR = re.compile(r"(?m)^\s*([A-Z]{1,2}\d{3,5})\s*=")
    _SETVAR = re.compile(r"(?mi)^\s*SET\s+([BIDRP]\d{3,4}|LB\d{3,4})\b")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._NAME.finditer(clean):
            self._add_function(file_id, m.group(1), [], [],
                               description="INFORM job routine")

        for m in self._CALL.finditer(clean):
            nm = m.group(1)
            self._add_import(file_id, nm, "JOB:" + nm)

        seen_fn = set()
        for m in self._LABEL.finditer(clean):
            nm = m.group(1)
            if nm in seen_fn:
                continue
            seen_fn.add(nm)
            self._add_function(file_id, "*" + nm, [], [],
                               description="INFORM jump label")

        seen_v = set()
        for m in self._POSVAR.finditer(clean):
            nm = m.group(1)
            if nm not in seen_v:
                seen_v.add(nm)
                self._add_variable(file_id, nm, "position variable", scope="job")
        for m in self._SETVAR.finditer(clean):
            nm = m.group(1)
            if nm not in seen_v:
                seen_v.add(nm)
                self._add_variable(file_id, nm, "user variable", scope="job")
