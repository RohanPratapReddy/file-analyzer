# Quil (.quil) quantum-instruction-language analyzer.
#
# Real parser for Rigetti Quil (indentation-delimited bodies; '#' line comments):
#
#     DECLARE ro BIT[2]                 -> variable (classical memory)
#     DEFGATE HADAMARD:                 -> function (matrix gate definition)
#         0.707, 0.707
#         0.707, -0.707
#     DEFGATE RX(%theta) p q AS PAULI-SUM:   -> function (parametric)
#     DEFCIRCUIT BELL a b:              -> function (circuit macro w/ qubit args)
#         H a
#         CNOT a b
#     DEFFRAME 0 "rf":                  -> function (named by quoted frame name)
#     DEFWAVEFORM my_wf:                -> function
#     LABEL @start                      -> variable (jump target)
#     EXTERN PHONY                      -> variable (external instruction decl)
#
# The instruction body (`H 0`, `MEASURE 0 ro[0]`, ...) is not itself a named
# entity, so only the DECLARE/DEF*/LABEL headers produce rows.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class QuilAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "quil"
    EXTENSIONS = (".quil",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    # Quil identifiers permit internal hyphens: [A-Za-z_]([\w-]*[\w])?
    _DECLARE = re.compile(r"^[ \t]*DECLARE\s+([A-Za-z_][\w-]*)\s+(\S+)", re.MULTILINE)
    _LABEL = re.compile(r"^[ \t]*LABEL\s+@?([A-Za-z_][\w-]*)", re.MULTILINE)
    _EXTERN = re.compile(r"^[ \t]*EXTERN\s+([A-Za-z_][\w-]*)", re.MULTILINE)
    # DEFGATE / DEFCIRCUIT / DEFWAVEFORM / DEFCAL headers (identifier-named)
    _DEF = re.compile(
        r"^[ \t]*(DEFGATE|DEFCIRCUIT|DEFWAVEFORM|DEFCAL)\s+"
        r"([A-Za-z_][\w-]*)\s*(?:\(([^)]*)\))?([^:\n]*):", re.MULTILINE)
    # DEFFRAME is named by qubit operands + a quoted frame name, with optional ':'
    _DEFFRAME = re.compile(r'^[ \t]*DEFFRAME\s+([\d \t]*)"([^"]+)"', re.MULTILINE)

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._DECLARE.finditer(text):
            self._add_variable(file_id, m.group(1), m.group(2))

        for m in self._LABEL.finditer(text):
            self._add_variable(file_id, m.group(1), "label")

        for m in self._EXTERN.finditer(text):
            self._add_variable(file_id, m.group(1), "extern")

        for m in self._DEF.finditer(text):
            kind, name = m.group(1), m.group(2)
            arg_ids = []
            for p in self._split_top_level(m.group(3) or ""):
                arg_ids.append(self._add_arg(p.strip().lstrip("%"), "param"))
            # trailing formal qubit/frame operands before the ':' / 'AS'
            tail = re.split(r"\bAS\b", m.group(4) or "")[0]
            for q in re.split(r"[ \t]+", tail.strip()):
                if re.match(r"^[A-Za-z_]\w*$", q):
                    arg_ids.append(self._add_arg(q, "qubit"))
            self._add_function(file_id, name, arg_ids, [],
                               description=kind.lower())

        # DEFFRAME <qubits> "frame-name" [:]  -> function named by the frame
        for m in self._DEFFRAME.finditer(text):
            arg_ids = []
            for q in re.split(r"[ \t]+", m.group(1).strip()):
                if q:
                    arg_ids.append(self._add_arg(q, "qubit"))
            self._add_function(file_id, m.group(2), arg_ids, [],
                               description="defframe")
