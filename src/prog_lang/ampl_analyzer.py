# AMPL (.ampl / .mod is taken) analyzer -- A Mathematical Programming Language.
#
#     set NODES;                              -> variable (set)
#     param cost{NODES} >= 0;                 -> variable (param)
#     var Flow{(i,j) in ARCS} >= 0;           -> variable (decision var)
#     maximize Profit: sum{i in N} c[i];      -> function (objective)
#     minimize Cost: ...;                     -> function (objective)
#     subject to Balance{i in N}: ...;        -> function (constraint)
#     s.t. Cap{a in A}: ...;                  -> function (constraint)
#     problem Sub: Flow, Cost;                -> class
#     include "data.dat";                     -> import
#     model "core.mod";                       -> import
#
# Comments are '#' and '/* */'; strings use '"' and "'".
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class AMPLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ampl"
    EXTENSIONS = (".ampl",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _SET = re.compile(r"(?m)^\s*set\s+(" + _ID + r")\b")
    _PARAM = re.compile(r"(?m)^\s*param\s+(" + _ID + r")\b")
    _VAR = re.compile(r"(?m)^\s*var\s+(" + _ID + r")\b")
    _OBJ = re.compile(r"(?m)^\s*(?:maximize|minimize)\s+(" + _ID + r")\b")
    _CON = re.compile(r"(?m)^\s*(?:subject\s+to|s\.t\.)\s+(" + _ID + r")\b")
    _PROBLEM = re.compile(r"(?m)^\s*problem\s+(" + _ID + r")\b")
    _INCLUDE = re.compile(r'(?m)^\s*(?:include|model|data)\s+(?:"([^"]+)"|(\S+?))\s*;')

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._PROBLEM.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = (m.group(1) or m.group(2) or "").strip()
            if not src:
                continue
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for m in self._SET.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="set")
        for m in self._PARAM.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="param")
        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="var")

        for m in self._OBJ.finditer(clean):
            self._add_function(file_id, m.group(1), [], [],
                               description="ampl objective")
        for m in self._CON.finditer(clean):
            self._add_function(file_id, m.group(1), [], [],
                               description="ampl constraint")
        for m in self._PROBLEM.finditer(clean):
            self._add_class(file_id, m.group(1), description="ampl problem")
