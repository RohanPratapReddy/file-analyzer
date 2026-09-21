# OpenQASM (.qasm / .openqasm) quantum-assembly analyzer.
#
# Real parser for OpenQASM 2.0 and 3.0 (C-family; '//' line + '/* */' block
# comments, "..." strings):
#
#     OPENQASM 3.0;
#     include "stdgates.inc";                 -> import
#     qubit[2] q;                             -> variable (register/decl)
#     bit[2] c;
#     qreg a[3];  creg b[3];                  -> variable (OpenQASM 2 registers)
#     const int[32] N = 5;                    -> variable
#     gate myrz(theta) a { rz(theta) a; }     -> function (params + qubit args)
#     def add(int a, int b) -> int { ... }    -> function (with return)
#     opaque cx a, b;                         -> function (declaration only)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class OpenQASMAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "openqasm"
    EXTENSIONS = (".qasm", ".openqasm")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _INCLUDE = re.compile(r'^[ \t]*include\s+"([^"]+)"', re.MULTILINE)
    _GATE = re.compile(r"^[ \t]*(?:opaque|gate)\s+([A-Za-z_]\w*)\s*"
                       r"(?:\(([^)]*)\))?\s*([^\{;\n]*)", re.MULTILINE)
    _DEF = re.compile(r"^[ \t]*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"
                      r"(?:\s*->\s*([^\{\n]+?))?\s*\{", re.MULTILINE)
    # declarations: qubit[..] name; / bit c; / qreg q[2]; / const int n = 5; ...
    _DECL = re.compile(
        r"^[ \t]*(?:const\s+)?"
        r"(qubit|bit|qreg|creg|int|uint|float|angle|bool|complex|duration|stretch)"
        r"(?:\[[^\]]*\])?\s+([A-Za-z_]\w*)", re.MULTILINE)
    # OpenQASM 3 I/O modifiers:  input int[8] x;  output qreg q[4];  input x;
    _IO = re.compile(
        r"^[ \t]*(input|output)\s+"
        r"(?:(?:qubit|bit|qreg|creg|int|uint|float|angle|bool|complex|duration|"
        r"stretch|array)(?:\[[^\]]*\])?\s+)?"
        r"([A-Za-z_]\w*)", re.MULTILINE)
    _TYPE_KW = {"qubit", "bit", "qreg", "creg", "int", "uint", "float", "angle",
                "bool", "complex", "duration", "stretch", "array"}

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._INCLUDE.finditer(text):
            src = m.group(1)
            self._add_import(file_id, re.sub(r"\.(inc|qasm)$", "", src), src)

        # gate definitions:  gate NAME(params) qubits { ... }
        gate_spans = []
        for m in self._GATE.finditer(text):
            name = m.group(1)
            arg_ids = []
            for p in self._split_top_level(m.group(2) or ""):
                arg_ids.append(self._add_arg(p.strip(), "param"))
            for q in re.split(r"[, \t]+", (m.group(3) or "").strip()):
                if re.match(r"^[A-Za-z_]\w*$", q):
                    arg_ids.append(self._add_arg(q, "qubit"))
            gate_spans.append((m.start(), m.end()))
            self._add_function(file_id, name, arg_ids, [],
                               description="openqasm gate")

        # subroutine definitions:  def NAME(params) -> ret { ... }
        for m in self._DEF.finditer(text):
            name = m.group(1)
            arg_ids = []
            for p in self._split_top_level(m.group(2)):
                pm = re.match(r"(?:const\s+)?[\w\[\]]+\s+([A-Za-z_]\w*)", p.strip())
                if pm:
                    arg_ids.append(self._add_arg(pm.group(1), p.strip()))
            out_ids = []
            if m.group(3):
                out_ids.append(self._add_output(m.group(3).strip()))
            self._add_function(file_id, name, arg_ids, out_ids,
                               description="openqasm def")

        # top-level declarations -> variables (skip parameter names inside gates)
        for m in self._DECL.finditer(text):
            if any(a <= m.start() < b for a, b in gate_spans):
                continue
            self._add_variable(file_id, m.group(2), m.group(1))

        # input/output I/O declarations -> variables (skip bare-type non-decls)
        for m in self._IO.finditer(text):
            name = m.group(2)
            if name in self._TYPE_KW:
                continue
            self._add_variable(file_id, name, m.group(1))
