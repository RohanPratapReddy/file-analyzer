# GNU / GAS assembly (.s) analyzer.
#
# Real parser for AT&T/GAS assembler source (`#` line comments; `/* */` too):
#   .include "macros.s"                           -> import
#   .global main   .globl _start                   -> exported symbol (function)
#   .type foo, @function                            -> declares foo a function
#   foo:                                            -> label (function if code)
#   .equ SIZE, 64   .set N, 8                        -> symbolic constant (variable)
#   msg: .asciz "hi"   count: .word 0                -> data label (variable)
#   .section .text / .data                          -> section (informational)
import re

from .regex_base import RegexCodeAnalyzer


class GnuAssemblyAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "gnu_assembly"
    EXTENSIONS = (".s",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("/*", "*/"),)

    _INCLUDE = re.compile(r'^\s*\.include\s+"([^"]+)"', re.MULTILINE)
    _GLOBAL = re.compile(r"^\s*\.globa?l\s+([\w.$,\s]+)", re.MULTILINE)
    _TYPE_FUNC = re.compile(r"^\s*\.type\s+(\w+)\s*,\s*[@%]function", re.MULTILINE)
    _EQU = re.compile(r"^\s*\.(?:equ|set|equiv)\s+(\w+)\s*,\s*([^\n]+)", re.MULTILINE)
    _LABEL = re.compile(r"^(\w+)\s*:", re.MULTILINE)
    _DATA_DIRECTIVE = re.compile(
        r"^(\w+)\s*:\s*\.(?:byte|word|long|quad|asciz?|ascii|string|float|"
        r"double|space|zero|skip|fill)\b",
        re.MULTILINE,
    )

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._INCLUDE.finditer(t):
            self._add_import(file_id, m.group(1).split("/")[-1], m.group(1))

        func_syms = set()
        for m in self._TYPE_FUNC.finditer(t):
            func_syms.add(m.group(1))
        for m in self._GLOBAL.finditer(t):
            for sym in re.split(r"[,\s]+", m.group(1).strip()):
                if sym:
                    func_syms.add(sym)

        data_syms = set()
        for m in self._DATA_DIRECTIVE.finditer(t):
            data_syms.add(m.group(1))

        for m in self._EQU.finditer(t):
            self._add_variable(
                file_id, m.group(1), m.group(2).strip(), scope="constant"
            )
            data_syms.add(m.group(1))

        # Emit labels: those declared .type @function or .global are functions;
        # labels that immediately define data are variables; the rest are
        # local code labels -> functions (entry points).
        seen = set()
        for m in self._LABEL.finditer(t):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            if name in data_syms:
                if name not in {v["variable_name"] for v in self.variables_table}:
                    self._add_variable(file_id, name, scope="data")
            else:
                self._add_function(
                    file_id,
                    name,
                    description="asm label" if name not in func_syms else "asm global",
                )
        # Globals that were declared but whose label lives in another file.
        for sym in func_syms:
            if sym not in seen:
                self._add_function(file_id, sym, description="asm extern global")
