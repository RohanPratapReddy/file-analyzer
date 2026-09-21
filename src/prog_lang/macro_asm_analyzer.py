# Macro / assembler source (.mac).
#
# The `.mac` extension is used by several assembler macro dialects; this
# analyzer recognises the named constructs of the common ones without assuming
# a single toolchain:
#
#   MASM / TASM (x86):
#       Adder  MACRO  a, b        ; macro definition
#              ENDM
#       main   PROC
#              ENDP main
#       DATA   SEGMENT
#       MAXLEN EQU   80
#              INCLUDE  common.inc
#
#   MACRO-11 / GNU-as style:
#       .MACRO  push  reg
#       .ENDM
#       .INCLUDE "defs.mac"
#       TURN:   .WORD  0            ; data label
#       DIVIDE: MOV    R0,R1        ; code label / subroutine entry
#
#   IBM HLASM:
#       MACRO
#       &LBL  SAVEREGS  &BASE=12
#       MEND
#
#   PDP-1 MACRO (historic; `//` comments, comma-terminated labels):
#       define index A,B,C
#           ...
#           term                    ; macro definition
#       foo,    lat                 ; label
#
# Recovered symbols:
#   * `name MACRO [args]`  /  `.MACRO name [args]`  /  HLASM prototype line
#     following a bare `MACRO`  /  PDP-1 `define name [args] ... term`
#                                                   -> function
#   * `name PROC`                                   -> function (subroutine)
#   * `LABEL:` / PDP-1 `LABEL,` followed by an instruction -> function
#     (subroutine / code entry point)
#   * `name SEGMENT` / `name STRUCT`                -> class
#   * `name EQU value` / `name = value` / `name SET value`   -> variable
#   * `LABEL:` / `LABEL,` followed by a data directive (.WORD/.BYTE/DB/DW/...)
#                                                   -> variable, scope "label"
#   * `INCLUDE file` / `.INCLUDE "file"` / `COPY member`     -> import
# `;` and `//` start comments; a `*` in column 1 is an HLASM comment line;
# keywords are case-insensitive.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_$@#.?][A-Za-z0-9_$@#.?]*"


class MacroAsmAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "macro_asm"
    EXTENSIONS = (".mac",)
    LINE_COMMENTS = (";", "//")
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _MACRO_NAMED = re.compile(r"(?mi)^[ \t]*(" + _ID + r")\s+MACRO\b")
    _MACRO_DOT = re.compile(r"(?mi)^[ \t]*\.MACRO\s+(" + _ID + r")")
    # PDP-1 MACRO:  define name [arg,arg,...]  ...  term
    _DEFINE = re.compile(r"(?m)^[ \t]*define\s+([A-Za-z][A-Za-z0-9]*)")
    # LABEL:  or  PDP-1 LABEL,   (label must not start with a digit)
    _LABEL = re.compile(r"(?m)^[ \t]*(" + _ID + r")[ \t]*([:,])[ \t]*(.*)$")
    # data-defining directives (rest of a label line) => the label names data
    _DATADIR = re.compile(r"(?i)^\.?(WORD|BYTE|BLKW|BLKB|BLKL|ASCI[IZ]|RAD50|"
                          r"RAD40|LONG|QUAD|FLT[24]|PACKED|DB|DW|DD|DQ|DT|DS|"
                          r"DC|FDB|FCB|FCC|RMB|EVEN|ODD)\b")
    _PROC = re.compile(r"(?mi)^[ \t]*(" + _ID + r")\s+PROC\b")
    _CLASS = re.compile(r"(?mi)^[ \t]*(" + _ID + r")\s+(?:SEGMENT|STRUCT|"
                        r"STRUC|UNION|RECORD)\b")
    _EQU = re.compile(r"(?mi)^[ \t]*(" + _ID + r")\s+(?:EQU|SET|SETA|SETB|"
                      r"SETC)\b")
    _ASSIGN = re.compile(r"(?mi)^[ \t]*(" + _ID + r")\s*=")
    _INCLUDE = re.compile(r'(?mi)^[ \t]*(?:\.INCLUDE\s+"([^"]+)"|'
                          r'INCLUDE\s+([^\s;]+)|COPY\s+([^\s;]+))')

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)
        lines = clean.splitlines()

        seen_fn, seen_c, seen_v, seen_i = set(), set(), set(), set()

        def add_fn(name, desc):
            if name and name.lower() not in seen_fn:
                seen_fn.add(name.lower())
                self._add_function(file_id, name, [], [], description=desc)

        # HLASM bare `MACRO` line: the macro name is the operation field of the
        # next non-blank prototype line (optionally preceded by a label).
        for i, ln in enumerate(lines):
            if re.match(r"(?i)^[ \t]*MACRO[ \t]*$", ln):
                for nxt in lines[i + 1:]:
                    if not nxt.strip():
                        continue
                    toks = nxt.split()
                    # `&LBL  OPNAME ...`  or  `OPNAME ...`
                    if toks and toks[0].startswith("&") and len(toks) > 1:
                        add_fn(toks[1], "HLASM macro")
                    elif toks:
                        add_fn(toks[0], "HLASM macro")
                    break

        for m in self._MACRO_NAMED.finditer(clean):
            add_fn(m.group(1), "assembler macro")
        for m in self._MACRO_DOT.finditer(clean):
            add_fn(m.group(1), "assembler macro")
        for m in self._DEFINE.finditer(clean):
            add_fn(m.group(1), "PDP-1 macro")
        for m in self._PROC.finditer(clean):
            add_fn(m.group(1), "assembler procedure")

        for m in self._CLASS.finditer(clean):
            name = m.group(1)
            if name.lower() not in seen_c:
                seen_c.add(name.lower())
                self._add_class(file_id, name, description="assembler segment/struct")

        for rx in (self._EQU, self._ASSIGN):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name.lower() in seen_v or name.lower() in seen_fn:
                    continue
                # avoid catching the MACRO/PROC/EQU keyword lines already handled
                seen_v.add(name.lower())
                self._add_variable(file_id, name, None, scope="symbol")

        # labels: `LABEL:` (MACRO-11/MASM/GNU) or `LABEL,` (PDP-1).  A label
        # that names a data cell (followed by a data directive) is a variable;
        # a label at a code location is a subroutine / entry point (function).
        for m in self._LABEL.finditer(clean):
            name, sep, rest = m.group(1), m.group(2), m.group(3).strip()
            low = name.lower()
            if low in seen_fn or low in seen_v:
                continue
            # keep directives/opcodes with a stray comma from being read as
            # PDP-1 labels: the comma form only labels when `rest` looks like an
            # instruction or is empty, not a bare operand-less directive.
            if self._DATADIR.match(rest):
                seen_v.add(low)
                self._add_variable(file_id, name, None, scope="label")
            else:
                seen_fn.add(low)
                self._add_function(file_id, name, [], [],
                                   description="assembler label")

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1) or m.group(2) or m.group(3)
            if src:
                src = src.strip("'\"")
                if src.lower() not in seen_i:
                    seen_i.add(src.lower())
                    self._add_import(file_id, src.replace("\\", "/").split("/")[-1],
                                     src)
