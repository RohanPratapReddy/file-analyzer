# NASM (.nasm) x86/x86-64 assembly analyzer.
#
# Real parser for Netwide Assembler source:
#
#     %include "io.inc"                 -> import
#     extern printf                     -> import (external symbol)
#     global _start                     -> (export, not emitted)
#     %define WIDTH 8                    -> variable (single-line macro)
#     BUFSZ equ 1024                     -> variable (assembly-time constant)
#     %macro prologue 1                 -> function (multi-line macro)
#         push rbp
#     %endmacro
#     struc point                       -> class
#         .x resd 1
#     endstruc
#     _start:                           -> function (code label)
#         mov rax, 1
#     msg: db "hi", 0                    -> variable (data label)
#
# A label followed by a data directive (db/dw/.../resb/equ) is a data object
# (variable); any other top-level label is a code entry point (function).
# Local labels (leading '.') are ignored.  Comments are ';'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_.?][\w.$#@?~]*"
_DATA_DIR = re.compile(r"^(?:d[bwdqto]|res[bwdqto]|equ)\b", re.IGNORECASE)


class NasmAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "nasm"
    EXTENSIONS = (".nasm",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'", "`")

    _INCLUDE = re.compile(r'^[ \t]*%include\s+["\']([^"\']+)["\']', re.MULTILINE)
    _EXTERN = re.compile(r"^[ \t]*extern\s+(.+)$", re.MULTILINE | re.IGNORECASE)
    _MACRO = re.compile(r"^[ \t]*%i?macro\s+(" + _ID + r")", re.MULTILINE)
    _DEFINE = re.compile(
        r"^[ \t]*%[a-z]*(?:define|assign)\s+(" + _ID + r")",
        re.MULTILINE | re.IGNORECASE,
    )
    _STRUC = re.compile(r"^[ \t]*struc\s+(" + _ID + r")", re.MULTILINE)
    _EQU = re.compile(r"^[ \t]*(" + _ID + r")\s+equ\b", re.MULTILINE | re.IGNORECASE)
    _LABEL = re.compile(r"^[ \t]*(" + _ID + r")\s*:(.*)$", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._STRUC.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            hdr = m.group(1)
            self._add_import(file_id, hdr.replace("\\", "/").split("/")[-1], hdr)
        for m in self._EXTERN.finditer(clean):
            for nm in self._split_top_level(m.group(1)):
                nm = nm.strip()
                if nm:
                    self._add_import(file_id, nm, nm)

        for m in self._STRUC.finditer(clean):
            self._add_class(file_id, m.group(1), description="nasm struc")

        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), "macro")
        for m in self._EQU.finditer(clean):
            self._add_variable(file_id, m.group(1), "equ")

        for m in self._MACRO.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], description="nasm macro")

        for m in self._LABEL.finditer(clean):
            name = m.group(1)
            if name.startswith("."):
                continue  # local label
            rest = m.group(2).strip()
            if _DATA_DIR.match(rest):
                self._add_variable(file_id, name, "data")
            else:
                self._add_function(file_id, name, [], [], description="nasm label")
