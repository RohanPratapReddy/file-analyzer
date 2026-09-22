# Red (.red) analyzer  (Red / Red System, a REBOL-descended language).
#
# Real parser for Red:
#
#     add: func [a b][a + b]               -> function
#     inc: function [n][n + 1]             -> function
#     ping: routine [][...]                -> function (Red/System routine)
#     make-node: does [ ... ]              -> function
#     styles: make object! [ ... ]         -> class
#     ctx: context [ x: 0 ]                -> class
#     total: 0                             -> variable (set-word)
#     do %helper.red                       -> import
#     #include %util.reds                  -> import (Red/System)
#
# Comment token is ';' to end of line; strings use '"' (and {...} blocks).
import re

from .regex_base import RegexCodeAnalyzer

_WORD = r"[A-Za-z][A-Za-z0-9!?~+='*&|._-]*"
_FUNC_KW = r"(?:func|function|routine|does|has|make\s+function!)"
_OBJ_KW = r"(?:make\s+object!|context|object)"


class RedAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "red"
    EXTENSIONS = (".red",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(
        r"^[ \t]*(" + _WORD + r"):\s+" + _FUNC_KW + r"(?![\w!?])", re.MULTILINE
    )
    _OBJ = re.compile(
        r"^[ \t]*(" + _WORD + r"):\s+" + _OBJ_KW + r"(?![\w!?])", re.MULTILINE
    )
    _SET = re.compile(
        r"^[ \t]*(" + _WORD + r"):\s+(?!" + _FUNC_KW + r"\b)(?!" + _OBJ_KW + r"\b)\S",
        re.MULTILINE,
    )
    _DO = re.compile(r"^[ \t]*do\s+%(\S+)", re.MULTILINE)
    _INCLUDE = re.compile(r"^[ \t]*#include\s+%(\S+)", re.MULTILINE)

    _SPEC = re.compile(r"\[([^\]]*)\]")

    def _spec_args(self, clean, kw_end):
        m = self._SPEC.search(clean, kw_end)
        if not m:
            return []
        ids = []
        for tok in re.findall(r"[A-Za-z][A-Za-z0-9!?~+='*&|._-]*", m.group(1)):
            ids.append(self._add_arg(tok))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._OBJ.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for rx in (self._DO, self._INCLUDE):
            for m in rx.finditer(clean):
                src = m.group(1)
                self._add_import(file_id, src.replace("\\", "/").split("/")[-1], src)

        func_pos = set()
        for m in self._FUNC.finditer(clean):
            func_pos.add(m.start())
            self._add_function(
                file_id,
                m.group(1),
                self._spec_args(clean, m.end()),
                [],
                description="red function",
            )
        obj_pos = set()
        for m in self._OBJ.finditer(clean):
            obj_pos.add(m.start())
            self._add_class(file_id, m.group(1), description="red object")

        for m in self._SET.finditer(clean):
            if m.start() in func_pos or m.start() in obj_pos:
                continue
            self._add_variable(file_id, m.group(1))
