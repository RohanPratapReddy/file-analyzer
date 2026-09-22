# K (.k) analyzer  (kdb / ngn-k array language; sibling of q).
#
# Real parser for K:
#
#     name:{[a;b] a+b}                     -> function (named lambda + args)
#     sq:{x*x}                             -> function (implicit x/y/z args)
#     name:2 3 5                           -> variable
#     name::0                              -> variable (global assign)
#     \l script.k                          -> import (load)
#     \d .ns                               -> (namespace directive, ignored)
#
# K comments: a '/' at the start of a line (or after whitespace) begins a line
# comment, and a block runs from a lone '/' line to a lone '\' line.  Every
# declaration captured here is anchored to the start of a line and begins with
# an identifier, so leading-'/' comment lines never produce a false symbol and
# comment handling is left to anchoring (mirrors the q analyzer).
import re

from .regex_base import RegexCodeAnalyzer

_NAME = r"[A-Za-z_][A-Za-z0-9_.]*"


class KAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "k"
    EXTENSIONS = (".k",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _LOAD = re.compile(r"^[ \t]*\\l\s+(\S+)", re.MULTILINE)
    _FUNC = re.compile(r"^[ \t]*(" + _NAME + r")\s*::?\s*\{(\[[^\]]*\])?", re.MULTILINE)
    _VAR = re.compile(r"^[ \t]*(" + _NAME + r")\s*::?(?!\s*\{)", re.MULTILINE)

    def _args(self, bracket):
        ids = []
        if not bracket:
            return ids
        for part in bracket[1:-1].split(";"):
            nm = part.strip()
            if re.fullmatch(_NAME, nm):
                ids.append(self._add_arg(nm))
        return ids

    def _register_types(self, file_id, text, path):
        return  # K has no user-defined named types

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._LOAD.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.replace("\\", "/").split("/")[-1], src)

        for m in self._FUNC.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._args(m.group(2)),
                [],
                description="k function",
            )

        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1))
