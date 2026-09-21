# q / kdb+ (.q) analyzer  (kx Systems vector language).
#
# Real parser for q:
#
#     \l script.q                                   -> import (load)
#     \d .util                                       -> (namespace directive)
#     add:{[x;y] x+y}                                -> function (named lambda + args)
#     sq:{x*x}                                        -> function (implicit x/y/z args)
#     .util.pi:3.14159                               -> variable
#     t:([]sym:`a`b; px:1 2)                          -> variable (table)
#     counter::0                                      -> variable (global assign)
#
# q comments: a '/' at the start of a line (or after whitespace) begins a
# line comment; because every declaration we capture is anchored to the start
# of a line and begins with an identifier, leading-'/' comment lines never
# produce a false symbol, so comment handling is left to anchoring.
import re

from .regex_base import RegexCodeAnalyzer

_NAME = r"[A-Za-z_][\w.]*"


class QAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "q"
    EXTENSIONS = (".q",)
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
        inner = bracket[1:-1]  # strip [ ]
        for part in inner.split(";"):
            nm = part.strip()
            if re.fullmatch(_NAME, nm):
                ids.append(self._add_arg(nm))
        return ids

    def _register_types(self, file_id, text, path):
        return  # q has no user-defined named types

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._LOAD.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.replace("\\", "/").split("/")[-1], src)

        fn_names = set()
        for m in self._FUNC.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._args(m.group(2)),
                [],
                description="q function",
            )
            fn_names.add((m.group(1), m.start()))

        # variable assignments whose RHS is not a lambda
        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1))
