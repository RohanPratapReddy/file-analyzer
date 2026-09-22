# PineScript (.pine) analyzer  (TradingView charting language, v4/v5/v6).
#
# Real parser for PineScript:
#
#     //@version=5
#     indicator("My Ind", overlay=true)            -> variable (script decl)
#     strategy("My Strat")                          -> variable
#     library("mylib")                              -> variable
#     import user/lib/1 as L                        -> import
#     type Point                                    -> class (user-defined type)
#         float x
#     enum Signal                                   -> class
#     f(x, y) =>                                     -> function
#     method reset(Point p) =>                      -> function (method)
#     var float total = 0.0                         -> variable
#     length = input.int(14)                        -> variable
#
# Comments are '//' only.  Strings use ' or ".
import re

from .regex_base import RegexCodeAnalyzer


class PineScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "pinescript"
    EXTENSIONS = (".pine",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _IMPORT = re.compile(
        r"^[ \t]*import\s+([\w./]+)(?:\s+as\s+([A-Za-z_]\w*))?", re.MULTILINE
    )
    _DECL = re.compile(r"^[ \t]*(indicator|strategy|library)\s*\(", re.MULTILINE)
    _TYPE = re.compile(r"^[ \t]*(?:export\s+)?type\s+([A-Za-z_]\w*)", re.MULTILINE)
    _ENUM = re.compile(r"^[ \t]*(?:export\s+)?enum\s+([A-Za-z_]\w*)", re.MULTILINE)
    _METHOD = re.compile(
        r"^[ \t]*(?:export\s+)?method\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*=>", re.MULTILINE
    )
    _FUNC = re.compile(
        r"^[ \t]*(?:export\s+)?([A-Za-z_]\w*)\s*\(([^)]*)\)\s*=>", re.MULTILINE
    )
    _VAR = re.compile(
        r"^(?:var\s+|varip\s+)(?:[A-Za-z_][\w.\[\]<>]*\s+)?([A-Za-z_]\w*)\s*=",
        re.MULTILINE,
    )
    _ASSIGN = re.compile(r"^([A-Za-z_]\w*)\s*=(?![=>])", re.MULTILINE)

    def _args(self, blob):
        ids = []
        for part in self._split_top_level(blob or ""):
            nm = re.search(r"([A-Za-z_]\w*)\s*(?:=|$)", part)
            if nm:
                ids.append(self._add_arg(nm.group(1), part.strip()))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            mod, alias = m.group(1), m.group(2)
            self._add_import(file_id, (alias or mod).split("/")[-1], mod, alias)

        for m in self._DECL.finditer(clean):
            self._add_variable(file_id, m.group(1), "script")

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="pine type")
        for m in self._ENUM.finditer(clean):
            self._add_class(file_id, m.group(1), description="pine enum")

        seen_fn = set()
        for m in self._METHOD.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._args(m.group(2)),
                [],
                description="pine method",
            )
            seen_fn.add((m.group(1), m.start()))
        for m in self._FUNC.finditer(clean):
            # skip the `method` keyword itself being read as a function name
            if m.group(1) in ("method", "if", "for", "while", "switch"):
                continue
            self._add_function(
                file_id,
                m.group(1),
                self._args(m.group(2)),
                [],
                description="pine function",
            )

        emitted = set()
        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1))
            emitted.add(m.group(1))
        for m in self._ASSIGN.finditer(clean):
            nm = m.group(1)
            if nm in ("indicator", "strategy", "library") or nm in emitted:
                continue
            self._add_variable(file_id, nm)
            emitted.add(nm)
