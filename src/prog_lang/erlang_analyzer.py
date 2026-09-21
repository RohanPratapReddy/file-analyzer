# Erlang (.erl source, .hrl header) analyzer.
#
# Real parser for Erlang (`%` line comments, no block comments):
#   -module(mymod).                              -> module (class row)
#   -import(lists, [map/2, foldl/3]).            -> import
#   -include("defs.hrl").  -include_lib(...)     -> import
#   -record(person, {name, age = 0}).            -> record (class row, fields)
#   -export([start/0, loop/1]).                  -> export list (informational)
#   start() -> ... .                             -> function (by name/arity)
#   loop(State) when ... -> ... ;                -> function clause (deduped)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class ErlangAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "erlang"
    EXTENSIONS = (".erl", ".hrl")
    LINE_COMMENTS = ("%",)
    BLOCK_COMMENTS = ()

    _MODULE = re.compile(r"^\s*-module\s*\(\s*([\w]+)\s*\)", re.MULTILINE)
    _IMPORT = re.compile(r"^\s*-import\s*\(\s*([\w]+)\s*,\s*\[([^\]]*)\]",
                         re.MULTILINE)
    _INCLUDE = re.compile(r'^\s*-include(?:_lib)?\s*\(\s*"([^"]+)"', re.MULTILINE)
    _RECORD = re.compile(
        r"^\s*-record\s*\(\s*(\w+)\s*,\s*\{(.*?)\}\s*\)\s*\.",
        re.MULTILINE | re.DOTALL)
    _DEFINE = re.compile(r"^\s*-define\s*\(\s*(\w+)", re.MULTILINE)
    _FUNC = re.compile(r"^([a-z]\w*)\s*\(([^)]*)\)\s*(?:when\b[^-]*?)?->",
                       re.MULTILINE)

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._MODULE.finditer(t):
            self._register_class(m.group(1))
        for m in self._RECORD.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._IMPORT.finditer(t):
            mod = m.group(1)
            for fn in m.group(2).split(","):
                fn = fn.strip()
                if fn:
                    self._add_import(file_id, fn, f"{mod}:{fn}")
        for m in self._INCLUDE.finditer(t):
            inc = m.group(1)
            self._add_import(file_id, inc.split("/")[-1], inc)

        for m in self._MODULE.finditer(t):
            self._add_class(file_id, m.group(1), description="erlang module")

        for m in self._RECORD.finditer(t):
            name, body = m.group(1), m.group(2)
            attr_ids = []
            for field in self._split_top_level(body):
                fm = re.match(r"(\w+)\s*(?:=\s*(.+))?$", field.strip(), re.DOTALL)
                if fm:
                    attr_ids.append(self._add_arg(
                        fm.group(1), None,
                        fm.group(2).strip() if fm.group(2) else None))
            self._add_class(file_id, name, description="erlang record",
                            attr_ids=attr_ids)

        for m in self._DEFINE.finditer(t):
            self._add_variable(file_id, m.group(1), scope="macro")

        # Function clauses: one row per name/arity.
        seen = set()
        for m in self._FUNC.finditer(t):
            name, params = m.group(1), m.group(2).strip()
            arity = 0 if not params else len(self._split_top_level(params))
            key = (name, arity)
            if key in seen:
                continue
            seen.add(key)
            arg_ids = [self._add_arg(a.strip())
                       for a in self._split_top_level(params)] if params else []
            self._add_function(file_id, f"{name}/{arity}", arg_ids,
                               description="erlang function")
