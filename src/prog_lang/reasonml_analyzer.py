# ReasonML (.re) analyzer.
#
# Real parser for Reason (OCaml semantics, JS-ish syntax; '/* */' block and '//'
# line comments; strings "..."):
#   open Belt;                                            -> import
#   module Foo = { ... };                                 -> module (class row)
#   type point = { x: int, y: int };                      -> type (class + fields)
#   type color = Red | Green | Blue;                       -> type (class + cons)
#   let area = (r) => pi *. r *. r;                        -> function
#   let name = (a, b) => ...;                              -> function
#   let pi = 3.14;                                          -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class ReasonMLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "reasonml"
    EXTENSIONS = (".re", ".rei")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _OPEN = re.compile(r"^\s*(?:open|include)\s+([A-Z][\w.]*)", re.MULTILINE)
    _MODULE = re.compile(r"^\s*module\s+([A-Z]\w*)\s*=", re.MULTILINE)
    _TYPE = re.compile(r"^\s*type\s+([a-z_]\w*)\s*(?:\([^)]*\))?\s*=", re.MULTILINE)
    _LET = re.compile(
        r"^\s*let\s+(?:rec\s+)?([a-z_]\w*)\s*(?::[^=]+?)?=\s*", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._TYPE.finditer(text):
            self._register_class(m.group(1))
        for m in self._MODULE.finditer(text):
            self._register_class(m.group(1))

    def _rhs(self, text, eq_end):
        """The RHS text of a let/type binding up to the terminating ';' at depth 0."""
        i, n, depth = eq_end, len(text), 0
        instr = None
        while i < n:
            c = text[i]
            if instr:
                if c == "\\":
                    i += 2; continue
                if c == instr:
                    instr = None
                i += 1; continue
            if c == '"':
                instr = c
            elif c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == ";" and depth == 0:
                return text[eq_end:i]
            i += 1
        return text[eq_end:]

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._OPEN.finditer(text):
            mod = m.group(1)
            self._add_import(file_id, mod.split(".")[-1], mod)

        # modules -> class rows
        for m in self._MODULE.finditer(text):
            self._add_class(file_id, m.group(1), description="reasonml module")

        # types -> record fields or variant constructors as attrs
        for m in self._TYPE.finditer(text):
            name = m.group(1)
            rhs = self._rhs(text, m.end())
            attrs = []
            rec = re.search(r"\{(.*)\}", rhs, re.DOTALL)
            if rec:
                for field in self._split_top_level(rec.group(1)):
                    fm = re.match(r"(?:mutable\s+)?(\w+)\s*:\s*(.+)", field.strip(),
                                  re.DOTALL)
                    if fm:
                        attrs.append(self._add_arg(fm.group(1), fm.group(2).strip()))
            else:
                for part in rhs.split("|"):
                    cm = re.match(r"\s*([A-Z]\w*)", part)
                    if cm:
                        attrs.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="reasonml type", attr_ids=attrs)

        # let bindings: function if RHS is an arrow, else variable
        for m in self._LET.finditer(text):
            name = m.group(1)
            rhs = self._rhs(text, m.end()).strip()
            paren = re.match(r"\(([^)]*)\)\s*=>", rhs)
            single = re.match(r"([A-Za-z_]\w*)\s*=>", rhs)
            if paren:
                params = []
                for part in self._split_top_level(paren.group(1)):
                    pm = re.match(r"(?:~)?(\w+)", part.strip())
                    if pm:
                        params.append(self._add_arg(pm.group(1)))
                self._add_function(file_id, name, params, [])
            elif single:
                self._add_function(file_id, name, [self._add_arg(single.group(1))], [])
            else:
                self._add_variable(file_id, name, rhs[:60] or None)
