# ReScript source (.res).
#
# ReScript is a strongly-typed language in the OCaml/ML family that compiles to
# JavaScript.  Top-level declarations look like:
#
#     open Belt
#     module Button = {
#       @react.component
#       let make = (~label) => <button> {React.string(label)} </button>
#     }
#     type point = {x: int, y: int}
#     external log: string => unit = "console.log"
#     let pi = 3.14159
#     let add = (a, b) => a + b
#     exception NotFound
#
# Recovered symbols:
#   * `let name = (args) => ...`         -> function  (arrow-bound binding)
#     `let rec name = ...`               -> function
#     `let name = <non-arrow>`           -> variable
#   * `external name : t = "..."`        -> function  (JS FFI binding)
#   * `module Name = { ... }` / `module Name: T = { ... }`  -> class
#   * `type name = ...`                  -> class
#   * `exception Name`                   -> class
#   * `open M` / `include M`             -> import
# `//` is a line comment, `/* ... */` a (nesting) block comment, `"..."` a
# string.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_']*"
_UID = r"[A-Z][A-Za-z0-9_']*"


class ReScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "rescript"
    EXTENSIONS = (".res",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    # let [rec] name [: type] = rhs
    _LET = re.compile(r"(?m)^[ \t]*(?:@[\w.]+(?:\([^)]*\))?\s*)*"
                      r"let\s+(rec\s+)?(" + _ID + r")\s*"
                      r"(?::[^=]+)?=\s*(.*)$")
    _EXTERNAL = re.compile(r"(?m)^[ \t]*(?:@[\w.]+(?:\([^)]*\))?\s*)*"
                           r"external\s+(" + _ID + r")\s*:")
    _MODULE = re.compile(r"(?m)^[ \t]*module\s+(?:type\s+)?(" + _UID +
                         r")\b(?![ \t]*=[ \t]*" + _UID + r"[ \t]*$)")
    _TYPE = re.compile(r"(?m)^[ \t]*type\s+(?:rec\s+)?(" + _ID + r")\b")
    _EXCEPTION = re.compile(r"(?m)^[ \t]*exception\s+(" + _UID + r")\b")
    _OPEN = re.compile(r"(?m)^[ \t]*(?:open|include)\s+(?:module\s+)?(" +
                       _UID + r"(?:\." + _UID + r")*)")

    # an arrow function RHS:  (...) => ...   or   x =>   or   async (...) =>
    _ARROW = re.compile(r"^\s*(?:async\s+)?(?:\([^;]*?\)|" + _ID + r")\s*=>")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn, seen_v, seen_c, seen_i = set(), set(), set(), set()

        for m in self._LET.finditer(clean):
            is_rec, name, rhs = m.group(1), m.group(2), m.group(3)
            if name in seen_fn or name in seen_v:
                continue
            if is_rec or self._ARROW.match(rhs):
                seen_fn.add(name)
                self._add_function(file_id, name, [], [],
                                   description="ReScript function")
            else:
                seen_v.add(name)
                self._add_variable(file_id, name, rhs.strip() or None,
                                   scope="module")

        for m in self._EXTERNAL.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_function(file_id, name, [], [],
                                   description="ReScript external binding")

        for rx, desc in ((self._MODULE, "ReScript module"),
                         (self._TYPE, "ReScript type"),
                         (self._EXCEPTION, "ReScript exception")):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name in seen_c:
                    continue
                seen_c.add(name)
                self._add_class(file_id, name, description=desc)

        for m in self._OPEN.finditer(clean):
            src = m.group(1)
            if src not in seen_i:
                seen_i.add(src)
                self._add_import(file_id, src.split(".")[-1], src)
