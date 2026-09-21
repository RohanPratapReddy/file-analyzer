# Fennel (.fnl) analyzer.
#
# Real parser for Fennel (a Lisp that compiles to Lua; ';' line comments,
# no block comments; strings "..."):
#   (local json (require :json))                 -> import (require)
#   (import-macros {: view} :fennel.view)         -> import (macro module)
#   (local x 10)   (var y 0)   (global g 1)        -> variable
#   (fn area [r] (* math.pi r r))                  -> function
#   (lambda safe [x ...] ...)                      -> function (arity-checked)
#   (fn obj.method [self a] ...)                    -> function (table method)
#   (macro when-let [b ...] ...)                    -> function (macro)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_SYM = r"[A-Za-z_][A-Za-z0-9_%?!*+./<>=-]*"
# A Fennel symbol is any run of non-whitespace, non-structural characters, so
# operator-named bindings/functions (e.g. `+`, `->str`, `->>`) are captured too.
_NAME = r"[^\s()\[\]{}\";'`~@,]+"


class FennelAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "fennel"
    EXTENSIONS = (".fnl",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(r"\(\s*(fn|lambda|λ|macro)\s+(" + _NAME + r")")
    _VAR = re.compile(r"\(\s*(local|var|global)\s+(" + _NAME + r")")
    # require can be bare `(require :mod)` or bound `(local m (require :mod))`
    _REQUIRE = re.compile(r"\(\s*require(?:-macros)?\s+[:\"]?(" + _SYM + r")")
    _IMPORT_MACROS = re.compile(r"\(\s*import-macros\s+.*?[:\"](" + _SYM + r")")

    def _register_types(self, file_id, text, path):
        # Fennel has no class/struct forms; nothing to reserve.
        pass

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._REQUIRE.finditer(text):
            name = m.group(1).lstrip(":").split(".")[-1]
            self._add_import(file_id, name, m.group(1).lstrip(":"))
        for m in self._IMPORT_MACROS.finditer(text):
            self._add_import(file_id, m.group(1).split(".")[-1], m.group(1))

        # variables (skip those whose value is a (require ...) -> already an import)
        for m in self._VAR.finditer(text):
            name = m.group(2)
            val = self._value_after(text, m.end())
            if val and val.lstrip("(").lstrip().startswith("require"):
                continue
            self._add_variable(file_id, name, val)

        for m in self._FUNC.finditer(text):
            kind, name = m.group(1), m.group(2)
            params = self._arg_vector(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            desc = "fennel macro" if kind == "macro" else "fennel function"
            self._add_function(file_id, name, arg_ids, [], description=desc)

    # ------------------------------------------------------------------
    def _arg_vector(self, text, pos):
        """Parameters live in the ``[...]`` immediately following the name."""
        lb = text.find("[", pos)
        # make sure no other opener comes first (defensive)
        for ch in text[pos:lb if lb != -1 else len(text)]:
            if ch in "([{":
                return []
            if not ch.isspace():
                break
        if lb == -1:
            return []
        rb = self._find_matching(text, lb, "[", "]")
        inner = text[lb + 1:rb - 1]
        params = []
        for tok in re.findall(_SYM, inner):
            if tok in ("&", "&as"):
                continue
            params.append(tok)
        return params

    def _value_after(self, text, pos):
        rest = text[pos:].lstrip()
        if not rest:
            return None
        if rest[0] == "(":
            end = self._find_matching(rest, 0, "(", ")")
            return rest[:end].strip()[:120]
        m = re.match(r"[^\s)]+", rest)
        return m.group(0) if m else None
