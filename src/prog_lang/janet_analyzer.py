# Janet (.janet) analyzer.
#
# Real parser for Janet (a Lisp/Clojure-like language; '#' line comments;
# strings "..." and long-strings `...`):
#   (import ./util :as u)                         -> import (aliased)
#   (import spork/json)                            -> import
#   (use spork)                                    -> import (use)
#   (def PI 3.14)   (var count 0)                   -> variable
#   (defn area [r] (* PI r r))                     -> function
#   (defn- helper [x] ...)                          -> function (private)
#   (defmacro unless [c & body] ...)                -> function (macro)
#   (defn tbl/method [self a] ...)                   -> function
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_SYM = r"[A-Za-z_][A-Za-z0-9_%?!*/<>=+.-]*"
# A Janet symbol is any run of non-whitespace, non-structural characters, so
# operator-named bindings/functions (e.g. `+`, `->`, `not=`) are captured too.
_NAME = r"[^\s()\[\]{}\";'`~@,]+"


class JanetAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "janet"
    EXTENSIONS = (".janet",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(
        r"\(\s*(defn-|defn|defmacro-|defmacro|varfn)\s+(" + _NAME + r")")
    _VAR = re.compile(r"\(\s*(def|def-|var|var-)\s+(" + _NAME + r")")
    _IMPORT = re.compile(
        r"\(\s*(?:import|import\*)\s+['\"]?([\w./-]+)(?:.*?:as\s+(" + _SYM + r"))?",
        re.DOTALL)
    _USE = re.compile(r"\(\s*use\s+([\w./-]+)")

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._IMPORT.finditer(text):
            mod = m.group(1).strip("'\"")
            self._add_import(file_id, (m.group(2) or mod).split("/")[-1], mod,
                             m.group(2))
        for m in self._USE.finditer(text):
            self._add_import(file_id, m.group(1).split("/")[-1], m.group(1))

        # keep the `def*` forms that are NOT function definitions as variables
        func_starts = {m.start() for m in self._FUNC.finditer(text)}
        for m in self._VAR.finditer(text):
            if m.start() in func_starts:
                continue
            name = m.group(2)
            val = self._value_after(text, m.end())
            if val and val.lstrip("(").lstrip().split(None, 1)[0:1] == ["import"]:
                continue
            self._add_variable(file_id, name, val)

        for m in self._FUNC.finditer(text):
            kind, name = m.group(1), m.group(2)
            params = self._arg_vector(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            desc = "janet macro" if kind.startswith("defmacro") else "janet function"
            self._add_function(file_id, name, arg_ids, [], description=desc)

    # ------------------------------------------------------------------
    def _arg_vector(self, text, pos):
        # (defn name docstring? [params] body) - skip an optional docstring
        rest_i = pos
        # skip whitespace / an optional leading string docstring before the [
        while rest_i < len(text) and text[rest_i] in " \t\n\r":
            rest_i += 1
        if rest_i < len(text) and text[rest_i] == '"':
            end = self._find_matching_str(text, rest_i)
            rest_i = end
        lb = text.find("[", rest_i)
        # bail if a form opens before the param vector
        for ch in text[rest_i:lb if lb != -1 else len(text)]:
            if ch in "({":
                return []
            if not ch.isspace() and ch != '"':
                break
        if lb == -1:
            return []
        rb = self._find_matching(text, lb, "[", "]")
        params = []
        for tok in re.findall(_SYM, text[lb + 1:rb - 1]):
            if tok in ("&", "&opt", "&keys", "&named"):
                continue
            params.append(tok)
        return params

    @staticmethod
    def _find_matching_str(text, start):
        i = start + 1
        while i < len(text):
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == '"':
                return i + 1
            i += 1
        return len(text)

    def _value_after(self, text, pos):
        rest = text[pos:].lstrip()
        if not rest:
            return None
        if rest[0] == "(":
            end = self._find_matching(rest, 0, "(", ")")
            return rest[:end].strip()[:120]
        m = re.match(r"[^\s)]+", rest)
        return m.group(0) if m else None
