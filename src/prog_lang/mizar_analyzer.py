# Mizar (.mizar/.miz) analyzer  (formal mathematics article language).
#
# Real parser for a Mizar article:
#
#     vocabularies XBOOLE_0, ... ;         -> imports (environ directives)
#     notations TARSKI, ... ;              -> imports
#     definition func X + Y -> ... end;    -> function (functor)
#     definition pred x in X means ... ;   -> function (predicate)
#     definition mode Subset of X ...      -> class
#     definition attr x is finite ...      -> function (attribute)
#     struct (1-sorted) TopStruct ...      -> class
#     scheme Sep { ... } : ...             -> function
#     reserve x, y for set;                -> variables
#
# Comment token is '::' to end of line; Mizar has no string literals.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_']*"
_ENV_KEYWORDS = ("vocabularies", "notations", "constructors", "requirements",
                 "definitions", "registrations", "theorems", "schemes",
                 "equalities", "expansions")


class MizarAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "mizar"
    EXTENSIONS = (".mizar", ".miz")
    LINE_COMMENTS = ("::",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    _ENVDIR = re.compile(
        r"^[ \t]*(" + "|".join(_ENV_KEYWORDS) + r")\b([^;]*);",
        re.MULTILINE)
    _FUNC = re.compile(
        r"^[ \t]*(?:redefine\s+)?func\s+(\S+)", re.MULTILINE)
    _PRED = re.compile(
        r"^[ \t]*(?:redefine\s+)?pred\s+(\S+)", re.MULTILINE)
    _ATTR = re.compile(
        r"^[ \t]*(?:redefine\s+)?attr\s+(\S+)", re.MULTILINE)
    _MODE = re.compile(
        r"^[ \t]*(?:redefine\s+)?mode\s+(" + _ID + r")", re.MULTILINE)
    _STRUCT = re.compile(
        r"^[ \t]*struct\b(?:\s*\([^)]*\))?\s*(" + _ID + r")", re.MULTILINE)
    _SCHEME = re.compile(r"^[ \t]*scheme\s+(" + _ID + r")", re.MULTILINE)
    _RESERVE = re.compile(r"^[ \t]*reserve\s+([^;]+?)\s+for\b", re.MULTILINE)

    _ART = re.compile(_ID)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (self._MODE, self._STRUCT):
            for m in rx.finditer(clean):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._ENVDIR.finditer(clean):
            for art in self._ART.findall(m.group(2)):
                self._add_import(file_id, art, art)

        for m in self._MODE.finditer(clean):
            self._add_class(file_id, m.group(1), description="mizar mode")
        for m in self._STRUCT.finditer(clean):
            self._add_class(file_id, m.group(1), description="mizar struct")

        for rx, desc in ((self._FUNC, "mizar functor"),
                         (self._PRED, "mizar predicate"),
                         (self._ATTR, "mizar attribute"),
                         (self._SCHEME, "mizar scheme")):
            for m in rx.finditer(clean):
                nm = m.group(1)
                if nm:
                    self._add_function(file_id, nm, [], [], description=desc)

        for m in self._RESERVE.finditer(clean):
            for nm in self._ART.findall(m.group(1)):
                self._add_variable(file_id, nm)
