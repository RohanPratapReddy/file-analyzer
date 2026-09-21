# Koka (.kk) analyzer -- a function-oriented language with effect types.
#
#     module my/mod                              -> class (module)
#     import std/core                            -> import
#     import qual = std/os/path                  -> import (aliased)
#     pub fun map(f, xs) : e list<b> { ... }     -> function
#     fun square(x : int) : int = x * x          -> function
#     value type shape { Circle; Square }        -> class
#     struct point { x : int; y : int }          -> class
#     effect console { fun println(s : string) : () }  -> class (effect)
#     alias name = string                        -> variable (type alias)
#     val pi = 3.14159                           -> variable
#
# Koka identifiers may contain '-' (e.g. list-map).  Comments are '//', '///'
# and '/* */' (block comments nest, but a flat strip is adequate); strings '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

# Value identifiers start lowercase and may embed dashes; a trailing dash is not
# part of a name (it would be the minus operator), so require a word char last.
_LID = r"[a-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*"
_CID = r"[a-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*"
_PATH = r"[A-Za-z_][A-Za-z0-9_/]*"
_TQUAL = "|".join(["value", "reference", "co", "rec", "open", "extend", "div",
                   "linear"])


class KokaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "koka"
    EXTENSIONS = (".kk",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _MODULE = re.compile(r"(?m)^\s*(?:pub\s+)?module\s+(?:interface\s+)?(" + _PATH + r")")
    _IMPORT = re.compile(
        r"(?m)^\s*import\s+(?:(" + _LID + r")\s*=\s*)?(" + _PATH + r")")
    _FUN = re.compile(
        r"(?m)^\s*(?:pub\s+|inline\s+|noinline\s+|extern\s+|"
        r"private\s+|abstract\s+|fip\s+|fbip\s+|tail\s+)*"
        r"(?:fun|fn)\s+(" + _LID + r")")
    _TYPE = re.compile(
        r"(?m)^\s*(?:pub\s+|private\s+|abstract\s+)*(?:(?:" + _TQUAL +
        r")\s+)*type\s+(" + _CID + r")")
    _STRUCT = re.compile(r"(?m)^\s*(?:pub\s+|private\s+|abstract\s+)*(?:(?:" + _TQUAL +
                         r")\s+)*struct\s+(" + _CID + r")")
    _EFFECT = re.compile(r"(?m)^\s*(?:pub\s+)?(?:named\s+|raw\s+|linear\s+)*effect\s+(" + _CID + r")")
    _ALIAS = re.compile(r"(?m)^\s*(?:pub\s+)?alias\s+(" + _CID + r")")
    _VAL = re.compile(r"(?m)^\s*(?:pub\s+)?val\s+(" + _LID + r")")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1).split("/")[-1])
        for rx in (self._TYPE, self._STRUCT, self._EFFECT):
            for m in rx.finditer(clean):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._MODULE.finditer(clean):
            self._add_class(file_id, m.group(1).split("/")[-1],
                            description="koka module")
        for m in self._IMPORT.finditer(clean):
            src = m.group(2)
            self._add_import(file_id, src.split("/")[-1], src, alias=m.group(1))

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="koka type")
        for m in self._STRUCT.finditer(clean):
            self._add_class(file_id, m.group(1), description="koka struct")
        for m in self._EFFECT.finditer(clean):
            self._add_class(file_id, m.group(1), description="koka effect")
        for m in self._ALIAS.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="type")
        for m in self._VAL.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")

        for m in self._FUN.finditer(clean):
            self._add_function(file_id, m.group(1), [], [],
                               description="koka function")
