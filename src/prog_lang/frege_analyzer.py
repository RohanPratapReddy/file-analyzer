# Frege (.frege / .fr) analyzer -- Haskell for the JVM.
#
# Frege is Haskell syntax, so we parse the same declaration forms:
#
#     module My.Mod where                    -> class (module)
#     import Data.List (sort, nub)           -> import (+ each explicit name)
#     import frege.Prelude as P              -> import (aliased)
#     data Tree a = Leaf | Node a            -> class
#     newtype Age = Age Int                  -> class
#     type Name = String                     -> variable (type synonym)
#     class Show a where ...                 -> class (typeclass)
#     instance Show Int where ...            -> (folded onto the class)
#     native sqrt :: Double -> Double        -> function (native binding)
#     twice :: a -> a                        -> function (signature)
#     twice x = ...                          -> function (definition, deduped)
#
# Comments are '--' and '{- -}'; strings use '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[a-z_][A-Za-z0-9_']*"
_CID = r"[A-Z][A-Za-z0-9_']*"
_QUAL = r"[A-Za-z_][A-Za-z0-9_'.]*"
_KEYWORDS = {
    "data", "type", "newtype", "class", "instance", "module", "import",
    "where", "deriving", "infixl", "infixr", "infix", "native", "pure",
    "do", "let", "in", "case", "of", "if", "then", "else", "forall",
    "package", "protected", "private", "public", "abstract", "derive",
}


class FregeAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "frege"
    EXTENSIONS = (".frege", ".fr")
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = (("{-", "-}"),)
    STRING_DELIMS = ('"',)

    _MODULE = re.compile(r"(?m)^\s*module\s+(" + _QUAL + r")\b")
    _IMPORT = re.compile(
        r"(?m)^\s*import\s+(?:qualified\s+)?(" + _QUAL + r")"
        r"(?:\s+as\s+(" + _CID + r"))?(?:\s*\(([^)]*)\))?")
    _DATA = re.compile(r"(?m)^\s*(?:data|newtype)\s+(" + _CID + r")")
    _TYPE = re.compile(r"(?m)^\s*type\s+(" + _CID + r")")
    _CLASS = re.compile(r"(?m)^\s*class\s+(?:[^=>]*=>\s*)?(" + _CID + r")\b")
    _NATIVE = re.compile(r"(?m)^\s*(?:pure\s+)?native\s+(" + _ID + r")\b")
    _SIG = re.compile(r"(?m)^[ \t]*(" + _ID + r"(?:\s*,\s*" + _ID + r")*)\s*::")
    _DEF = re.compile(r"(?m)^(" + _ID + r")\s+[^=\n]*=(?!=)")
    _DEF0 = re.compile(r"(?m)^(" + _ID + r")\s*=(?!=)")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1).split(".")[-1])
        for m in self._DATA.finditer(clean):
            self._register_class(m.group(1))
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._MODULE.finditer(clean):
            self._add_class(file_id, m.group(1).split(".")[-1],
                            description="frege module")
        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            leaf = src.split(".")[-1]
            self._add_import(file_id, leaf, src, alias=m.group(2))
            if m.group(3):
                for nm in self._split_top_level(m.group(3)):
                    nm = nm.strip().strip("()").split()[0] if nm.strip() else ""
                    if re.match(r"[A-Za-z_]", nm):
                        self._add_import(file_id, nm, src + "." + nm)

        for m in self._DATA.finditer(clean):
            self._add_class(file_id, m.group(1), description="frege data type")
        for m in self._CLASS.finditer(clean):
            self._add_class(file_id, m.group(1), description="frege typeclass")
        for m in self._TYPE.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="type")

        seen = set()
        for m in self._NATIVE.finditer(clean):
            if m.group(1) not in seen:
                self._add_function(file_id, m.group(1), [], [],
                                   description="frege native")
                seen.add(m.group(1))
        for m in self._SIG.finditer(clean):
            for nm in m.group(1).split(","):
                nm = nm.strip()
                if nm and nm not in _KEYWORDS and nm not in seen:
                    self._add_function(file_id, nm, [], [],
                                       description="frege function")
                    seen.add(nm)
        for rx in (self._DEF, self._DEF0):
            for m in rx.finditer(clean):
                nm = m.group(1)
                if nm not in _KEYWORDS and nm not in seen:
                    self._add_function(file_id, nm, [], [],
                                       description="frege binding")
                    seen.add(nm)
