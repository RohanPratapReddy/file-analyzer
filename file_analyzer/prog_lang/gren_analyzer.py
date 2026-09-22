# Gren (.gren) analyzer -- a pure-functional Elm derivative.
#
# Gren shares Elm's surface syntax.  Type annotations use a SINGLE colon
# (``::`` is the array/list cons operator, not an annotation):
#
#     module My.Mod exposing (a, b)             -> class (module)
#     import Foo.Bar as B exposing (x, y)       -> import (+ aliased + names)
#     type Shape = Circle | Square              -> class (custom type)
#     type alias Point = { x : Int }            -> class (record alias)
#     port send : String -> Cmd msg             -> function (port)
#     area : Shape -> Float                      -> function (annotation)
#     area shape = ...                           -> function (definition, deduped)
#     main = ...                                 -> function (value)
#
# Comments are '--' and '{- -}'; strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[a-z_][A-Za-z0-9_']*"
_CID = r"[A-Z][A-Za-z0-9_']*"
_QUAL = r"[A-Za-z_][A-Za-z0-9_'.]*"
_KEYWORDS = {
    "module",
    "import",
    "type",
    "alias",
    "port",
    "exposing",
    "as",
    "where",
    "let",
    "in",
    "case",
    "of",
    "if",
    "then",
    "else",
    "effect",
    "infix",
    "infixl",
    "infixr",
    "hiding",
    "command",
    "subscription",
}


class GrenAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "gren"
    EXTENSIONS = (".gren",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = (("{-", "-}"),)
    STRING_DELIMS = ('"',)

    _MODULE = re.compile(r"(?m)^\s*(?:port\s+|effect\s+)?module\s+(" + _QUAL + r")")
    _IMPORT = re.compile(
        r"(?m)^\s*import\s+(" + _QUAL + r")(?:\s+as\s+(" + _CID + r"))?"
        r"(?:\s+exposing\s*\(([^)]*)\))?"
    )
    _TYPE = re.compile(r"(?m)^\s*type\s+(?:alias\s+)?(" + _CID + r")")
    _PORT = re.compile(r"(?m)^\s*port\s+(" + _ID + r")\s*:")
    _SIG = re.compile(r"(?m)^(" + _ID + r")\s*:(?!:)")
    _DEF = re.compile(r"(?m)^(" + _ID + r")\b[^=\n]*=(?!=)")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1).split(".")[-1])
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._MODULE.finditer(clean):
            self._add_class(
                file_id, m.group(1).split(".")[-1], description="gren module"
            )
        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split(".")[-1], src, alias=m.group(2))
            if m.group(3):
                for nm in m.group(3).split(","):
                    nm = nm.strip().strip("()").split()[0] if nm.strip() else ""
                    nm = nm.split("(")[0].strip()
                    if nm and re.match(r"[A-Za-z_]", nm) and nm != "..":
                        self._add_import(file_id, nm, src + "." + nm)

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="gren type")

        seen = set()
        for m in self._PORT.finditer(clean):
            nm = m.group(1)
            if nm not in _KEYWORDS and nm not in seen:
                self._add_function(file_id, nm, [], [], description="gren port")
                seen.add(nm)
        for m in self._SIG.finditer(clean):
            nm = m.group(1)
            if nm not in _KEYWORDS and nm not in seen:
                self._add_function(file_id, nm, [], [], description="gren function")
                seen.add(nm)
        for m in self._DEF.finditer(clean):
            nm = m.group(1)
            if nm not in _KEYWORDS and nm not in seen:
                self._add_function(file_id, nm, [], [], description="gren binding")
                seen.add(nm)
