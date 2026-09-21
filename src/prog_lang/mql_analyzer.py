# MQL4 / MQL5 (.mq4, .mq5) analyzer  (MetaTrader trading language, C++-like).
#
# Real parser for MetaQuotes Language:
#
#     #include <Trade/Trade.mqh>                    -> import
#     #include "MyLib.mqh"                          -> import
#     #import "kernel32.dll"                         -> import
#     #property copyright "..."                     -> variable
#     #define MAGIC 12345                            -> variable
#     input int FastMA = 12;                         -> variable
#     extern double Lots = 0.1;                       -> variable
#     sinput string Symbols = "EURUSD";               -> variable
#     class CExpert : public CObject { ... }          -> class
#     struct Trade { ... }                            -> class
#     enum ENUM_STATE { ... }                         -> class
#     interface IStrategy { ... }                     -> class
#     int OnInit() { ... }                            -> function
#     double CalcLots(double risk) { ... }            -> function
#     void CExpert::Process(void) { ... }             -> function (method)
#
# Comments are '//' and '/* */'.
import re

from .regex_base import RegexCodeAnalyzer

_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "else",
    "do",
    "case",
    "sizeof",
    "new",
    "delete",
    "catch",
    "typedef",
    "template",
}


class MQLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "mql"
    EXTENSIONS = (".mq4", ".mq5")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _INCLUDE = re.compile(r'^[ \t]*#\s*include\s+[<"]([^>"]+)[>"]', re.MULTILINE)
    _IMPORT = re.compile(r'^[ \t]*#\s*import\s+"([^"]+)"', re.MULTILINE)
    _PROPERTY = re.compile(r"^[ \t]*#\s*property\s+([A-Za-z_]\w*)", re.MULTILINE)
    _DEFINE = re.compile(r"^[ \t]*#\s*define\s+([A-Za-z_]\w*)", re.MULTILINE)
    _INPUT = re.compile(
        r"^[ \t]*(?:input|sinput|extern)\s+(?:const\s+)?"
        r"[A-Za-z_][\w:]*\s+([A-Za-z_]\w*)",
        re.MULTILINE,
    )
    _CLASS = re.compile(
        r"^[ \t]*(?:class|struct|interface|union)\s+([A-Za-z_]\w*)", re.MULTILINE
    )
    _ENUM = re.compile(r"^[ \t]*enum\s+([A-Za-z_]\w*)", re.MULTILINE)
    _FUNC = re.compile(
        r"^[ \t]*(?:static\s+|virtual\s+|const\s+)*"
        r"[A-Za-z_][\w:<>\*&\s]*?[\s\*&:]([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*"
        r"(?:const\s*)?\{",
        re.MULTILINE,
    )

    def _args(self, blob):
        ids = []
        for part in self._split_top_level(blob or ""):
            if not part.strip() or part.strip() == "void":
                continue
            nm = re.search(r"([A-Za-z_]\w*)\s*(?:=|\[|$)", part.split("=")[0])
            if nm:
                ids.append(self._add_arg(nm.group(1), part.strip()))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            hdr = m.group(1)
            self._add_import(file_id, hdr.replace("\\", "/").split("/")[-1], hdr)
        for m in self._IMPORT.finditer(clean):
            self._add_import(file_id, m.group(1).split("\\")[-1], m.group(1))

        for m in self._PROPERTY.finditer(clean):
            self._add_variable(file_id, m.group(1), "property")
        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), "macro")
        for m in self._INPUT.finditer(clean):
            self._add_variable(file_id, m.group(1), "input")

        for m in self._CLASS.finditer(clean):
            self._add_class(file_id, m.group(1), description="mql class")
        for m in self._ENUM.finditer(clean):
            self._add_class(file_id, m.group(1), description="mql enum")

        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in _KEYWORDS:
                continue
            self._add_function(
                file_id, name, self._args(m.group(2)), [], description="mql function"
            )
