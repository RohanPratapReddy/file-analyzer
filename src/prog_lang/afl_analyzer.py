# AmiBroker Formula Language (.afl) analyzer -- technical-analysis scripting.
#
#     #include <Include.afl>                         -> import
#     #include_once "path/lib.afl"                   -> import
#     function ATR( period )                         -> function
#     {
#         return ...;
#     }
#     procedure PlotBands( price )                   -> function
#     _SECTION_BEGIN("Moving Average");              -> variable (section)
#     fast = Param("Fast", 12, 2, 50);               -> variable
#     Buy = Cross(price, ma);                        -> variable
#
# C-like: comments '//' and '/* */'; strings '"' and "'". No classes.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class AFLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "afl"
    EXTENSIONS = (".afl",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _INCLUDE = re.compile(r'(?im)^\s*#\s*include(?:_once)?\s+[<"]([^>"]+)[>"]')
    _FUNC = re.compile(
        r"(?im)^\s*(?:function|procedure)\s+(" + _ID + r")\s*\(([^)]*)\)"
    )
    _SECTION = re.compile(r'(?i)_SECTION_BEGIN\s*\(\s*"([^"]*)"')
    # top-level simple assignment (skip '==', '<=', '>=', '!=')
    _ASSIGN = re.compile(r"(?m)^\s*(" + _ID + r")\s*=(?![=])")

    def _register_types(self, file_id, text, path):
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, re.split(r"[\\/]", src)[-1], src)

        func_names = set()
        for m in self._FUNC.finditer(clean):
            args = self._afl_args(m.group(2))
            self._add_function(
                file_id, m.group(1), args, [], description="afl function"
            )
            func_names.add(m.group(1).lower())

        seen = set()
        for m in self._SECTION.finditer(clean):
            name = m.group(1).strip()
            if name and name.lower() not in seen:
                seen.add(name.lower())
                self._add_variable(file_id, name, scope="section")
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            low = name.lower()
            if low in seen or low in func_names:
                continue
            seen.add(low)
            self._add_variable(file_id, name, scope="global")

    def _afl_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip().split("=")[0].strip()
            m = re.match(_ID, part)
            if m:
                arg_ids.append(self._add_arg(m.group(0)))
        return arg_ids
