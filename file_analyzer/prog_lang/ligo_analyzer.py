# LIGO (.ligo) PascaLIGO Tezos smart-contract analyzer.
#
# Real parser for PascaLIGO:
#
#     type storage is int                                 -> class (type)
#     type parameter is Increment of int | Reset          -> class
#     const initial : int = 0                             -> variable
#     function add (const s : int; const n : int) : int is -> function (params)
#         block { skip } with s + n
#     recursive function loop (const i : int) : int is ...
#     module Ops is ...                                   -> class (module)
#
# Comments are '//', '(* *)' and '/* */'.
import re

from .regex_base import RegexCodeAnalyzer


class LigoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ligo"
    EXTENSIONS = (".ligo",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("(*", "*)"), ("/*", "*/"))
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(
        r"^[ \t]*(?:recursive\s+)?function\s+([A-Za-z_]\w*)\s*" r"\(([^)]*)\)",
        re.MULTILINE,
    )
    _CONST = re.compile(r"^[ \t]*(const|var)\s+([A-Za-z_]\w*)\s*:", re.MULTILINE)
    _TYPE = re.compile(r"^[ \t]*type\s+([A-Za-z_]\w*)\s+is\b", re.MULTILINE)
    _MODULE = re.compile(r"^[ \t]*module\s+([A-Za-z_]\w*)\s+is\b", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="ligo type")
        for m in self._MODULE.finditer(clean):
            self._add_class(file_id, m.group(1), description="ligo module")

        for m in self._CONST.finditer(clean):
            self._add_variable(file_id, m.group(2), m.group(1))

        for m in self._FUNC.finditer(clean):
            arg_ids = []
            for part in re.split(r";", m.group(2)):
                pm = re.search(r"(?:const|var)?\s*([A-Za-z_]\w*)\s*:", part)
                if pm:
                    arg_ids.append(self._add_arg(pm.group(1)))
            self._add_function(
                file_id, m.group(1), arg_ids, [], description="ligo function"
            )
