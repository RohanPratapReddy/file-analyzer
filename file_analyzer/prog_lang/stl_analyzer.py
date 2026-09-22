# Siemens STEP 7 STL / AWL (.awl) analyzer -- PLC statement-list export format.
#
#     FUNCTION_BLOCK "Motor"                        -> class
#     FUNCTION FC10 : INT                           -> function (+ output)
#     ORGANIZATION_BLOCK "Main"                     -> function
#     DATA_BLOCK "Instance"                         -> class
#     TYPE "MyUDT"                                  -> class
#         VAR_INPUT
#             Speed : INT;                          -> variable
#         END_VAR
#         VAR
#             Running : BOOL := FALSE;              -> variable
#         END_VAR
#     END_FUNCTION_BLOCK
#
# Comments '//' line and '(* *)' block; strings use '"' and "'".
# Names are quoted "Symbolic" or absolute FB10/FC1/DB5/OB1. Case-insensitive kw.
import re

from .regex_base import RegexCodeAnalyzer

_NAME = r'(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_]*)'
_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class STLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "stl"
    EXTENSIONS = (".awl",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ()  # keep quoted symbolic names intact

    _CLASS = re.compile(
        r"(?im)^\s*(FUNCTION_BLOCK|DATA_BLOCK|TYPE|UDT)\s+" r"(" + _NAME + r")"
    )
    _FUNC = re.compile(
        r"(?im)^\s*(FUNCTION|ORGANIZATION_BLOCK)\s+"
        r"(" + _NAME + r")\s*(?::\s*(" + _ID + r"))?"
    )
    # a declaration line inside a VAR_* section:  `name : TYPE ...;`
    _DECL = re.compile(r"(?im)^\s*(" + _ID + r")\s*:\s*[^;]+;")
    _VARSECT = re.compile(
        r"(?im)^\s*(VAR(?:_INPUT|_OUTPUT|_IN_OUT|_TEMP|" r"_GLOBAL|_STAT)?)\b"
    )
    _ENDVAR = re.compile(r"(?im)^\s*END_VAR\b")

    @staticmethod
    def _clean_name(raw):
        return raw.strip().strip('"')

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(self._clean_name(m.group(2)))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._CLASS.finditer(clean):
            kind = m.group(1).upper()
            desc = {
                "FUNCTION_BLOCK": "stl fb",
                "DATA_BLOCK": "stl db",
                "TYPE": "stl udt",
                "UDT": "stl udt",
            }.get(kind, "stl block")
            self._add_class(file_id, self._clean_name(m.group(2)), description=desc)
        for m in self._FUNC.finditer(clean):
            outs = []
            if m.group(3) and m.group(3).upper() != "VOID":
                outs = [self._add_output(m.group(3))]
            self._add_function(
                file_id,
                self._clean_name(m.group(2)),
                [],
                outs,
                description="stl function",
            )

        # variables live only inside VAR_* .. END_VAR blocks
        seen = set()
        in_var = False
        for line in clean.splitlines():
            if self._VARSECT.match(line):
                in_var = True
                continue
            if self._ENDVAR.match(line):
                in_var = False
                continue
            if not in_var:
                continue
            m = self._DECL.match(line)
            if m:
                name = m.group(1)
                if name.upper() in ("STRUCT", "END_STRUCT") or name in seen:
                    continue
                seen.add(name)
                self._add_variable(file_id, name, scope="block")
