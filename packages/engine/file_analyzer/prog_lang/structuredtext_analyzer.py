# IEC 61131-3 Structured Text (.st, .scl) analyzer  (PLC programming language;
# .scl is Siemens SCL, a Structured-Text dialect).
#
# Real parser for Structured Text:
#
#     FUNCTION_BLOCK FB_Motor                       -> class
#         VAR_INPUT
#             Enable : BOOL;                        -> variable (declaration)
#             Speed  : INT := 0;                    -> variable
#         END_VAR
#         METHOD Start : BOOL                       -> function
#     END_FUNCTION_BLOCK
#     FUNCTION Add : INT                            -> function
#         VAR_INPUT a, b : INT; END_VAR
#     END_FUNCTION
#     PROGRAM Main                                  -> function
#     TYPE Point : STRUCT x : REAL; y : REAL; END_STRUCT END_TYPE  -> class
#
# Keywords are case-insensitive.  Comments are '(* *)' and '//'.
import re

from .regex_base import RegexCodeAnalyzer

_ML = re.MULTILINE | re.IGNORECASE


class StructuredTextAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "structured_text"
    EXTENSIONS = (".st", ".scl")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("(*", "*)"), ("/*", "*/"))
    STRING_DELIMS = ("'", '"')

    _FB = re.compile(r"^[ \t]*FUNCTION_BLOCK\s+([A-Za-z_]\w*)", _ML)
    _FUNC = re.compile(r"^[ \t]*FUNCTION\s+([A-Za-z_]\w*)", _ML)
    _PROGRAM = re.compile(r"^[ \t]*PROGRAM\s+([A-Za-z_]\w*)", _ML)
    _METHOD = re.compile(r"^[ \t]*METHOD\s+([A-Za-z_]\w*)", _ML)
    _TYPE = re.compile(r"^[ \t]*TYPE\s+([A-Za-z_]\w*)", _ML)
    _NAMED_STRUCT = re.compile(r"^[ \t]*([A-Za-z_]\w*)\s*:\s*STRUCT\b", _ML)
    _VAR_BLOCK = re.compile(
        r"\bVAR(?:_INPUT|_OUTPUT|_IN_OUT|_TEMP|_GLOBAL|_STAT|_EXTERNAL|"
        r"_CONSTANT|_ACCESS)?\b(.*?)\bEND_VAR\b",
        re.DOTALL | re.IGNORECASE,
    )
    _DECL = re.compile(
        r"^[ \t]*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:\s*([^;]+);", _ML
    )

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._FB.finditer(clean):
            self._register_class(m.group(1))
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))
        for m in self._NAMED_STRUCT.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._FB.finditer(clean):
            self._add_class(file_id, m.group(1), description="st function_block")
        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="st type")
        for m in self._NAMED_STRUCT.finditer(clean):
            self._add_class(file_id, m.group(1), description="st struct")

        for m in self._FUNC.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], description="st function")
        for m in self._PROGRAM.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], description="st program")
        for m in self._METHOD.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], description="st method")

        # variable declarations live inside VAR ... END_VAR regions
        for blk in self._VAR_BLOCK.finditer(clean):
            body = blk.group(1)
            for dm in self._DECL.finditer(body):
                ty = dm.group(2).strip()
                for nm in dm.group(1).split(","):
                    nm = nm.strip()
                    if nm:
                        self._add_variable(file_id, nm, ty)
