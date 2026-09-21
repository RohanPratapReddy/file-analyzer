# Michelson (.michelson / .tz) Tezos smart-contract stack-language analyzer.
#
# Real parser for Michelson contracts:
#
#     parameter (or (int %incr) (int %decr)) ;   -> variable (parameter type)
#     storage   int ;                            -> variable (storage type)
#     code { CAR ; PUSH int 1 ; ADD ; NIL operation ; PAIR }  -> function "code"
#     view "get" int int { ... } ;               -> function (on-chain view)
#
# The three top-level sections `parameter` / `storage` are the contract's type
# declarations (variables); `code` and each named `view` are executable blocks
# (functions).  Comments are '#', '/* */' and '(* *)'.
import re

from .regex_base import RegexCodeAnalyzer


class MichelsonAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "michelson"
    EXTENSIONS = (".michelson", ".tz")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("/*", "*/"), ("(*", "*)"))
    STRING_DELIMS = ('"',)

    _PARAM = re.compile(r"(?<![\w%])(parameter|storage)\b([^;]*);", re.DOTALL)
    _CODE = re.compile(r"(?<![\w%])code\b\s*\{", re.DOTALL)
    _VIEW = re.compile(r'(?<![\w%])view\b\s*"([^"]+)"', re.DOTALL)

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._PARAM.finditer(clean):
            self._add_variable(file_id, m.group(1), " ".join(m.group(2).split())[:80])

        for m in self._VIEW.finditer(clean):
            self._add_function(
                file_id, m.group(1), [], [], description="michelson view"
            )

        if self._CODE.search(clean):
            self._add_function(file_id, "code", [], [], description="michelson code")
