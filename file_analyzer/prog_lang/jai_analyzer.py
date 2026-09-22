# Jai (.jai) analyzer -- Jonathan Blow's systems language.
#
#     #import "Basic";                           -> import
#     #load "player.jai";                        -> import
#     Vector2 :: struct { x: float; y: float; }  -> class (struct)
#     Color :: enum u8 { RED; GREEN; }           -> class (enum)
#     add :: (a: int, b: int) -> int { ... }     -> function (args + output)
#     main :: () { ... }                         -> function
#     PI :: 3.14;                                -> variable (constant)
#     count : int = 0;  /  x := 5;               -> variable
#
# Comments are '//' and (nestable) '/* */'; strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class JaiAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "jai"
    EXTENSIONS = (".jai",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(r'(?m)^\s*#\s*(?:import|load)(?:,\s*\w+)?\s+"([^"]+)"')
    _TYPE = re.compile(
        r"(?m)^\s*(" + _ID + r")\s*::\s*(?:struct|enum_flags|enum|union)\b"
    )
    _PROC = re.compile(r"(?m)^\s*(" + _ID + r")\s*::\s*(?:inline\s+|no_inline\s+)?\(")
    # named constant `X :: <not a proc/type>`
    _CONST = re.compile(
        r"(?m)^\s*(" + _ID + r")\s*::\s*(?!struct\b|enum\b|enum_flags\b|"
        r"union\b|\(|inline\b|no_inline\b)"
    )
    _VAR = re.compile(r"(?m)^\s*(" + _ID + r")\s*:(?!:)=?")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="jai type")

        for m in self._PROC.finditer(clean):
            open_paren = clean.index("(", m.end() - 1)
            args = self._proc_args(clean, open_paren)
            out = self._proc_output(clean, open_paren)
            self._add_function(
                file_id,
                m.group(1),
                args,
                [out] if out is not None else [],
                description="jai procedure",
            )

        for m in self._CONST.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="constant")
        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")

    def _proc_args(self, clean, open_paren):
        end = self._find_matching(clean, open_paren, "(", ")")
        body = clean[open_paren + 1 : end - 1]
        arg_ids = []
        for part in self._split_top_level(body):
            name = part.split(":")[0].strip().lstrip("$").strip()
            if name and re.match(r"[A-Za-z_]", name):
                atype = part.split(":", 1)[1].strip() if ":" in part else None
                arg_ids.append(self._add_arg(name, atype))
        return arg_ids

    def _proc_output(self, clean, open_paren):
        end = self._find_matching(clean, open_paren, "(", ")")
        tail = clean[end:]
        m = re.match(r"\s*->\s*([^\{;]+)", tail)
        if m:
            rt = m.group(1).strip().rstrip("{").strip()
            if rt:
                return self._add_output(rt)
        return None
