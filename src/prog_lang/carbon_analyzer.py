# Carbon (.carbon) analyzer -- Google's experimental C++ successor.
#
#     package Geometry library "shapes" api;    -> class (package/module)
#     import Math library "core";                -> import
#     fn Add(a: i32, b: i32) -> i32 { ... }      -> function (args + output)
#     class Point { ... }                        -> class
#     base class Shape { ... }                   -> class
#     interface Drawable { ... }                 -> class
#     choice Result { Ok, Err }                  -> class (variant)
#     constraint Comparable { ... }              -> class
#     var x: i32 = 0;                            -> variable
#     let pi: f64 = 3.14;                        -> variable
#     alias Int = i32;                            -> variable
#
# Comments are '//'; strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class CarbonAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "carbon"
    EXTENSIONS = (".carbon",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _PACKAGE = re.compile(r"(?m)^\s*package\s+(" + _ID + r")")
    _IMPORT = re.compile(r"(?m)^\s*import\s+(" + _ID + r")")
    _FN = re.compile(
        r"(?m)^\s*(?:private\s+|protected\s+|virtual\s+|abstract\s+|"
        r"final\s+|default\s+)*fn\s+(" + _ID + r")\s*(?:\[[^\]]*\])?\s*\("
    )
    _CLASS = re.compile(
        r"(?m)^\s*(?:(?:private|protected|abstract|base|final|"
        r"extern|virtual)\s+)*class\s+(" + _ID + r")"
    )
    _INTERFACE = re.compile(r"(?m)^\s*(?:private\s+)?interface\s+(" + _ID + r")")
    _CHOICE = re.compile(r"(?m)^\s*(?:private\s+)?choice\s+(" + _ID + r")")
    _CONSTRAINT = re.compile(r"(?m)^\s*(?:private\s+)?constraint\s+(" + _ID + r")")
    _VAR = re.compile(
        r"(?m)^\s*(?:private\s+|protected\s+)?(?:var|let)\s+(" + _ID + r")\s*:"
    )
    _ALIAS = re.compile(r"(?m)^\s*(?:private\s+)?alias\s+(" + _ID + r")\s*=")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (
            self._PACKAGE,
            self._CLASS,
            self._INTERFACE,
            self._CHOICE,
            self._CONSTRAINT,
        ):
            for m in rx.finditer(clean):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))
        for m in self._PACKAGE.finditer(clean):
            self._add_class(file_id, m.group(1), description="carbon package")
        for m in self._CLASS.finditer(clean):
            self._add_class(file_id, m.group(1), description="carbon class")
        for m in self._INTERFACE.finditer(clean):
            self._add_class(file_id, m.group(1), description="carbon interface")
        for m in self._CHOICE.finditer(clean):
            self._add_class(file_id, m.group(1), description="carbon choice")
        for m in self._CONSTRAINT.finditer(clean):
            self._add_class(file_id, m.group(1), description="carbon constraint")

        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")
        for m in self._ALIAS.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="alias")

        for m in self._FN.finditer(clean):
            args = self._fn_args(clean, m.end() - 1)
            out = self._fn_output(clean, m.end())
            self._add_function(
                file_id,
                m.group(1),
                args,
                [out] if out is not None else [],
                description="carbon function",
            )

    def _fn_args(self, clean, open_paren):
        end = self._find_matching(clean, open_paren, "(", ")")
        body = clean[open_paren + 1 : end - 1]
        arg_ids = []
        for part in self._split_top_level(body):
            name = part.split(":")[0].strip()
            if name and re.match(r"[A-Za-z_]", name):
                atype = part.split(":", 1)[1].strip() if ":" in part else None
                arg_ids.append(self._add_arg(name, atype))
        return arg_ids

    def _fn_output(self, clean, after_name):
        # find the arg list, then look for `-> Type` before the body `{` or `;`
        open_paren = clean.find("(", after_name - 1)
        if open_paren == -1:
            return None
        end = self._find_matching(clean, open_paren, "(", ")")
        tail = clean[end:]
        m = re.match(r"\s*->\s*([^\{;]+)", tail)
        if m:
            return self._add_output(m.group(1).strip())
        return None
