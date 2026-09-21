# Io (.io) analyzer  (prototype-based language).
#
# Real parser for Io:
#
#     Account := Object clone              -> class (named prototype, parent Object)
#     Account := Object clone do( ... )     -> class
#     deposit := method(amount, ...)        -> function (slot bound to a method)
#     total := 0                            -> variable (data slot)
#     setSlot("name", value)                -> variable
#     doFile("other.io")                    -> import
#     doRelativeFile("lib/util.io")         -> import
#
# Comments are '//' and '#' (line) and '/* */' (block); strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class IoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "io"
    EXTENSIONS = (".io",)
    LINE_COMMENTS = ("//", "#")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _PROTO = re.compile(
        r"^[ \t]*(" + _ID + r")\s*:?=\s*(" + _ID + r")\s+clone\b", re.MULTILINE
    )
    _METHOD = re.compile(r"^[ \t]*(" + _ID + r")\s*:?=\s*method\s*\(", re.MULTILINE)
    _SETSLOT = re.compile(r'\bsetSlot\(\s*"(' + _ID + r')"', re.MULTILINE)
    _ASSIGN = re.compile(
        r"^[ \t]*(" + _ID + r")\s*:?=\s*(?!method\b)(?:(" + _ID + r")\s+clone\b)?",
        re.MULTILINE,
    )
    _DOFILE = re.compile(r'\b(?:doFile|doRelativeFile|ifFileExists)\(\s*"([^"]+)"')

    def _method_args(self, blob):
        """Io method(...) leading identifiers are the parameter names; the final
        expression is the body.  Collect leading bare-identifier parts."""
        ids = []
        parts = self._split_top_level(blob)
        for p in parts[:-1] if len(parts) > 1 else []:
            if re.fullmatch(_ID, p.strip()):
                ids.append(self._add_arg(p.strip()))
            else:
                break
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._PROTO.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._DOFILE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.replace("\\", "/").split("/")[-1], src)

        proto_pos = set()
        for m in self._PROTO.finditer(clean):
            proto_pos.add(m.start())
            self._add_class(file_id, m.group(1), description="io prototype")

        method_pos = set()
        for m in self._METHOD.finditer(clean):
            method_pos.add(m.start())
            lp = m.end() - 1
            rp = self._find_matching(clean, lp, "(", ")")
            arg_ids = self._method_args(clean[lp + 1 : rp - 1])
            self._add_function(
                file_id, m.group(1), arg_ids, [], description="io method"
            )

        for m in self._SETSLOT.finditer(clean):
            self._add_variable(file_id, m.group(1))

        for m in self._ASSIGN.finditer(clean):
            if m.start() in proto_pos or m.start() in method_pos:
                continue
            self._add_variable(file_id, m.group(1))
