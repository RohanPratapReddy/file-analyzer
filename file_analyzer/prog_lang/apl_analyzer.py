# APL (.apl) analyzer.
#
# Real parser for APL source (Dyalog / GNU APL flavour):
#
#     name←{ ... }                         -> function (dfn, implicit ⍺ ⍵)
#     ∇ R←name arg  ... ∇                  -> function (tradfn, result/args parsed)
#     ∇ larg name rarg                     -> function (dyadic tradfn)
#     name←value                            -> variable (assignment)
#     :Class Foo   ... :EndClass            -> class
#     :Namespace N ... :EndNamespace        -> class
#     :Interface I ... :EndInterface        -> class
#     :Field Public x                       -> variable (class field)
#     :Include Base                         -> import
#     )LOAD ws   /  )COPY ws obj            -> import (system commands)
#
# Comment glyph is ⍝ (to end of line); strings use single quotes.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_∆⍙][A-Za-z0-9_∆⍙]*"  # letters, ∆ (U+2206), ⍙ (U+2359)


class AplAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "apl"
    EXTENSIONS = (".apl",)
    LINE_COMMENTS = ("⍝",)  # ⍝
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'",)

    _DFN = re.compile(r"^[ \t]*(" + _ID + r")\s*←\s*\{", re.MULTILINE)  # name←{
    _ASSIGN = re.compile(r"^[ \t]*(" + _ID + r")\s*←(?!\s*\{)", re.MULTILINE)
    _TRADFN = re.compile(r"^[ \t]*∇\s*([^\n]*)", re.MULTILINE)  # ∇ header
    _CLASS = re.compile(
        r"^[ \t]*:(Class|Namespace|Interface)\b[ \t]+(" + _ID + r")",
        re.MULTILINE | re.IGNORECASE,
    )
    _FIELD = re.compile(r"^[ \t]*:Field\b([^\n←]*)", re.MULTILINE | re.IGNORECASE)
    _INCLUDE = re.compile(
        r"^[ \t]*:Include\b[ \t]+(" + _ID + r")", re.MULTILINE | re.IGNORECASE
    )
    _SYSLOAD = re.compile(
        r"^[ \t]*\)(?:LOAD|COPY)\s+(\S+)", re.MULTILINE | re.IGNORECASE
    )

    _ID_RX = re.compile(_ID)

    def _tradfn_name(self, header):
        """Parse an APL tradfn header line into (name, [arg names])."""
        h = header.split(";")[0]  # drop ;locals
        if "←" in h:  # drop result assignment R←
            h = h.split("←", 1)[1]
        ids = self._ID_RX.findall(h)
        if not ids:
            return None, []
        if len(ids) >= 3:  # larg name rarg (dyadic)
            return ids[1], [ids[0], ids[2]]
        if len(ids) == 2:  # name arg (monadic)
            return ids[0], [ids[1]]
        return ids[0], []  # niladic

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))
        for m in self._SYSLOAD.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.replace("\\", "/").split("/")[-1], src)

        for m in self._CLASS.finditer(clean):
            kind = m.group(1).lower()
            self._add_class(file_id, m.group(2), description=f"apl {kind}")

        dfn_pos = set()
        for m in self._DFN.finditer(clean):
            dfn_pos.add(m.start())
            self._add_function(file_id, m.group(1), [], [], description="apl dfn")

        for m in self._TRADFN.finditer(clean):
            name, args = self._tradfn_name(m.group(1))
            if not name:
                continue
            arg_ids = [self._add_arg(a) for a in args]
            self._add_function(file_id, name, arg_ids, [], description="apl tradfn")

        for m in self._FIELD.finditer(clean):
            ids = self._ID_RX.findall(m.group(1))
            # last identifier after the access modifiers is the field name
            mods = {"public", "private", "shared", "instance", "readonly"}
            names = [i for i in ids if i.lower() not in mods]
            if names:
                self._add_variable(file_id, names[-1], scope="class")

        for m in self._ASSIGN.finditer(clean):
            if m.start() in dfn_pos:
                continue
            self._add_variable(file_id, m.group(1))
