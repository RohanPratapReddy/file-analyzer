# Progress OpenEdge ABL / WebSpeed (.progress, .w) analyzer -- 4GL business lang.
#
#     USING com.acme.Logger.                        -> import
#     {include/header.i}                            -> import (include ref)
#     CLASS acme.Service INHERITS Base IMPLEMENTS I: -> class (+ parent)
#     INTERFACE acme.IService:                       -> class
#         DEFINE PUBLIC PROPERTY Name AS CHAR ...    -> variable
#         METHOD PUBLIC INTEGER Add(INPUT a AS INT): -> function (+ output)
#     END CLASS.
#     PROCEDURE doWork:                              -> function
#     END PROCEDURE.
#     FUNCTION calc RETURNS DECIMAL (INPUT n AS INT):-> function (+ output)
#     DEFINE VARIABLE i AS INTEGER NO-UNDO.          -> variable
#     DEFINE INPUT PARAMETER p AS CHARACTER.         -> variable
#
# Case-insensitive keywords. Comments '/* */' (nestable) and '//'; strings "'".
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_QUAL = r"[A-Za-z_][A-Za-z0-9_.]*"  # dotted class path


class ProgressAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "progress"
    EXTENSIONS = (".progress", ".w")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _USING = re.compile(r"(?im)^\s*USING\s+(" + _QUAL + r"(?:\.\*)?)\s*\.")
    _INCLUDE = re.compile(r"\{([A-Za-z0-9_./\\-]+\.(?:i|w|p))\b")
    _CLASS = re.compile(
        r"(?im)^\s*CLASS\s+(" + _QUAL + r")"
        r"(?:\s+INHERITS\s+(" + _QUAL + r"))?"
        r"(?:\s+IMPLEMENTS\s+([\w.,\s]+?))?"
        r"(?:\s+(?:FINAL|ABSTRACT|SERIALIZABLE|WIDGET-POOL))*\s*:"
    )
    _INTERFACE = re.compile(
        r"(?im)^\s*INTERFACE\s+(" + _QUAL + r")" r"(?:\s+INHERITS\s+([\w.,\s]+?))?\s*:"
    )
    _METHOD = re.compile(
        r"(?im)^\s*METHOD\s+"
        r"(?:(?:PUBLIC|PRIVATE|PROTECTED|STATIC|ABSTRACT|"
        r"OVERRIDE|FINAL)\s+)*"
        r"(" + _QUAL + r")\s+(" + _ID + r")\s*\(([^)]*)\)"
    )
    _PROCEDURE = re.compile(r"(?im)^\s*PROCEDURE\s+(" + _ID + r")")
    _FUNCTION = re.compile(
        r"(?im)^\s*FUNCTION\s+(" + _ID + r")\s+RETURNS?\s+"
        r"(" + _QUAL + r"(?:\s+EXTENT)?)\s*(\([^)]*\))?"
    )
    _DEFVAR = re.compile(
        r"(?im)^\s*DEFINE\s+"
        r"(?:(?:NEW\s+|GLOBAL\s+|SHARED\s+|PUBLIC\s+|"
        r"PRIVATE\s+|PROTECTED\s+|STATIC\s+)*)"
        r"(?:VARIABLE|PROPERTY|"
        r"(?:INPUT|OUTPUT|INPUT-OUTPUT|RETURN)?\s*PARAMETER)\s+"
        r"(" + _ID + r")\b"
    )

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1).split(".")[-1])
        for m in self._INTERFACE.finditer(clean):
            self._register_class(m.group(1).split(".")[-1])

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._USING.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split(".")[-1], src)
        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, re.split(r"[\\/]", src)[-1], src)

        cls_id = None
        for m in self._CLASS.finditer(clean):
            name = m.group(1).split(".")[-1]
            cls_id = self._register_class(name)
            pids = []
            if m.group(2):
                pids.append(self._register_class(m.group(2).split(".")[-1]))
            if m.group(3):
                for p in m.group(3).split(","):
                    p = p.strip()
                    if p:
                        pids.append(self._register_class(p.split(".")[-1]))
            self._add_class(
                file_id, name, description="abl class", parent_ids=pids or None
            )
        for m in self._INTERFACE.finditer(clean):
            name = m.group(1).split(".")[-1]
            cid = self._register_class(name)
            if cls_id is None:
                cls_id = cid
            self._add_class(file_id, name, description="abl interface")

        for m in self._METHOD.finditer(clean):
            args = self._abl_args(m.group(3))
            ret = m.group(1).upper()
            outs = [] if ret == "VOID" else [self._add_output(m.group(1))]
            self._add_function(
                file_id,
                m.group(2),
                args,
                outs,
                class_id=cls_id,
                description="abl method",
            )
        for m in self._PROCEDURE.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                [],
                [],
                class_id=cls_id,
                description="abl procedure",
            )
        for m in self._FUNCTION.finditer(clean):
            args = self._abl_args(m.group(3)[1:-1] if m.group(3) else "")
            outs = [self._add_output(m.group(2).split()[0])]
            self._add_function(
                file_id,
                m.group(1),
                args,
                outs,
                class_id=cls_id,
                description="abl function",
            )

        seen = set()
        for m in self._DEFVAR.finditer(clean):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                self._add_variable(file_id, name, scope="module")

    def _abl_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip()
            if not part:
                continue
            # `INPUT p AS INTEGER` / `OUTPUT TABLE FOR tt` / `p AS CHAR`
            toks = part.split()
            name, atype = None, None
            if "AS" in [t.upper() for t in toks]:
                idx = [t.upper() for t in toks].index("AS")
                if idx >= 1:
                    name = toks[idx - 1]
                if idx + 1 < len(toks):
                    atype = toks[idx + 1]
            else:
                # `INPUT TABLE FOR tt` etc -> last token is the name
                mm = re.findall(_ID, part)
                if mm:
                    name = mm[-1]
            if name and re.match(_ID + r"$", name):
                arg_ids.append(self._add_arg(name, atype))
        return arg_ids
