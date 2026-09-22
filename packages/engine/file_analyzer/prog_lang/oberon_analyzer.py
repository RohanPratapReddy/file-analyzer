# Oberon / Oberon-2 (.oberon) analyzer.
#
# Real parser for Wirth's Oberon family:
#
#     MODULE Draw;                         -> class (the module)
#     IMPORT Files, Out := Texts;          -> import (with := alias)
#     PROCEDURE Draw* (x, y: INTEGER);     -> function ('*' export mark)
#     PROCEDURE (r: Rectangle) Draw*;      -> type-bound method
#     TYPE Node* = RECORD next: NodePtr END; -> class (record)
#     TYPE Tree = POINTER TO RECORD ... END; -> class
#     CONST Max* = 100;                    -> variable
#     VAR count, top: INTEGER;             -> variables
#
# Comments are nested '(* ... *)'; strings use '"'.  Case-sensitive; a trailing
# '*' (or '-') on an identifier is the export mark and is stripped.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_]*"
_MARK = r"[*-]?"  # export / read-only mark


class OberonAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "oberon"
    EXTENSIONS = (".oberon",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _MODULE = re.compile(r"\bMODULE\s+(" + _ID + r")")
    _IMPORT = re.compile(r"\bIMPORT\s+([^;]+);")
    # optional "(recv: Type)" receiver, then name, then export mark, then '('
    _PROC = re.compile(
        r"\bPROCEDURE\s*(?:\(\s*" + _ID + r"\s*:\s*" + _ID + r"\s*\)\s*)?"
        r"(" + _ID + r")" + _MARK + r"\s*(\([^)]*\))?"
    )
    _RECTYPE = re.compile(
        r"\b(" + _ID + r")" + _MARK + r"\s*=\s*(?:POINTER\s+TO\s+)?RECORD\b"
    )
    _CONST = re.compile(
        r"^[ \t]*(?:CONST[ \t]+)?(" + _ID + r")" + _MARK + r"\s*=\s*[^=;]", re.MULTILINE
    )
    _VARLINE = re.compile(
        r"^[ \t]*(?:VAR[ \t]+)?("
        + _ID
        + _MARK
        + r"(?:\s*,\s*"
        + _ID
        + _MARK
        + r")*)\s*:\s*[^;]+",
        re.MULTILINE,
    )

    @staticmethod
    def _clean_id(tok):
        return re.sub(r"[*-]$", "", tok.strip())

    def _proc_args(self, paren):
        if not paren:
            return []
        inner = paren[1:-1]
        ids = []
        for grp in self._split_top_level(inner, sep=";"):
            if ":" in grp:
                names, _, typ = grp.partition(":")
                typ = typ.strip()
            else:
                names, typ = grp, None
            names = re.sub(r"(?i)\bVAR\b", "", names)
            for nm in names.split(","):
                cid = self._clean_id(nm)
                m = re.match(_ID, cid)
                if m:
                    ids.append(self._add_arg(m.group(0), arg_type=typ))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1))
        for m in self._RECTYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            for chunk in self._split_top_level(m.group(1)):
                # "Files" | "Out := Texts"
                if ":=" in chunk:
                    alias, _, mod = chunk.partition(":=")
                    alias, mod = alias.strip(), mod.strip()
                else:
                    alias, mod = None, chunk.strip()
                nm = re.match(_ID, mod)
                if nm:
                    self._add_import(
                        file_id, (alias or nm.group(0)), nm.group(0), alias
                    )

        cls_id = None
        for m in self._MODULE.finditer(clean):
            cls_id = self._add_class(file_id, m.group(1), description="oberon module")
        for m in self._RECTYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="oberon record")

        for m in self._PROC.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._proc_args(m.group(2)),
                [],
                class_id=cls_id,
                description="oberon procedure",
            )

        for m in self._CONST.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")
        for m in self._VARLINE.finditer(clean):
            for nm in m.group(1).split(","):
                cid = self._clean_id(nm)
                if cid:
                    self._add_variable(file_id, cid, scope="module")
