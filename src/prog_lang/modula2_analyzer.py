# Modula-2 (.mod / .def) analyzer.
#
# Real parser for Modula-2 (Wirth's language, ISO / PIM dialects):
#
#     DEFINITION MODULE Stack;             -> class (the module)
#     IMPLEMENTATION MODULE Stack;         -> class
#     MODULE Main;                         -> class
#     FROM Storage IMPORT ALLOCATE, DEALLOCATE;  -> import (each symbol)
#     IMPORT Terminal, InOut;              -> import (each module)
#     PROCEDURE Push(VAR s: Stack; x: INTEGER); -> function (with args)
#     CONST Max = 100;                     -> variable
#     VAR top, count: CARDINAL;            -> variables
#     TYPE Node = RECORD next: NodePtr END; -> class (record type)
#
# Comments are nested '(* ... *)'; strings use '"' and "'".  Keywords are
# upper-case and the language is case-sensitive.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_]*"


class Modula2Analyzer(RegexCodeAnalyzer):
    LANG_KEY = "modula2"
    EXTENSIONS = (".mod", ".def")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"', "'")

    _MODULE = re.compile(r"\b(?:DEFINITION|IMPLEMENTATION)?\s*MODULE\s+(" + _ID + r")")
    _PROC = re.compile(r"\bPROCEDURE\s+(" + _ID + r")\s*(\([^)]*\))?")
    _FROM = re.compile(r"\bFROM\s+(" + _ID + r")\s+IMPORT\s+([^;]+);")
    _IMPORT = re.compile(r"^[ \t]*IMPORT\s+([^;]+);", re.MULTILINE)
    _RECORD = re.compile(r"\b(" + _ID + r")\s*=\s*RECORD\b")
    _CONST = re.compile(
        r"^[ \t]*(?:CONST[ \t]+)?(" + _ID + r")\s*=\s*[^=;]", re.MULTILINE
    )
    _VARLINE = re.compile(
        r"^[ \t]*(?:VAR[ \t]+)?(" + _ID + r"(?:\s*,\s*" + _ID + r")*)\s*:\s*[^;]+;",
        re.MULTILINE,
    )

    def _proc_args(self, paren):
        if not paren:
            return []
        inner = paren[1:-1]
        ids = []
        for grp in self._split_top_level(inner, sep=";"):
            # "VAR s: Stack" | "x, y: INTEGER" | "f: PROC"
            if ":" in grp:
                names, _, typ = grp.partition(":")
                typ = typ.strip()
            else:
                names, typ = grp, None
            names = re.sub(r"(?i)\bVAR\b", "", names)
            for nm in names.split(","):
                m = re.match(_ID, nm.strip())
                if m:
                    ids.append(self._add_arg(m.group(0), arg_type=typ))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1))
        for m in self._RECORD.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._FROM.finditer(clean):
            src = m.group(1)
            for sym in self._split_top_level(m.group(2)):
                self._add_import(file_id, sym, src)
        for m in self._IMPORT.finditer(clean):
            for mod in self._split_top_level(m.group(1)):
                # "Foo" or "alias := Foo"
                mod = mod.split(":=")[-1].strip()
                nm = re.match(_ID, mod)
                if nm:
                    self._add_import(file_id, nm.group(0), nm.group(0))

        cls_id = None
        for m in self._MODULE.finditer(clean):
            cls_id = self._add_class(file_id, m.group(1), description="modula-2 module")
        for m in self._RECORD.finditer(clean):
            self._add_class(file_id, m.group(1), description="modula-2 record")

        for m in self._PROC.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._proc_args(m.group(2)),
                [],
                class_id=cls_id,
                description="modula-2 procedure",
            )

        for m in self._CONST.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")
        for m in self._VARLINE.finditer(clean):
            for nm in m.group(1).split(","):
                self._add_variable(file_id, nm.strip(), scope="module")
