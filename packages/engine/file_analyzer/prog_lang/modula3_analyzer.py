# Modula-3 (.m3 / .i3) analyzer.
#
# Real parser for Modula-3 (interfaces .i3 / implementations .m3):
#
#     INTERFACE Stack;                     -> class
#     MODULE Stack EXPORTS Stack;          -> class
#     IMPORT Text, IO, Fmt AS F;           -> import (with AS alias)
#     FROM Stack IMPORT T, Push;           -> import (each symbol)
#     PROCEDURE Push(s: T; x: INTEGER): BOOLEAN = -> function
#     TYPE T = OBJECT next: T METHODS get(): INTEGER END; -> class (object)
#     TYPE Node = RECORD next: Ref END;    -> class (record)
#     CONST Max = 100;                     -> variable
#     VAR count: CARDINAL;                 -> variables
#     REVEAL T = BRANDED OBJECT ... END;   -> class reveal
#
# Comments are nested '(* ... *)'; strings use '"' and "'".  Case-sensitive.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_]*"


class Modula3Analyzer(RegexCodeAnalyzer):
    LANG_KEY = "modula3"
    EXTENSIONS = (".m3", ".i3")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"', "'")

    _UNIT = re.compile(r"\b(?:INTERFACE|MODULE)\s+(" + _ID + r")")
    _PROC = re.compile(r"\bPROCEDURE\s+(" + _ID + r")\s*(\([^)]*\))?")
    _FROM = re.compile(r"\bFROM\s+(" + _ID + r")\s+IMPORT\s+([^;]+);")
    _IMPORT = re.compile(r"^[ \t]*IMPORT\s+([^;]+);", re.MULTILINE)
    _OBJTYPE = re.compile(
        r"\b(" + _ID + r")\s*=\s*(?:BRANDED\s+(?:\"[^\"]*\"\s+)?)?OBJECT\b"
    )
    _RECTYPE = re.compile(r"\b(" + _ID + r")\s*=\s*RECORD\b")
    _CONST = re.compile(
        r"^[ \t]*(?:CONST[ \t]+)?(" + _ID + r")\s*=\s*[^=;]", re.MULTILINE
    )
    _VARLINE = re.compile(
        r"^[ \t]*(?:VAR[ \t]+)?(" + _ID + r"(?:\s*,\s*" + _ID + r")*)\s*:\s*[^;]+",
        re.MULTILINE,
    )
    _METHOD = re.compile(r"\b(" + _ID + r")\s*\([^)]*\)\s*(?::[^;]+)?:=")

    def _proc_args(self, paren):
        if not paren:
            return []
        inner = paren[1:-1]
        ids = []
        for grp in self._split_top_level(inner, sep=";"):
            if ":" in grp:
                names, _, rest = grp.partition(":")
                typ = rest.split(":=")[0].strip()
            else:
                names, typ = grp, None
            names = re.sub(r"(?i)\b(?:VAR|READONLY|VALUE)\b", "", names)
            for nm in names.split(","):
                m = re.match(_ID, nm.strip())
                if m:
                    ids.append(self._add_arg(m.group(0), arg_type=typ))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (self._UNIT, self._OBJTYPE, self._RECTYPE):
            for m in rx.finditer(clean):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._FROM.finditer(clean):
            src = m.group(1)
            for sym in self._split_top_level(m.group(2)):
                self._add_import(file_id, sym.split()[0], src)
        for m in self._IMPORT.finditer(clean):
            for chunk in self._split_top_level(m.group(1)):
                # "Text" | "Fmt AS F"
                parts = re.split(r"\s+AS\s+", chunk.strip())
                mod = parts[0].strip()
                alias = parts[1].strip() if len(parts) > 1 else None
                nm = re.match(_ID, mod)
                if nm:
                    self._add_import(
                        file_id, (alias or nm.group(0)), nm.group(0), alias
                    )

        cls_id = None
        for m in self._UNIT.finditer(clean):
            cls_id = self._add_class(file_id, m.group(1), description="modula-3 unit")
        for m in self._OBJTYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="modula-3 object")
        for m in self._RECTYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="modula-3 record")

        for m in self._PROC.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._proc_args(m.group(2)),
                [],
                class_id=cls_id,
                description="modula-3 procedure",
            )

        for m in self._CONST.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")
        for m in self._VARLINE.finditer(clean):
            for nm in m.group(1).split(","):
                self._add_variable(file_id, nm.strip(), scope="module")
