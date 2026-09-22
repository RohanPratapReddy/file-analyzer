# Tandem / HP NonStop TAL (.tal) analyzer -- Transaction Application Language.
#
#     ?SOURCE $SYSTEM.SYSTEM.EXTDECS0(WRITE, READ)  -> import (+ each name)
#     NAME mymodule;                                -> import (module identity)
#     INT PROC compute(a, b);                       -> function (+ INT output)
#     PROC main MAIN;                               -> function
#     STRING PROC fmt(s) VARIABLE;                  -> function
#     SUBPROC helper;                               -> function
#     STRUCT rec (*);                               -> class
#     INT count;                                    -> variable
#     STRING .buf[0:79];                            -> variable
#     LITERAL max = 100;                            -> variable
#     DEFINE flag = 1 #;                            -> variable
#
# Comments '!' (to EOL or matching '!') and '--'; strings '"'. Case-insensitive.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_\^][A-Za-z0-9_\^]*"  # TAL allows '^' in identifiers
_TYPE = (
    r"(?:INT|STRING|FIXED|REAL|UNSIGNED|BYTE|CHAR|"
    r"INT\(32\)|INT\(64\)|REAL\(64\)|FIXED\([^)]*\))"
)


class TALAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "tal"
    EXTENSIONS = (".tal",)
    LINE_COMMENTS = ("!", "--")
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _SOURCE = re.compile(r"(?im)^\s*\?SOURCE\s+(\S+?)(?:\s*\(([^)]*)\))?\s*$")
    _NAME = re.compile(r"(?im)^\s*NAME\s+(" + _ID + r")\s*;")
    _PROC = re.compile(
        r"(?im)^\s*(?:" + _TYPE + r"\s+)?"
        r"(?:PROC|SUBPROC)\s+(" + _ID + r")"
        r"\s*(\([^)]*\))?",
    )
    _STRUCT = re.compile(r"(?im)^\s*STRUCT\s+\.?(" + _ID + r")")
    _LITERAL = re.compile(r"(?im)^\s*(?:LITERAL|DEFINE)\s+(" + _ID + r")")
    _VAR = re.compile(
        r"(?im)^\s*("
        + _TYPE
        + r")\s+(\.?(?:EXT\s+)?"
        + _ID
        + r"(?:\s*,\s*\.?"
        + _ID
        + r")*)"
    )

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._STRUCT.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._SOURCE.finditer(clean):
            src = m.group(1)
            leaf = src.split(".")[-1]
            self._add_import(file_id, leaf, src)
            if m.group(2):
                for nm in m.group(2).split(","):
                    nm = nm.strip()
                    if nm and re.match(_ID + r"$", nm):
                        self._add_import(file_id, nm, src)
        for m in self._NAME.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        for m in self._STRUCT.finditer(clean):
            self._add_class(file_id, m.group(1), description="tal struct")

        for m in self._PROC.finditer(clean):
            args = self._tal_args(m.group(2))
            self._add_function(file_id, m.group(1), args, [], description="tal proc")

        seen = set()
        for m in self._LITERAL.finditer(clean):
            if m.group(1) not in seen:
                seen.add(m.group(1))
                self._add_variable(file_id, m.group(1), scope="module")
        for m in self._VAR.finditer(clean):
            for raw in m.group(2).split(","):
                raw = raw.strip().lstrip(".")
                raw = re.sub(r"(?i)^EXT\s+", "", raw)
                mm = re.match(_ID, raw)
                if not mm:
                    continue
                name = mm.group(0)
                if name.upper() in ("PROC", "SUBPROC") or name in seen:
                    continue
                seen.add(name)
                self._add_variable(file_id, name, scope="module")

    def _tal_args(self, group):
        if not group or not group.strip("() "):
            return []
        inner = group.strip()[1:-1]
        arg_ids = []
        for part in self._split_top_level(inner):
            part = part.strip()
            mm = re.match(_ID, part)
            if mm:
                arg_ids.append(self._add_arg(mm.group(0)))
        return arg_ids
