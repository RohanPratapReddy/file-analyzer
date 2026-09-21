# KRL (.krl) analyzer -- KUKA Robot Language.
#
#     DEF main()                                    -> function
#       DECL INT i                                  -> variable
#       ...
#     END
#     GLOBAL DEFFCT REAL add(a:IN, b:IN)            -> function (+ REAL output)
#       ...
#     ENDFCT
#     DEFDAT prog_data                              -> class (data list)
#       DECL E6POS home                             -> variable
#     ENDDAT
#     EXT BAS(BAS_COMMAND:IN, REAL:IN)              -> import (external decl)
#     EXTFCT REAL myext(REAL:IN)                    -> import
#     $VEL.CP = 2.0                                 -> variable (system var)
#
# Comments are ';'; strings use '"'. Case-insensitive keywords.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_TYPE = r"[A-Za-z_][A-Za-z0-9_]*"


class KRLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "krl"
    EXTENSIONS = (".krl",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    # DEF / DEFFCT (optionally GLOBAL), function with optional return type
    _DEF = re.compile(r"(?im)^\s*(?:GLOBAL\s+)?DEF\s+(" + _ID + r")\s*\(([^)]*)\)")
    _DEFFCT = re.compile(r"(?im)^\s*(?:GLOBAL\s+)?DEFFCT\s+(" + _TYPE +
                         r")\s+(" + _ID + r")\s*\(([^)]*)\)")
    _DEFDAT = re.compile(r"(?im)^\s*(?:GLOBAL\s+)?DEFDAT\s+(" + _ID + r")")
    _EXT = re.compile(r"(?im)^\s*(?:GLOBAL\s+)?EXT(?:FCT)?\s+(?:" + _TYPE +
                      r"\s+)?(" + _ID + r")\s*\(")
    # DECL [GLOBAL] TYPE name  |  TYPE name  |  bare `DECL name`
    _DECL = re.compile(r"(?im)^\s*(?:GLOBAL\s+)?(?:CONST\s+)?DECL\s+"
                       r"(?:GLOBAL\s+)?(?:CONST\s+)?(?:" + _TYPE + r"\s+)?(" +
                       _ID + r")")
    _SYSVAR = re.compile(r"(?m)^\s*(\$" + _ID + r")\s*=")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._DEFDAT.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._EXT.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        for m in self._DEFDAT.finditer(clean):
            self._add_class(file_id, m.group(1), description="krl data list")

        for m in self._DEF.finditer(clean):
            args = self._krl_args(m.group(2))
            self._add_function(file_id, m.group(1), args, [],
                               description="krl def")
        for m in self._DEFFCT.finditer(clean):
            args = self._krl_args(m.group(3))
            outs = [self._add_output(m.group(1))]
            self._add_function(file_id, m.group(2), args, outs,
                               description="krl deffct")

        seen = set()
        for m in self._DECL.finditer(clean):
            name = m.group(1)
            if name.upper() in ("GLOBAL", "CONST") or name in seen:
                continue
            seen.add(name)
            self._add_variable(file_id, name, scope="module")
        for m in self._SYSVAR.finditer(clean):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                self._add_variable(file_id, name, scope="system")

    def _krl_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            # `name:IN` / `name:OUT` / `name`
            name = part.strip().split(":")[0].strip()
            if re.fullmatch(_ID, name):
                arg_ids.append(self._add_arg(name))
        return arg_ids
