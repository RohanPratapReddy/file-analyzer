# LOLCODE (.lol, .lolcode) analyzer -- lolcat-themed esoteric language.
#
#     HAI 1.2                                    -> (version header, ignored)
#     CAN HAS STDIO?                             -> import (library)
#     HOW IZ I add YR a AN YR b ... IF U SAY SO  -> function (+ args)
#     I HAS A var                                -> variable
#     I HAS A var ITZ 5                          -> variable (initialised)
#     KTHXBYE                                    -> (end, ignored)
#
# Comments are 'BTW' (line) and 'OBTW ... TLDR' (block); strings use '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_]*"


class LOLCODEAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "lolcode"
    EXTENSIONS = (".lol", ".lolcode")
    LINE_COMMENTS = ("BTW",)
    BLOCK_COMMENTS = (("OBTW", "TLDR"),)
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(r"(?m)^\s*CAN\s+HAS\s+(" + _ID + r")\s*\??")
    # function:  HOW IZ I name [YR arg [AN YR arg] ...]
    _FUNC = re.compile(r"(?m)^\s*HOW\s+IZ\s+I\s+(" + _ID + r")(.*)$")
    _ARG = re.compile(r"YR\s+(" + _ID + r")")
    _VAR = re.compile(r"(?m)^\s*I\s+HAS\s+A\s+(" + _ID + r")")

    def _register_types(self, file_id, text, path):
        # LOLCODE has no class construct.
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            args = [self._add_arg(a.group(1)) for a in self._ARG.finditer(m.group(2))]
            self._add_function(file_id, name, args, [],
                               description="lolcode function")

        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")
