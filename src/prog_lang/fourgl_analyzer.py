# Informix / Genero 4GL (.4gl) analyzer -- business 4GL language.
#
#     IMPORT FGL mylib                              -> import
#     IMPORT util                                   -> import
#     SCHEMA stores                                 -> import (database schema)
#     FUNCTION compute(a, b)                        -> function
#         DEFINE r INTEGER                          -> variable
#         RETURN r
#     END FUNCTION
#     MAIN ... END MAIN                             -> function
#     REPORT invoice(item)  ... END REPORT          -> function
#     DEFINE g_total DECIMAL(10,2)                  -> variable
#
# Comments are '#', '--' and '{ }'; strings use '"' and '\''. Case-insensitive.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class FourGLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "fourgl"
    EXTENSIONS = (".4gl",)
    LINE_COMMENTS = ("#", "--")
    BLOCK_COMMENTS = (("{", "}"),)
    STRING_DELIMS = ('"', "'")

    _IMPORT = re.compile(r"(?im)^\s*IMPORT\s+(?:FGL|JAVA|C)?\s*([\w.]+)")
    _SCHEMA = re.compile(r"(?im)^\s*(?:SCHEMA|DATABASE)\s+(" + _ID + r")")
    _FUNC = re.compile(r"(?im)^\s*(?:PRIVATE\s+|PUBLIC\s+)?FUNCTION\s+(" + _ID +
                       r")\s*\(([^)]*)\)")
    _MAIN = re.compile(r"(?im)^\s*MAIN\b")
    _REPORT = re.compile(r"(?im)^\s*REPORT\s+(" + _ID + r")\s*\(([^)]*)\)")
    # `DEFINE name TYPE` (may list several comma-separated names before a type)
    _DEFINE = re.compile(r"(?im)^\s*DEFINE\s+([^\n]+)")

    _TYPE_TOKENS = re.compile(r"(?i)\b(?:CHAR|VARCHAR|STRING|INTEGER|INT|"
                              r"SMALLINT|BIGINT|DECIMAL|DEC|MONEY|FLOAT|SMALLFLOAT|"
                              r"REAL|DOUBLE|DATE|DATETIME|INTERVAL|BOOLEAN|BYTE|"
                              r"TEXT|RECORD|ARRAY|DYNAMIC|LIKE|OF|TO|DIM)\b")

    def _register_types(self, file_id, text, path):
        # 4GL has no user class construct (RECORD types are inline).
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split(".")[-1], src)
        for m in self._SCHEMA.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        for m in self._FUNC.finditer(clean):
            args = self._simple_args(m.group(2))
            self._add_function(file_id, m.group(1), args, [],
                               description="4gl function")
        for m in self._MAIN.finditer(clean):
            self._add_function(file_id, "MAIN", [], [], description="4gl main")
        for m in self._REPORT.finditer(clean):
            args = self._simple_args(m.group(2))
            self._add_function(file_id, m.group(1), args, [],
                               description="4gl report")

        seen = set()
        for m in self._DEFINE.finditer(clean):
            for name in self._define_names(m.group(1)):
                if name and name not in seen:
                    seen.add(name)
                    self._add_variable(file_id, name, scope="module")

    def _define_names(self, line):
        # everything up to the first type keyword is a comma-separated name list
        tm = self._TYPE_TOKENS.search(line)
        head = line[:tm.start()] if tm else line
        names = []
        for tok in re.split(r"[,\s]+", head.strip()):
            if re.fullmatch(_ID, tok) and tok.upper() not in ("DEFINE",):
                names.append(tok)
        return names

    def _simple_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip()
            m = re.match(_ID, part)
            if m:
                arg_ids.append(self._add_arg(m.group(0)))
        return arg_ids
