# RAMIS report definition (.ramis).
#
# RAMIS (originally Mathematica Inc., later Computer Associates) is a mainframe
# 4GL report writer, a close cousin of FOCUS.  A procedure combines DEFINE
# virtual fields, TABLE/REPORT requests and `-`-prefixed control lines:
#
#     -* quarterly summary
#     DEFINE PROFIT = SALES - COST
#     TABLE FILE ORDERS
#     PRINT SALES AND PROFIT
#     BY REGION
#     END
#     PROCEDURE RECAP
#     ...
#     END
#     -SET %LIMIT = 100
#     -INCLUDE STDHEAD
#
# Recovered symbols:
#   * `DEFINE name [= ...]` / `COMPUTE name = ...`   -> variable (virtual field)
#   * `-SET %var = ...`                              -> variable, scope "amper"
#   * `PROCEDURE name ... END`                       -> function
#   * `TABLE FILE x` / `REPORT ON x` / `FROM x`      -> import (the data file)
#   * `-INCLUDE member`                              -> import
# `-*` starts a control-line comment; keywords are case-insensitive.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_#@$][A-Za-z0-9_#@$]*"


class RamisAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ramis"
    EXTENSIONS = (".ramis",)
    LINE_COMMENTS = ("-*",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'",)

    _DEFINE = re.compile(r"(?mi)^[ \t]*(?:DEFINE|COMPUTE)\s+(" + _ID +
                         r")\s*(?:/[^=\s]+)?\s*(?:=|$)")
    _AMPER = re.compile(r"(?mi)^[ \t]*-SET\s+%+(" + _ID + r")\s*=")
    _PROC = re.compile(r"(?mi)^[ \t]*PROCEDURE\s+(" + _ID + r")\b")
    _FILE = re.compile(r"(?mi)^[ \t]*(?:TABLE\s+FILE|REPORT\s+ON|FROM)\s+(" +
                       _ID + r")")
    _INCLUDE = re.compile(r"(?mi)^[ \t]*-INCLUDE\s+(" + _ID + r")")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            name = m.group(1)
            if name.lower() in seen_fn:
                continue
            seen_fn.add(name.lower())
            self._add_function(file_id, name, [], [],
                               description="RAMIS procedure")

        seen_v = set()
        for rx, scope in ((self._DEFINE, "field"), (self._AMPER, "amper")):
            for m in rx.finditer(clean):
                name = m.group(1)
                key = (scope, name.lower())
                if key in seen_v:
                    continue
                seen_v.add(key)
                self._add_variable(file_id, name, None, scope=scope)

        seen_i = set()
        for rx in (self._FILE, self._INCLUDE):
            for m in rx.finditer(clean):
                src = m.group(1)
                if src.lower() in seen_i:
                    continue
                seen_i.add(src.lower())
                self._add_import(file_id, src, src)
