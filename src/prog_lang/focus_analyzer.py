# IBI FOCUS report procedure / FOCEXEC (.focus).
#
# FOCUS (Information Builders) is a mainframe/4GL reporting language.  A
# procedure (FOCEXEC) mixes Dialogue Manager control lines (which begin with
# `-`) and TABLE/MODIFY request syntax:
#
#     -* build a sales report
#     -SET &REGION = 'EAST';
#     DEFINE FILE SALES
#     MARGIN/D8.2 = PRICE - COST;
#     END
#     TABLE FILE SALES
#     PRINT PRICE COMPUTE PROFIT/D8.2 = PRICE - COST;
#     BY STORE
#     END
#     CASE GETRATE
#     ...
#     ENDCASE
#     -INCLUDE COMMON
#
# Recovered symbols:
#   * `DEFINE fld/fmt = ...`  and  `COMPUTE fld/fmt = ...`  -> variable
#     (a computed/virtual field), scope "field"
#   * `-SET &amper = ...`                       -> variable, scope "amper"
#   * `CASE name ... ENDCASE`                   -> function
#   * `TABLE FILE x` / `MODIFY FILE x` / `DEFINE FILE x` / `GRAPH FILE x`
#                                               -> import (the master file read)
#   * `-INCLUDE member` / `-READ file`          -> import
# `-*` starts a Dialogue Manager comment line; FOCUS keywords are
# case-insensitive.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_#@$][A-Za-z0-9_#@$]*"
_FLD = r"[A-Za-z_#@$][A-Za-z0-9_#@$.]*"


class FocusAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "focus"
    EXTENSIONS = (".focus",)
    LINE_COMMENTS = ("-*",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'",)

    # DEFINE fieldname[/format] = ...   (but NOT `DEFINE FILE master`)
    _DEFINE_FIELD = re.compile(r"(?mi)^[ \t]*DEFINE\s+(?!FILE\b)(" + _FLD +
                               r")\s*(?:/[^=;\s]+)?\s*=")
    # COMPUTE fieldname[/format] = ...  (may appear inline after PRINT/SUM/etc.)
    _COMPUTE = re.compile(r"(?mi)\bCOMPUTE\s+(" + _FLD +
                          r")\s*(?:/[^=;\s]+)?\s*=")
    # inside a `DEFINE FILE ... END` block, a bare `field[/fmt] = expr` line
    _BLOCK_OPEN = re.compile(r"(?mi)^[ \t]*DEFINE\s+FILE\b")
    _BLOCK_END = re.compile(r"(?mi)^[ \t]*END[ \t]*$")
    _BLOCK_FIELD = re.compile(r"(?i)^[ \t]*(" + _FLD +
                              r")\s*(?:/[^=;\s]+)?\s*=")
    # -SET &var = value ;
    _AMPER = re.compile(r"(?mi)^[ \t]*-SET\s+&+(" + _ID + r")\s*=")
    # CASE label
    _CASE = re.compile(r"(?mi)^[ \t]*CASE\s+(" + _ID + r")\b")
    # TABLE/MODIFY/DEFINE/GRAPH/MATCH FILE  <master>
    _FILE = re.compile(r"(?mi)^[ \t]*(?:TABLE|MODIFY|GRAPH|MATCH|DEFINE)\s+"
                       r"FILE\s+(" + _ID + r")")
    # -INCLUDE member  /  -READ file
    _INCLUDE = re.compile(r"(?mi)^[ \t]*-(?:INCLUDE|READ|MRNOEDIT\s+-INCLUDE)\s+"
                          r"(" + _ID + r")")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._CASE.finditer(clean):
            name = m.group(1)
            if name.lower() in seen_fn:
                continue
            seen_fn.add(name.lower())
            self._add_function(file_id, name, [], [], description="FOCUS case")

        seen_v = set()

        def add_field(name, scope="field"):
            key = (scope, name.lower())
            if key not in seen_v:
                seen_v.add(key)
                self._add_variable(file_id, name, None, scope=scope)

        for rx in (self._DEFINE_FIELD, self._COMPUTE):
            for m in rx.finditer(clean):
                add_field(m.group(1))
        for m in self._AMPER.finditer(clean):
            add_field(m.group(1), scope="amper")

        # virtual fields declared inside a `DEFINE FILE ... END` block
        in_block = False
        for ln in clean.splitlines():
            if not in_block:
                if self._BLOCK_OPEN.match(ln):
                    in_block = True
                continue
            if self._BLOCK_END.match(ln):
                in_block = False
                continue
            fm = self._BLOCK_FIELD.match(ln)
            if fm:
                add_field(fm.group(1))

        seen_i = set()
        for rx in (self._FILE, self._INCLUDE):
            for m in rx.finditer(clean):
                src = m.group(1)
                if src.lower() in seen_i:
                    continue
                seen_i.add(src.lower())
                self._add_import(file_id, src, src)
