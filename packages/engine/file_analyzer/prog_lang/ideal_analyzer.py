# CA-Ideal program source (.ideal).
#
# CA-Ideal (Computer Associates, over the Datacom/DB database) is a mainframe
# 4GL.  An application is built from named components -- procedures, panels,
# reports, datasets and datatables -- and data definitions:
#
#     PROCEDURE MAIN
#         DEFINE CUST-NAME TYPE CHAR LENGTH 30.
#         DEFINE TOTAL     TYPE NUMERIC.
#         SET TOTAL = 0.
#         FOR EACH ORDER
#             SET TOTAL = TOTAL + ORDER-AMT.
#         ENDFOR
#         CALL SUBRTN USING TOTAL.
#     ENDPROC
#     PANEL CUSTFORM
#     REPORT SALESRPT
#     DATASET ORDERS
#
# Recovered symbols:
#   * `PROCEDURE name` / `SUBROUTINE name`          -> function
#   * `PANEL|REPORT|DATASET|DATATABLE|MESSAGE name` -> class (a named component)
#   * `DEFINE name TYPE ...`                         -> variable
#   * `CALL name` / `RUN name` / `USE name`          -> import
# `<< ... >>` is a comment; keywords are case-insensitive; statements end in a
# period.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_-]*"


class IdealAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ideal"
    EXTENSIONS = (".ideal",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("<<", ">>"),)
    STRING_DELIMS = ("'", '"')

    _PROC = re.compile(r"(?mi)^[ \t]*(?:PROCEDURE|SUBROUTINE)\s+(" + _ID + r")\b")
    _COMPONENT = re.compile(
        r"(?mi)^[ \t]*(PANEL|REPORT|DATASET|DATATABLE|"
        r"MESSAGE|APPLICATION)\s+(" + _ID + r")\b"
    )
    _DEFINE = re.compile(r"(?mi)^[ \t]*DEFINE\s+(" + _ID + r")\s+TYPE\b")
    _CALL = re.compile(r"(?mi)^[ \t]*(?:CALL|RUN|USE)\s+(" + _ID + r")\b")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            name = m.group(1)
            if name.lower() not in seen_fn:
                seen_fn.add(name.lower())
                self._add_function(file_id, name, [], [], description="Ideal procedure")

        seen_c = set()
        for m in self._COMPONENT.finditer(clean):
            kind, name = m.group(1).upper(), m.group(2)
            if name.lower() not in seen_c:
                seen_c.add(name.lower())
                self._add_class(file_id, name, description=f"Ideal {kind.title()}")

        seen_v = set()
        for m in self._DEFINE.finditer(clean):
            name = m.group(1)
            if name.lower() not in seen_v:
                seen_v.add(name.lower())
                self._add_variable(file_id, name, None, scope="data")

        seen_i = set()
        for m in self._CALL.finditer(clean):
            name = m.group(1)
            if name.lower() not in seen_i and name.lower() not in seen_fn:
                seen_i.add(name.lower())
                self._add_import(file_id, name, name)
