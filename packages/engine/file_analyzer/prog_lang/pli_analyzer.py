# PL/I (.pli) analyzer.
#
# Real parser for IBM PL/I:
#
#     Main: PROCEDURE OPTIONS(MAIN);       -> function (label = name)
#     Compute: PROC(a, b) RETURNS(FIXED);  -> function (with args + output)
#     DECLARE Count FIXED BINARY(31);      -> variable
#     DCL (Total, Sub) FLOAT;              -> variables (group)
#     DCL 1 Record, 2 Field CHAR(10);      -> structure -> class + members
#     %INCLUDE Payroll;                    -> import
#
# Comments are '/* ... */'.  Keywords are case-insensitive; strings use "'".
# Statements end at ';'.  Labels precede PROC/PROCEDURE with a ':'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z@#$][A-Za-z0-9@#$_]*"


class PLIAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "pli"
    EXTENSIONS = (".pli",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ("'",)

    _PROC = re.compile(r"(?im)\b(" + _ID + r")\s*:\s*(?:PROCEDURE|PROC)\b([^;]*);")
    _RETURNS = re.compile(r"(?i)\bRETURNS\s*\(([^)]*)\)")
    _DECL = re.compile(r"(?im)\b(?:DECLARE|DCL)\b([^;]*);")
    _INCLUDE = re.compile(r"(?im)%\s*INCLUDE\s+([^;]+);")
    _LEVEL1 = re.compile(r"(?i)^\s*1\s+(" + _ID + r")\b")
    _ENTRY = re.compile(r"(?im)\b(" + _ID + r")\s*:\s*ENTRY\b")

    def _decl_names(self, body):
        """Yield (name, is_structure_root) from a DECLARE body."""
        # strip leading noise, split on top-level commas
        for item in self._split_top_level(body, sep=","):
            item = item.strip()
            if not item:
                continue
            # optional leading level number: "1 Rec", "2 Field CHAR(10)"
            m = re.match(
                r"(?:(\d+)\s+)?(\(?)\s*(" + _ID + r"(?:\s*,\s*" + _ID + r")*)?", item
            )
            if not m:
                continue
            level = m.group(1)
            names_blob = m.group(3) or ""
            # grouped "(A, B) FLOAT"
            if not names_blob and m.group(2) == "(":
                inner = item[item.index("(") + 1 :]
                names_blob = inner.split(")")[0]
            for nm in names_blob.split(","):
                nn = re.match(_ID, nm.strip())
                if nn:
                    yield nn.group(0), (level == "1")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._DECL.finditer(clean):
            for nm, is_struct in self._decl_names(m.group(1)):
                if is_struct:
                    self._register_class(nm)

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            for part in re.split(r"[,\s]+", m.group(1).strip()):
                part = part.strip("()")
                nm = re.match(_ID, part)
                if nm:
                    self._add_import(file_id, nm.group(0), nm.group(0))

        for m in self._PROC.finditer(clean):
            tail = m.group(2)
            arg_ids = []
            pm = re.search(r"\(([^)]*)\)", tail)
            if pm and "OPTIONS" not in pm.group(0).upper():
                for a in self._split_top_level(pm.group(1)):
                    nm = re.match(_ID, a.strip())
                    if nm:
                        arg_ids.append(self._add_arg(nm.group(0)))
            out_ids = []
            rm = self._RETURNS.search(tail)
            if rm:
                out_ids.append(self._add_output(rm.group(1).strip()))
            self._add_function(
                file_id, m.group(1), arg_ids, out_ids, description="pl/i procedure"
            )

        for m in self._ENTRY.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], description="pl/i entry")

        for m in self._DECL.finditer(clean):
            for nm, is_struct in self._decl_names(m.group(1)):
                if is_struct:
                    self._add_class(file_id, nm, description="pl/i structure")
                else:
                    self._add_variable(file_id, nm, scope="module")
