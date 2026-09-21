# SNOBOL4 (.snobol) analyzer -- pattern-matching string language.
#
#     -INCLUDE 'strings.sno'                        -> import (control line)
#            DEFINE('SWAP(A,B)')                    -> function SWAP (+ args A,B)
#            DEFINE('FACT(N)','FACT_1')             -> function FACT (+ arg N)
#     COUNT  = 0                                    -> variable COUNT
#            OUTPUT = COUNT                          -> variable OUTPUT
#
# Column-1 '*' -> comment line; column-1 '-' -> control line; '+'/'.' -> cont.
# Strings use '"' and "'". No classes.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_.]*"


class SnobolAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "snobol"
    EXTENSIONS = (".snobol", ".sno")
    LINE_COMMENTS = ()  # column-sensitive; custom cleaner
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _DEFINE = re.compile(r"(?i)\bDEFINE\s*\(\s*['\"]\s*(" + _ID + r")\s*(\([^)]*\))?")
    _INCLUDE = re.compile(r"(?im)^-\s*INCLUDE\s+['\"]([^'\"]+)['\"]")
    # assignment:  [LABEL] SUBJECT = OBJECT   -- capture the assigned identifier
    _ASSIGN = re.compile(r"(?m)^\s*(?:(" + _ID + r")\s+)?(" + _ID + r")\s*=\s*(?!=)")

    def _clean(self, text):
        out = []
        for line in text.splitlines():
            if line[:1] == "*":  # column-1 comment
                out.append("")
            elif line[:1] == "-":  # control line (keep for include)
                out.append(line)
            else:
                out.append(line)
        return "\n".join(out)

    def _register_types(self, file_id, text, path):
        return

    def _extract_entities(self, file_id, text, path):
        raw = self._clean(text)
        clean = self._strip_comments(raw)

        for m in self._INCLUDE.finditer(raw):
            src = m.group(1)
            self._add_import(file_id, re.split(r"[\\/]", src)[-1], src)

        defined = set()
        for m in self._DEFINE.finditer(clean):
            name = m.group(1)
            args = []
            if m.group(2):
                for a in m.group(2).strip("()").split(","):
                    a = a.strip()
                    if a:
                        args.append(self._add_arg(a))
            self._add_function(file_id, name, args, [], description="snobol function")
            defined.add(name.upper())

        seen = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(2)
            up = name.upper()
            if up in defined or up in seen:
                continue
            # control keyword after '-' handled elsewhere; skip common ops
            seen.add(up)
            self._add_variable(file_id, name, scope="module")
