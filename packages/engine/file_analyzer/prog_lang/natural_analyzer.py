# Software AG Natural (.nat) analyzer -- 4GL / ADABAS application language.
#
#     DEFINE DATA LOCAL                             -> (section)
#     1 #CUSTOMER (A20)                             -> variable
#     1 #TOTALS                                     -> variable (group)
#     2 #AMOUNT (P7.2)                              -> variable
#     END-DEFINE
#     DEFINE SUBROUTINE calc-total                  -> function
#     END-SUBROUTINE
#     DEFINE FUNCTION F#ADD RETURNS (I4)            -> function (+ output)
#     CALLNAT 'SUBPROG' #A #B                       -> import
#     INCLUDE COPYCODE                              -> import
#     FETCH 'PROGRAM'                               -> import
#
# Case-insensitive keywords. Comments: '*' or '**' line-lead, '/*' inline; "'".
import re

from .regex_base import RegexCodeAnalyzer

# Natural identifiers may carry #, +, & sigils and internal hyphens/dots.
_NID = r"[#&+]?[A-Za-z][A-Za-z0-9_.#/-]*"


class NaturalAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "natural"
    EXTENSIONS = (".nat", ".nsp", ".nsn")
    LINE_COMMENTS = ()  # handled by custom cleaner (col-1 '*'/'/*')
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'", '"')

    _SUBROUTINE = re.compile(r"(?im)^\s*DEFINE\s+SUBROUTINE\s+(" + _NID + r")")
    _FUNCTION = re.compile(
        r"(?im)^\s*DEFINE\s+FUNCTION\s+(" + _NID + r")"
        r"(?:\s+RETURNS?\s*\(([^)]*)\))?"
    )
    _CALLNAT = re.compile(
        r"(?im)^\s*(?:CALLNAT|FETCH(?:\s+RETURN|\s+REPEAT)?|" r"CALL)\s+'([^']+)'"
    )
    _INCLUDE = re.compile(r"(?im)^\s*INCLUDE\s+(" + _NID + r")")
    # level-numbered data field:  `1 #NAME (A20)`  /  `2 #SUB`
    _FIELD = re.compile(r"(?im)^\s*([1-9])\s+(" + _NID + r")\b")

    def _clean(self, text):
        out = []
        for line in text.splitlines():
            s = line.lstrip()
            if s.startswith("**") or s.startswith("* ") or s == "*":
                out.append("")
                continue
            # inline '/*' comment to end of line
            i = line.find("/*")
            if i != -1:
                line = line[:i]
            out.append(line)
        return "\n".join(out)

    def _extract_entities(self, file_id, text, path):
        clean = self._clean(text)

        seen_imp = set()
        for rx in (self._CALLNAT, self._INCLUDE):
            for m in rx.finditer(clean):
                name = m.group(1)
                key = name.upper()
                if key in seen_imp:
                    continue
                seen_imp.add(key)
                self._add_import(file_id, name, name)

        for m in self._SUBROUTINE.finditer(clean):
            self._add_function(
                file_id, m.group(1), [], [], description="natural subroutine"
            )
        for m in self._FUNCTION.finditer(clean):
            outs = []
            if m.group(2):
                outs = [self._add_output(m.group(2).strip())]
            self._add_function(
                file_id, m.group(1), [], outs, description="natural function"
            )

        seen_var = set()
        for m in self._FIELD.finditer(clean):
            name = m.group(2)
            up = name.upper()
            if up in ("DATA", "END", "REDEFINE") or name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, scope="module")

    def _register_types(self, file_id, text, path):
        return
