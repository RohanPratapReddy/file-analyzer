# ALGOL (.algol) analyzer -- covers ALGOL 60 and ALGOL 68 declaration forms.
#
#  ALGOL 60:
#     integer procedure fact(n);  value n; integer n; -> function (+ output)
#     procedure swap(a, b);                            -> function
#     integer i, j, k;                                 -> variables
#     real x, y;                                        -> variables
#  ALGOL 68:
#     PROC add = (INT a, INT b) INT: a + b;            -> function (+ output)
#     MODE VEC = [1:3] REAL;                           -> class (type)
#     INT count := 0;                                   -> variable
#     REAL x, y, z;                                     -> variables
#
# Comments: 'comment ... ;', 'co ... co', '# ... #'; strings '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_]*"
# ALGOL 60 lower-case + ALGOL 68 upper-case primitive types
_TYPE = (r"(?:integer|real|boolean|string|char|complex|bits|bytes|"
         r"long\s+real|long\s+int|short\s+int|"
         r"INT|REAL|BOOL|CHAR|STRING|COMPL|BITS|BYTES|VOID|"
         r"LONG\s+REAL|LONG\s+INT|REF\s+" + _ID + r")")


class AlgolAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "algol"
    EXTENSIONS = (".algol", ".alg", ".a68")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()          # custom cleaner below
    STRING_DELIMS = ('"',)

    # ALGOL 60:  [type] procedure NAME (params) ;   /  procedure NAME ;
    _PROC60 = re.compile(r"(?i)(?:^|;|\bbegin\b)\s*(?:(" + _TYPE +
                         r")\s+)?procedure\s+(" + _ID + r")\s*(\([^)]*\))?")
    # ALGOL 68:  PROC NAME = (params) RETTYPE :   /  PROC NAME = RETTYPE :
    # RETTYPE may be a primitive (_TYPE) or a user-declared MODE (identifier).
    _PROC68 = re.compile(r"(?i)\bPROC\s+(" + _ID + r")\s*=\s*"
                         r"(\([^)]*\))?\s*((?:" + _TYPE + r")|" + _ID + r")?\s*:")
    _MODE = re.compile(r"(?i)\bMODE\s+(" + _ID + r")\s*=")
    _DECL = re.compile(r"(?im)(?:^|;|\bbegin\b)\s*(" + _TYPE + r")\s+"
                       r"(" + _ID + r"(?:\s*,\s*" + _ID + r")*)\s*(?=[;:=])")

    def _clean(self, text):
        # strip `comment ... ;`  and  `co ... co`  and  `# ... #`
        text = re.sub(r"(?is)\bcomment\b.*?;", " ", text)
        text = re.sub(r"(?is)\bco\b.*?\bco\b", " ", text)
        text = re.sub(r"(?s)#.*?#", " ", text)
        return self._strip_comments(text)

    def _register_types(self, file_id, text, path):
        clean = self._clean(text)
        for m in self._MODE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._clean(text)

        for m in self._MODE.finditer(clean):
            self._add_class(file_id, m.group(1), description="algol68 mode")

        seen_fn = set()
        for m in self._PROC60.finditer(clean):
            name = m.group(2)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            args = self._paren_args(m.group(3))
            outs = [self._add_output(m.group(1))] if m.group(1) else []
            self._add_function(file_id, name, args, outs,
                               description="algol procedure")
        for m in self._PROC68.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            args = self._paren_args(m.group(2))
            outs = [self._add_output(m.group(3))] if m.group(3) else []
            self._add_function(file_id, name, args, outs,
                               description="algol68 proc")

        seen_var = set()
        for m in self._DECL.finditer(clean):
            for raw in m.group(2).split(","):
                nm = raw.strip()
                if nm and nm not in seen_var and nm not in seen_fn:
                    seen_var.add(nm)
                    self._add_variable(file_id, nm, scope="module")

    def _paren_args(self, group):
        if not group or not group.strip("() "):
            return []
        inner = group.strip()[1:-1]
        arg_ids = []
        for part in self._split_top_level(inner):
            part = part.strip()
            if not part:
                continue
            toks = re.findall(_ID, part)
            if not toks:
                continue
            # A68 `INT a` -> name last, type first; A60 `a` -> name only
            name = toks[-1]
            atype = toks[0] if len(toks) >= 2 else None
            arg_ids.append(self._add_arg(name, atype))
        return arg_ids
