# GAMS (.gms) analyzer -- General Algebraic Modeling System.
#
# GAMS declarations come in keyword-introduced blocks terminated by ';':
#
#     Sets  i /seattle, san-diego/            -> variable (set) : i
#           j markets /new-york, chicago/ ;   -> variable (set) : j
#     Parameters a(i) capacity, b(j) demand ; -> variable (param) : a, b
#     Scalar f freight /90/ ;                 -> variable (scalar): f
#     Variables x(i,j), z ;                   -> variable (var)   : x, z
#     Equations cost, supply(i), demand(j) ;  -> function (equation): cost, ...
#     cost .. z =e= sum((i,j), c(i,j)*x) ;    -> function (equation def, deduped)
#     Table d(i,j) distances                  -> variable (table) : d
#     Model transport /all/ ;                 -> class
#     Solve transport using lp minimizing z ; -> (statement, ignored)
#     $include "sets.inc"                     -> import
#
# Comments are '*' in column 1 and '$ontext/$offtext' blocks; strings use quotes.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_]*"
_DECL_KW = {
    "set": "set", "sets": "set",
    "scalar": "scalar", "scalars": "scalar",
    "parameter": "param", "parameters": "param",
    "variable": "var", "variables": "var",
    "table": "table",
}
_VARQUAL = r"(?:positive|negative|binary|integer|free|nonnegative|sos1|sos2|semicont|semiint)"


class GAMSAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "gams"
    EXTENSIONS = (".gms",)
    LINE_COMMENTS = ()          # '*' comments handled explicitly (column 1 only)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _INCLUDE = re.compile(r'(?im)^\s*\$(?:bat)?include\s+(?:"([^"]+)"|(\S+))')
    _DECL = re.compile(
        r"(?is)^[ \t]*(" + _VARQUAL + r"\s+)?(sets?|scalars?|parameters?|"
        r"variables?|equations?|table)\b(.*?);", re.MULTILINE)
    _MODEL = re.compile(r"(?is)^[ \t]*models?\b(.*?);", re.MULTILINE)
    _EQDEF = re.compile(r"(?m)^\s*(" + _ID + r")\s*(?:\([^)]*\))?\s*\.\.")

    @staticmethod
    def _decomment(text):
        """Drop '*'-in-column-1 comment lines and $ontext/$offtext blocks."""
        out, skip = [], False
        for line in text.splitlines():
            low = line.strip().lower()
            if low.startswith("$ontext"):
                skip = True
                out.append("")
                continue
            if low.startswith("$offtext"):
                skip = False
                out.append("")
                continue
            if skip or line[:1] == "*":
                out.append("")
            else:
                out.append(line)
        return "\n".join(out)

    def _entry_names(self, body):
        """Leading identifier of every declaration entry in a block body."""
        # remove /.../ element/value lists, then treat newlines as separators
        body = re.sub(r"/[^/]*/", " ", body)
        body = body.replace("\n", ",")
        names = []
        for entry in self._split_top_level(body, sep=","):
            m = re.match(r"\s*(" + _ID + r")", entry)
            if m:
                names.append(m.group(1))
        return names

    def _register_types(self, file_id, text, path):
        clean = self._decomment(text)
        for m in self._MODEL.finditer(clean):
            for nm in self._entry_names(m.group(1)):
                self._register_class(nm)

    def _extract_entities(self, file_id, text, path):
        clean = self._decomment(text)

        for m in self._INCLUDE.finditer(clean):
            src = (m.group(1) or m.group(2) or "").strip()
            if src:
                leaf = re.split(r"[\\/]", src)[-1]
                self._add_import(file_id, leaf, src)

        seen_fn = set()
        for m in self._DECL.finditer(clean):
            kw = m.group(2).lower()
            body = m.group(3)
            if kw.startswith("equation"):
                for nm in self._entry_names(body):
                    if nm.lower() not in seen_fn:
                        self._add_function(file_id, nm, [], [],
                                           description="gams equation")
                        seen_fn.add(nm.lower())
            else:
                scope = _DECL_KW.get(kw, "gams")
                for nm in self._entry_names(body):
                    self._add_variable(file_id, nm, scope=scope)

        for m in self._EQDEF.finditer(clean):
            nm = m.group(1)
            if nm.lower() not in seen_fn:
                self._add_function(file_id, nm, [], [],
                                   description="gams equation definition")
                seen_fn.add(nm.lower())

        for m in self._MODEL.finditer(clean):
            for nm in self._entry_names(m.group(1)):
                self._add_class(file_id, nm, description="gams model")
