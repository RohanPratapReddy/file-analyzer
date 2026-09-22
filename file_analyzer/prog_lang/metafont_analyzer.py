# Metafont (.mf).
#
# Metafont is Knuth's font-description language (sibling of MetaPost).  Named
# constructs:
#
#     input plain;
#     numeric u, py; pair z[];
#     def spot = pickup pencircle enddef;
#     vardef aa@#(expr w) = ... enddef;
#     primarydef a dotprod b = ... enddef;
#     beginchar ("A", 9u#, cap#, 0); ... endchar;
#     newinternal tracingtitles;
#
#   input NAME                                   -> import
#   def / vardef NAME                            -> function
#   primarydef/secondarydef/tertiarydef a OP b   -> function (named by OP)
#   beginchar (code, ...)                         -> function (char builder)
#   numeric/pair/path/pen/picture/transform/     -> variable
#     string/boolean/newinternal  declarations
#
# Comments run from `%` to end of line; there are no block comments.  Metafont
# identifiers are letter-runs that may embed `.` and a trailing `@#` sparker.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_.]*"
_TYPES = ("numeric", "pair", "path", "pen", "picture", "transform", "string", "boolean")


class MetafontAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "metafont"
    EXTENSIONS = (".mf",)
    LINE_COMMENTS = ("%",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _INPUT = re.compile(r"(?m)\binput\s+(" + _ID + r")")
    _DEF = re.compile(r"(?m)\b(?:def|vardef)\s+(" + _ID + r")(@#)?")
    _OPDEF = re.compile(
        r"(?m)\b(?:primary|secondary|tertiary)def\s+"
        + _ID
        + r"\s+("
        + _ID
        + r"|[-+*/<>=|&.]+)\s+"
        + _ID
    )
    _BEGINCHAR = re.compile(r'(?m)\bbeginchar\s*\(\s*("[^"]*"|[^,]+),')
    # declarations may share a line (`numeric u, py; pair z[];`) so this is not
    # line-anchored; a single decl runs from its type keyword to the next `;`.
    _DECL = re.compile(r"(?m)\b(" + "|".join(_TYPES) + r")\s+([^;{}=\n]+);")
    _NEWINT = re.compile(r"(?m)\bnewinternal\s+([^;]+);")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INPUT.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        seen_fn = set()
        for m in self._DEF.finditer(clean):
            nm = m.group(1) + (m.group(2) or "")
            if nm in seen_fn:
                continue
            seen_fn.add(nm)
            self._add_function(file_id, nm, [], [], description="metafont macro")
        for m in self._OPDEF.finditer(clean):
            op = m.group(1)
            if op in seen_fn:
                continue
            seen_fn.add(op)
            self._add_function(
                file_id,
                op,
                [self._add_arg("a"), self._add_arg("b")],
                [],
                description="metafont operator macro",
            )
        for m in self._BEGINCHAR.finditer(clean):
            code = m.group(1).strip().strip('"')
            nm = "char_" + re.sub(r"[^A-Za-z0-9_]", "_", code)[:24]
            if nm in seen_fn:
                continue
            seen_fn.add(nm)
            self._add_function(file_id, nm, [], [], description="metafont character")

        seen_v = set()

        def _emit_vars(names):
            for raw in self._split_top_level(names):
                nm = re.split(r"[\[\(]", raw.strip())[0].strip()
                if (
                    re.fullmatch(_ID, nm or "")
                    and nm not in seen_v
                    and nm not in seen_fn
                ):
                    seen_v.add(nm)
                    self._add_variable(file_id, nm, None, scope="module")

        for m in self._DECL.finditer(clean):
            _emit_vars(m.group(2))
        for m in self._NEWINT.finditer(clean):
            _emit_vars(m.group(1))
