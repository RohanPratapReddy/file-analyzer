# Wolfram Language (.wl, .wls, .m, .nb-lite) analyzer -- Mathematica language.
#
#     BeginPackage["MyPkg`"]                      -> class (package)
#     Needs["Other`"]                            -> import
#     Get["file.wl"]  /  << file.wl              -> import
#     f[x_] := x^2                               -> function (pattern def)
#     g[a_, b_Integer] := ...                    -> function
#     h[x_] : ...  (SetDelayed via :=)           -> function
#     const = 42                                 -> variable (immediate Set)
#     opts = {a -> 1}                            -> variable
#
# Comments are '(* *)' (nestable); strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z$][A-Za-z0-9$]*"


class WolframAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "wolfram"
    EXTENSIONS = (".wl", ".wls")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _PACKAGE = re.compile(r'BeginPackage\s*\[\s*"([^"`]+)`')
    _NEEDS = re.compile(r'(?:Needs|Get)\s*\[\s*"([^"`\]]+)`?[^"]*"')
    _GET = re.compile(r"(?m)^\s*<<\s*([^\s;]+)")
    # function definition:  name[ patterns ] := ...   (SetDelayed) or =  (Set)
    _FUNC = re.compile(r"(?m)^\s*(" + _ID + r")\s*\[([^\]]*)\]\s*:?=")
    # simple immediate assignment:  name = value  (not followed by '[' before '=')
    _VAR = re.compile(r"(?m)^\s*(" + _ID + r")\s*=(?![=.])")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._PACKAGE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._PACKAGE.finditer(clean):
            self._add_class(file_id, m.group(1), description="wolfram package")

        for m in self._NEEDS.finditer(clean):
            src = m.group(1)
            leaf = src.rstrip("`").split("`")[-1] or src
            self._add_import(file_id, leaf, src)
        for m in self._GET.finditer(clean):
            src = m.group(1).strip('"')
            leaf = re.split(r"[\\/`]", src)[-1]
            self._add_import(file_id, leaf, src)

        func_names = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            func_names.add(name)
            args = self._pattern_args(m.group(2))
            self._add_function(
                file_id, name, args, [], description="wolfram definition"
            )

        seen = set()
        for m in self._VAR.finditer(clean):
            name = m.group(1)
            if name in func_names or name in seen:
                continue
            seen.add(name)
            self._add_variable(file_id, name, scope="module")

    def _pattern_args(self, inner):
        arg_ids = []
        for part in self._split_top_level(inner):
            part = part.strip()
            if not part:
                continue
            # patterns look like  x_  x_Integer  x_:default  x__  x___
            mm = re.match(r"(" + _ID + r")_+([A-Za-z$]*)", part)
            if mm:
                atype = mm.group(2) or None
                arg_ids.append(self._add_arg(mm.group(1), atype))
        return arg_ids
