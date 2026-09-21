# Scilab (.sci, .sce) analyzer -- numerical-computation language (MATLAB-like).
#
#     function y = f(a, b) ... endfunction        -> function (1 output)
#     function [x, y] = g(a) ... endfunction      -> function (multi output)
#     function h(a)  ... endfunction              -> function (no output)
#     exec("lib.sci", -1);   /   getf("x.sci")    -> import
#     x = 5;   /   A = [1 2 3];                    -> variable (assignment)
#     global G                                     -> variable
#
# Comments are '//'; strings use '"' and single-quote (also transpose -- we
# treat only '"' as a delimiter to avoid transpose ambiguity).
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_%][A-Za-z0-9_]*"
# Scilab also permits legacy special characters (#, !, $, ?) inside some
# macro/function names (e.g. `function #_deff_wrapper(...)`).
_FID = r"[A-Za-z_%#!$?][A-Za-z0-9_#!$?]*"


class ScilabAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "scilab"
    EXTENSIONS = (".sci", ".sce")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    # function [out1,out2] = name(args)  |  function out = name(args)  |  function name(args)
    _FUNC = re.compile(
        r"(?m)^\s*function\s+"
        r"(?:\[([^\]]*)\]\s*=\s*|(" + _ID + r")\s*=\s*)?"
        r"(" + _FID + r")\s*(\([^)]*\))?"
    )
    _IMPORT = re.compile(
        r'(?m)(?:exec|getf|load|loadmatfile|getd)\s*\(\s*["\']([^"\']+)["\']'
    )
    _GLOBAL = re.compile(r"(?m)^\s*global\s+(.+)$")
    _ASSIGN = re.compile(r"(?m)^\s*(" + _ID + r")\s*=(?![=])")

    def _register_types(self, file_id, text, path):
        # Scilab has no class construct.
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        func_names = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(3)
            func_names.add(name)
            out_ids = []
            outs = m.group(1) if m.group(1) is not None else m.group(2)
            if outs:
                for o in self._split_top_level(outs):
                    o = o.strip()
                    if o:
                        out_ids.append(self._add_output(o))
            args = self._paren_args(m.group(4))
            self._add_function(
                file_id, name, args, out_ids, description="scilab function"
            )

        seen = set()
        for m in self._GLOBAL.finditer(clean):
            for name in re.split(r"[\s,]+", m.group(1).strip()):
                if name and re.match(r"[A-Za-z_%]", name) and name not in seen:
                    seen.add(name)
                    self._add_variable(file_id, name, scope="global")

        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in func_names or name in seen:
                continue
            seen.add(name)
            self._add_variable(file_id, name, scope="module")

    def _paren_args(self, group):
        if not group:
            return []
        inner = group.strip()[1:-1]
        arg_ids = []
        for part in self._split_top_level(inner):
            name = part.strip()
            if name and re.match(r"[A-Za-z_%]", name):
                arg_ids.append(self._add_arg(name))
        return arg_ids
