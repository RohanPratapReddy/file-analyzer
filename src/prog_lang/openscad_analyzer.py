# OpenSCAD (.scad) analyzer.
#
# Real parser for the OpenSCAD solid-modelling language:
#
#     module roundedBox(size, radius = 2, center = false) { ... } -> function
#     function circumference(r) = 2 * PI * r;   -> function (with output)
#     wall_thickness = 3;                        -> variable
#     use <MCAD/involute_gears.scad>             -> import
#     include <utils.scad>                       -> import
#
# Comments are '//' and '/* ... */'; strings use '"'.  OpenSCAD has no classes;
# 'module' and 'function' are the only definitional forms.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_$][A-Za-z0-9_]*"


class OpenSCADAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "openscad"
    EXTENSIONS = (".scad",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _MODULE = re.compile(r"(?m)^\s*module\s+(" + _ID + r")\s*\(")
    _FUNCTION = re.compile(r"(?m)^\s*function\s+(" + _ID + r")\s*\(")
    _USE = re.compile(r"(?m)^\s*use\s*<([^>]+)>")
    _INCLUDE = re.compile(r"(?m)^\s*include\s*<([^>]+)>")
    _ASSIGN = re.compile(r"(?m)^\s*(" + _ID + r")\s*=(?!=)")

    def _params(self, text, open_paren):
        end = self._find_matching(text, open_paren, "(", ")")
        inner = text[open_paren + 1 : end - 1]
        ids = []
        for grp in self._split_top_level(inner):
            grp = grp.strip()
            if not grp:
                continue
            nm = re.match(_ID, grp)
            if not nm:
                continue
            default = None
            if "=" in grp:
                default = grp.split("=", 1)[1].strip()
            ids.append(self._add_arg(nm.group(0), default_value=default))
        return ids, end

    def _register_types(self, file_id, text, path):
        return  # OpenSCAD has no user-defined types

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._USE.finditer(clean):
            src = m.group(1).strip()
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)
        for m in self._INCLUDE.finditer(clean):
            src = m.group(1).strip()
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for m in self._MODULE.finditer(clean):
            args, _ = self._params(clean, m.end() - 1)
            self._add_function(
                file_id, m.group(1), args, [], description="openscad module"
            )

        for m in self._FUNCTION.finditer(clean):
            args, end = self._params(clean, m.end() - 1)
            # a function has a single expression body after '='
            out = [self._add_output("expr")]
            self._add_function(
                file_id, m.group(1), args, out, description="openscad function"
            )

        # only top-level (module-scope) assignments -> variables
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in ("module", "function", "use", "include"):
                continue
            self._add_variable(file_id, name, scope="module")
