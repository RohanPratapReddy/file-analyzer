# Gmsh geometry script (.geo).
#
# Gmsh's built-in scripting language describes a CAD/mesh geometry as a
# sequence of numbered geometric entities plus named groupings, user
# functions/macros and scalar options:
#
#     lc = 0.1;                      // a user variable
#     Point(1) = {0, 0, 0, lc};      // numbered geometric entity
#     Line(1)  = {1, 2};
#     Physical Surface("inlet") = {1, 2};   // a *named* group
#     Function MyBox                 // a reusable macro
#       Point(newp) = {x, y, z, lc};
#     Return
#     Include "common.geo";          // pull in another script
#     Merge "mesh.msh";
#
# The named constructs this analyzer recovers:
#   * `Function name` / `Macro name` ... `Return`   -> function
#   * `Physical Point|Line|Curve|Surface|Volume("name")` -> class (named group)
#   * top-level `ident = expr;` scalar/array assignment -> variable
#   * `Include`/`Merge`/`ShapeFromFile("...")`      -> import
# Numbered geometric primitives (`Point(1)`, `Line(2)`, ...) are indexed, not
# named, so they carry no recoverable symbol and are intentionally skipped.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class GmshGeoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "gmsh_geo"
    EXTENSIONS = (".geo",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(r"(?m)^[ \t]*(?:Function|Macro)\s+(" + _ID + r")\s*$")
    _PHYS = re.compile(
        r"(?m)^[ \t]*Physical\s+"
        r"(?:Point|Line|Curve|Surface|Volume)\s*"
        r'(?:\(\s*)?"([^"]+)"'
    )
    # a top-level scalar / array assignment: ident [ = | += | -= | *= | /= ] ...
    _ASSIGN = re.compile(
        r"(?m)^[ \t]*(" + _ID + r")\s*(?:\[[^\]]*\])?" r"\s*(?:\+|-|\*|/)?=\s*([^;]+);"
    )
    _INCLUDE = re.compile(r'(?mi)^[ \t]*(?:Include|Merge)\s+"([^"]+)"')
    _SHAPEFILE = re.compile(r'(?i)ShapeFromFile\s*\(\s*"([^"]+)"')
    # DefineConstant[ name = value|... ]  -> a configurable variable
    _DEFCONST = re.compile(r"(?i)DefineConstant\s*\[\s*(" + _ID + r")\s*=")

    # reserved words that can appear on the LHS of `=` but are not variables
    _RESERVED = {
        "If",
        "ElseIf",
        "For",
        "While",
        "Return",
        "Physical",
        "Point",
        "Line",
        "Curve",
        "Surface",
        "Volume",
        "Circle",
        "Ellipse",
        "Spline",
        "BSpline",
        "Bezier",
        "Plane",
        "Transfinite",
        "Recombine",
        "Extrude",
        "Rotate",
        "Translate",
    }

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._FUNC.finditer(clean):
            self._add_function(
                file_id, m.group(1), [], [], description="Gmsh function/macro"
            )
        for m in self._PHYS.finditer(clean):
            self._add_class(file_id, m.group(1), description="Gmsh physical group")

        seen_v = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in self._RESERVED or name in seen_v:
                continue
            seen_v.add(name)
            self._add_variable(file_id, name, m.group(2).strip(), scope="module")
        for m in self._DEFCONST.finditer(clean):
            name = m.group(1)
            if name not in seen_v:
                seen_v.add(name)
                self._add_variable(file_id, name, None, scope="constant")

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split("/")[-1], src)
        for m in self._SHAPEFILE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split("/")[-1], src)
