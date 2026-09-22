# S-Lang / RenderMan Shading Language source (.sl).
#
# The `.sl` extension is shared by two unrelated languages; this analyzer
# recognises the named constructs of BOTH, since their declaration syntaxes do
# not collide.
#
# S-Lang (the jedsoft scripting/extension language):
#     variable x, y = 3;                 % module variables
#     define area (r) { return PI*r*r; } % a function
#     public define run () { ... }
#     typedef struct { x, y } Point;     % a named type
#     import("png");                     % load a module
#     () = evalfile("helpers.sl");
#
# RenderMan Shading Language (Pixar):
#     surface plastic (float Ka = 1; color Cs = 1) { ... }
#     displacement bumpy (float km = 1) { ... }
#     float noise3d (point p) { ... }    % a shader-local function
#
# Recovered symbols:
#   * S-Lang `define name` / SL shader `surface|displacement|light|volume|
#     imager|transformation name (...)` / SL `type name (...) { }` -> function
#   * `variable a, b, ...;`                       -> variable
#   * `typedef struct { ... } Name;`              -> class
#   * `import("m")` / `require("m")` / `evalfile("f")` / `#include`  -> import
# `%` starts an S-Lang comment; `//` and `/* */` cover the C-like SL dialect.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_SL_TYPES = r"float|point|vector|normal|color|string|matrix|void"


class SLangAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "slang"
    EXTENSIONS = (".sl",)
    LINE_COMMENTS = ("%", "//")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    # S-Lang function definition
    _DEFINE = re.compile(
        r"(?m)^[ \t]*(?:public\s+|private\s+|static\s+)?"
        r"define\s+(" + _ID + r")\s*\("
    )
    # RenderMan shader entry point
    _SHADER = re.compile(
        r"(?m)^[ \t]*(?:surface|displacement|light|volume|"
        r"imager|transformation)\s+(" + _ID + r")\s*\("
    )
    # RenderMan shader-local typed function:  float noise (point p) { ... }
    _SLFUNC = re.compile(
        r"(?m)^[ \t]*(?:" + _SL_TYPES + r")\s+(" + _ID + r")\s*\(([^)]*)\)\s*\{"
    )
    _VARIABLE = re.compile(r"(?m)^[ \t]*variable\s+([^;]+);")
    _TYPEDEF = re.compile(r"(?m)\btypedef\s+struct\s*\{[^}]*\}\s*(" + _ID + r")")
    _IMPORT = re.compile(
        r"(?m)\b(?:import|require|evalfile|autoload)\s*\(\s*" r'"([^"]+)"'
    )
    _INCLUDE = re.compile(r'(?m)^[ \t]*#\s*include\s+[<"]([^>"]+)[>"]')

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for rx, desc in (
            (self._DEFINE, "S-Lang function"),
            (self._SHADER, "RenderMan shader"),
            (self._SLFUNC, "SL function"),
        ):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name in seen_fn:
                    continue
                seen_fn.add(name)
                self._add_function(file_id, name, [], [], description=desc)

        seen_v = set()
        for m in self._VARIABLE.finditer(clean):
            for part in self._split_top_level(m.group(1)):
                name = part.split("=")[0].strip()
                if re.fullmatch(_ID, name) and name not in seen_v:
                    seen_v.add(name)
                    self._add_variable(file_id, name, None, scope="module")

        for m in self._TYPEDEF.finditer(clean):
            self._add_class(file_id, m.group(1), description="S-Lang struct type")

        for rx in (self._IMPORT, self._INCLUDE):
            for m in rx.finditer(clean):
                src = m.group(1)
                self._add_import(file_id, src.split("/")[-1], src)
