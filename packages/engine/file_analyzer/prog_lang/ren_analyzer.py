# Ren'Py (.ren) visual-novel script analyzer.
#
# Ren'Py is an indentation-structured DSL with embedded Python.  Real
# constructs (regex; '#' line comments, Python strings protect their bodies):
#
#     define e = Character("Eileen")                   -> variable
#     default points = 0                               -> variable
#     image bg room = "images/room.png"                -> variable
#     label start:                                     -> function (label)
#     label sample(count=1):                           -> function (+ params)
#     menu choose:                                     -> function
#     screen inventory(items):                         -> function (screen)
#     transform hearts(delay=0.1):                     -> function
#     style my_button is button:                       -> variable (style)
#     $ score = score + 1                              -> variable ($-oneliner)
#     init python:                                     -> (block; body scanned)
#         def award(n):                                -> function
#         class Weapon:                                -> class
#
# `label`/`screen`/`transform`/`menu` blocks and `def` are functions; embedded
# `class` is a class; `define`/`default`/`image`/`style`/`$` bind variables.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class RenPyAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "renpy"
    EXTENSIONS = (".ren",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    # block-opening statements that carry a name (+ optional param list) then ':'
    _BLOCK = re.compile(
        r"^[ \t]*(label|screen|transform|menu|python|init)\b"
        r"(?:\s+([A-Za-z_][\w.]*))?\s*(\([^)]*\))?[^:\n]*:",
        re.MULTILINE,
    )
    _DEFINE = re.compile(
        r"^[ \t]*(?:define|default)\s+([A-Za-z_][\w.\[\]]*)\s*(?:=|\+=)", re.MULTILINE
    )
    _IMAGE = re.compile(r"^[ \t]*image\s+([A-Za-z_][\w ]*?)\s*=", re.MULTILINE)
    _STYLE = re.compile(r"^[ \t]*style\s+([A-Za-z_][\w.]*)\b", re.MULTILINE)
    _DOLLAR = re.compile(
        r"^[ \t]*\$\s*([A-Za-z_][\w.\[\]]*)\s*(?:=|\+=|-=|\*=)(?!=)", re.MULTILINE
    )
    # embedded Python
    _PYDEF = re.compile(r"^[ \t]*def\s+(" + _ID + r")\s*\(([^)]*)\)", re.MULTILINE)
    _PYCLASS = re.compile(
        r"^[ \t]*class\s+(" + _ID + r")\s*(?:\(([^)]*)\))?\s*:", re.MULTILINE
    )

    def _register_types(self, file_id, text, path):
        for m in self._PYCLASS.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        for m in self._PYCLASS.finditer(text):
            parents = []
            for p in self._split_top_level(m.group(2) or ""):
                p = p.split("=")[0].strip()
                if p and re.match(_ID + r"$", p):
                    pid = self._register_class(p)
                    if pid is not None:
                        parents.append(pid)
            self._add_class(
                file_id,
                m.group(1),
                description="renpy class",
                parent_ids=parents or None,
            )

        for m in self._DEFINE.finditer(text):
            self._add_variable(file_id, m.group(1), scope="define")
        for m in self._IMAGE.finditer(text):
            nm = m.group(1).strip().replace(" ", "_")
            self._add_variable(file_id, nm, scope="image")
        for m in self._STYLE.finditer(text):
            self._add_variable(file_id, m.group(1), scope="style")
        for m in self._DOLLAR.finditer(text):
            self._add_variable(file_id, m.group(1), scope="python")

        seen_fn = set()
        for m in self._BLOCK.finditer(text):
            kind, name, params = m.group(1), m.group(2), m.group(3)
            if kind in ("python", "init") and not name:
                continue  # bare `python:` / `init python:`
            if not name:
                # anonymous `menu:` -> synthesize a name from position
                name = kind
            key = (m.start(), name)
            if key in seen_fn:
                continue
            seen_fn.add(key)
            arg_ids = self._parse_params(params)
            self._add_function(file_id, name, arg_ids, [], description="renpy " + kind)

        for m in self._PYDEF.finditer(text):
            key = (m.start(), m.group(1))
            if key in seen_fn:
                continue
            seen_fn.add(key)
            arg_ids = self._parse_params("(" + (m.group(2) or "") + ")")
            self._add_function(
                file_id, m.group(1), arg_ids, [], description="renpy def"
            )

    def _parse_params(self, group):
        if not group:
            return []
        inner = group.strip()
        if inner.startswith("("):
            inner = inner[1:]
        inner = inner.rstrip(")")
        arg_ids = []
        for part in self._split_top_level(inner):
            part = part.split("=")[0].strip()
            if not part or part in ("self", "*", "**"):
                continue
            part = re.sub(r"^\*+", "", part).strip()
            nm = re.findall(_ID, part)
            if nm:
                arg_ids.append(self._add_arg(nm[0]))
        return arg_ids
