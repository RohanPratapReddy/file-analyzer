# Ink (.ink) analyzer -- inkle's interactive-narrative scripting language.
#
#     INCLUDE story_part2.ink                    -> import
#     === knot_name ===                          -> function (knot)
#     === function add(a, b) ===                 -> function (declared function)
#     = stitch_name                              -> function (stitch)
#     VAR health = 100                           -> variable
#     CONST TAX = 0.2                            -> variable
#     LIST colors = red, green, blue             -> variable
#     ~ temp x = 5                               -> variable
#     EXTERNAL roll_dice(sides)                  -> import (external binding)
#
# Comments are '//' and '/* */'; strings appear inline (no delimiter parsing needed).
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class InkAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ink"
    EXTENSIONS = (".ink",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ()

    _INCLUDE = re.compile(r"(?m)^\s*INCLUDE\s+(\S+)")
    _EXTERNAL = re.compile(r"(?m)^\s*EXTERNAL\s+(" + _ID + r")\s*\(([^)]*)\)")
    # knot:  === name ===  or  === name  or  === function name(args)
    _KNOT = re.compile(
        r"(?m)^\s*={2,}\s*(?:(function)\s+)?(" + _ID + r")\s*(\([^)]*\))?"
    )
    # stitch:  = name  (single '=', not '==')
    _STITCH = re.compile(r"(?m)^\s*=(?!=)\s*(" + _ID + r")\s*(\([^)]*\))?")
    _VAR = re.compile(r"(?m)^\s*(?:VAR|CONST|LIST)\s+(" + _ID + r")")
    _TEMP = re.compile(r"(?m)^\s*~\s*temp\s+(" + _ID + r")")

    def _register_types(self, file_id, text, path):
        # Ink has no class-like constructs.
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for m in self._EXTERNAL.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        for m in self._KNOT.finditer(clean):
            name = m.group(2)
            args = self._paren_args(m.group(3))
            desc = "ink function" if m.group(1) else "ink knot"
            self._add_function(file_id, name, args, [], description=desc)

        for m in self._STITCH.finditer(clean):
            name = m.group(1)
            args = self._paren_args(m.group(2))
            self._add_function(file_id, name, args, [], description="ink stitch")

        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="global")
        for m in self._TEMP.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="temp")

    def _paren_args(self, group):
        if not group:
            return []
        inner = group.strip()[1:-1]
        arg_ids = []
        for part in self._split_top_level(inner):
            name = part.strip().lstrip("ref").strip()
            name = part.strip().split()[-1] if part.strip().split() else ""
            if name and re.match(r"[A-Za-z_]", name):
                arg_ids.append(self._add_arg(name))
        return arg_ids
