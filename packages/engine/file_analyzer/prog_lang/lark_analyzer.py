# Lark (.lark) grammar analyzer.
#
# Real parser for Lark grammar files (Python `lark` library; '//' line comments):
#
#     // a grammar
#     start: expr                      -> rule (function, lowercase)
#     ?expr: term
#          | expr "+" term
#     term.2: factor                   -> rule with priority
#     NUMBER: /[0-9]+/                 -> terminal (variable, UPPERCASE)
#     STRING: /"[^"]*"/
#     %import common.WS                -> import
#     %ignore WS                       -> directive (variable)
#     %declare INDENT DEDENT
#
# Rules (lowercase, optionally `?`/`!`-prefixed or `.priority`) become functions;
# terminals (UPPERCASE) become variables; `%import` become imports.
import re

from .regex_base import RegexCodeAnalyzer


class LarkAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "lark"
    EXTENSIONS = (".lark",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _RULE = re.compile(
        r"^[ \t]*[?!]?([a-z_]\w*)(?:\.\-?\d+)?" r"(?:\{[^}]*\})?\s*:", re.MULTILINE
    )
    _TERM = re.compile(r"^[ \t]*([A-Z_][A-Z0-9_]*)(?:\.\-?\d+)?\s*:", re.MULTILINE)
    _IMPORT = re.compile(r"^[ \t]*%import\s+([^\s(]+)", re.MULTILINE)
    _IGNORE = re.compile(r"^[ \t]*%(ignore|declare)\s+(.+)$", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, re.split(r"\.", src)[-1], src)

        seen_r = set()
        for m in self._RULE.finditer(clean):
            name = m.group(1)
            if name in seen_r:
                continue
            seen_r.add(name)
            self._add_function(file_id, name, [], [], description="lark rule")

        seen_t = set()
        for m in self._TERM.finditer(clean):
            name = m.group(1)
            if name in seen_t:
                continue
            seen_t.add(name)
            self._add_variable(file_id, name, "terminal")

        for m in self._IGNORE.finditer(clean):
            kind = m.group(1)
            for name in re.split(r"[ \t]+", m.group(2).strip()):
                if re.match(r"^[A-Za-z_]\w*$", name) and name not in seen_t:
                    seen_t.add(name)
                    self._add_variable(file_id, name, f"%{kind}")
