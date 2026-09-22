# J (.j) analyzer  (Jsoftware array language).
#
# Real parser for J:
#
#     name =: 3 : 'x + 1'                  -> function (explicit verb, monad)
#     name =: 4 : 0    ... )               -> function (explicit dyad, script body)
#     name =: verb define ... )            -> function (define form)
#     name =: {{ y + 1 }}                  -> function (direct definition)
#     name =: 2 3 5                        -> variable (noun assignment)
#     name =. localval                     -> variable (local assignment)
#     coclass 'Stack'                      -> class (locale / OOP)
#     load 'foo.ijs'  /  require 'addon'   -> import
#
# Comment token is 'NB.' to end of line; strings use single quotes.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_]*"
# a J explicit definition RHS begins with one of these shapes
_DEF_RE = re.compile(
    r"\b(?:verb|adverb|conjunction|monad|dyad)\b|" r"\bdefine\b|\{\{|[1-4]\s*:\s*"
)


class JAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "j"
    EXTENSIONS = (".j",)
    LINE_COMMENTS = ("NB.",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'",)

    _ASSIGN = re.compile(r"^[ \t]*(" + _ID + r")\s*=[.:]\s*(.*)$", re.MULTILINE)
    _COCLASS = re.compile(r"^[ \t]*coclass\s+'([^']+)'", re.MULTILINE)
    _LOAD = re.compile(r"^[ \t]*(?:load|loadd|require)\s+'([^']+)'", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._COCLASS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._LOAD.finditer(clean):
            for part in re.split(r"\s+", m.group(1).strip()):
                if part:
                    self._add_import(
                        file_id, part.replace("\\", "/").split("/")[-1], part
                    )

        for m in self._COCLASS.finditer(clean):
            self._add_class(file_id, m.group(1), description="j locale")

        for m in self._ASSIGN.finditer(clean):
            name, rhs = m.group(1), m.group(2)
            if _DEF_RE.search(rhs):
                self._add_function(file_id, name, [], [], description="j verb")
            else:
                self._add_variable(file_id, name)
