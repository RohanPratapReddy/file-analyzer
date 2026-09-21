# Groovy (.groovy) analyzer.
#
# Real parser for Groovy (`//` line, `/* */` block comments):
#   import groovy.json.JsonSlurper                -> import
#   class Foo extends Bar implements Baz { ... }   -> class (parents)
#   interface I { ... }   trait T   enum E          -> class row
#   def greet(name) { ... }                         -> function (dynamic)
#   String build(int n) { ... }                     -> function (typed)
#   def x = 5   int y = 1                           -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class GroovyAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "groovy"
    EXTENSIONS = (".groovy",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)

    _IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)(?:\s+as\s+(\w+))?",
                         re.MULTILINE)
    _CLASS = re.compile(
        r"^\s*(?:(?:public|private|protected|abstract|final|static)\s+)*"
        r"(class|interface|trait|enum)\s+(\w+)"
        r"(?:\s+extends\s+([\w.,\s]+?))?"
        r"(?:\s+implements\s+([\w.,\s]+?))?\s*\{", re.MULTILINE)
    _FUNC = re.compile(
        r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized)\s+)*"
        r"(?:def|void|[\w.<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s[\w.,\s]+)?\{",
        re.MULTILINE)
    _VAR = re.compile(
        r"^\s*(?:def|final)\s+(\w+)\s*=(?!=)", re.MULTILINE)

    _KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "new",
                 "else", "do", "try", "synchronized"}

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._CLASS.finditer(t):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._IMPORT.finditer(t):
            self._add_import(file_id, m.group(1).split(".")[-1], m.group(1),
                             alias=m.group(2))

        class_spans = []
        for m in self._CLASS.finditer(t):
            kind, name = m.group(1), m.group(2)
            end = self._find_matching(t, t.index("{", m.start()))
            class_spans.append((m.start(), end, name))
            parents = []
            for grp in (m.group(3), m.group(4)):
                if grp:
                    for p in grp.split(","):
                        pid = self._register_class(p.strip().split("<")[0])
                        if pid is not None:
                            parents.append(pid)
            self._add_class(file_id, name, description=f"groovy {kind}",
                            parent_ids=parents)

        def owner(pos):
            for a, b, name in class_spans:
                if a <= pos < b:
                    return self._class_registry.get(name)
            return None

        for m in self._FUNC.finditer(t):
            name = m.group(1)
            if name in self._KEYWORDS:
                continue
            self._add_function(file_id, name, self._args(m.group(2)),
                               class_id=owner(m.start()))
        for m in self._VAR.finditer(t):
            self._add_variable(file_id, m.group(1))

    def _args(self, params):
        ids = []
        for part in self._split_top_level(params):
            toks = part.split("=")[0].strip().split()
            if not toks:
                continue
            if len(toks) >= 2:
                ids.append(self._add_arg(toks[-1], " ".join(toks[:-1])))
            else:
                ids.append(self._add_arg(toks[-1]))
        return ids
