# Wren (.wren) analyzer.
#
# Real parser for Wren (small class-based scripting language, braces):
#   import "collection" for List, Map      -> import (+ selective names)
#   class Foo is Sequence { }               -> class (+ superclass via `is`)
#   construct new(a) { }                    -> constructor (method)
#   bar(a, b) { }                           -> method
#   static make() { }                       -> static method
#   name { _name }                          -> getter (method, no params)
#   name=(v) { }                            -> setter (method)
#   +(other) { }                            -> operator method
#   var Global = 5                          -> top-level variable
# Wren has no free functions; every method lives in a class.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class WrenAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "wren"
    EXTENSIONS = (".wren",)

    _IMPORT = re.compile(r'^\s*import\s+"([^"]+)"(?:\s+for\s+([^\n]+))?', re.MULTILINE)
    _CLASS = re.compile(
        r"\bclass\s+([A-Za-z_]\w*)\s*(?:is\s+([A-Za-z_][\w.]*)\s*)?\{")
    _VAR = re.compile(r"^\s*var\s+([A-Za-z_]\w*)\s*=\s*(.+)$", re.MULTILINE)
    _METHOD = re.compile(
        r"(?:(static|foreign)\s+)*"
        r"(construct\s+)?"
        r"([A-Za-z_]\w*=?|\[\]=?|[-+*/%<>=!&|~^]+)\s*"
        r"(?:\(([^)]*)\))?\s*\{")

    def _register_types(self, file_id, text, path):
        for m in self._CLASS.finditer(self._strip_comments(text)):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._IMPORT.finditer(text):
            src = m.group(1)
            self._add_import(file_id, src.split("/")[-1], src)

        class_spans = []
        for m in self._CLASS.finditer(text):
            name, parent = m.group(1), m.group(2)
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            parents = []
            if parent and parent.split(".")[-1] in self._class_registry:
                parents.append(self._class_registry[parent.split(".")[-1]])
            method_ids = []
            body = text[bstart + 1:bend - 1]
            covered = 0
            for mm in self._METHOD.finditer(body):
                if mm.start() < covered:
                    continue
                mname = mm.group(3)
                if mname in ("if", "for", "while", "else", "return"):
                    continue
                inner = body.index("{", mm.end() - 1)
                covered = self._find_matching(body, inner)
                arg_ids = self._params(mm.group(4) or "")
                fid = self._add_function(
                    file_id, mname, arg_ids, [],
                    class_id=self._class_registry.get(name),
                    description="constructor" if mm.group(2) else None)
                method_ids.append(fid)
            class_spans.append((bstart, bend))
            self._add_class(file_id, name, description="wren class",
                            parent_ids=parents, method_ids=method_ids)

        for m in self._VAR.finditer(text):
            if any(a <= m.start() < b for a, b in class_spans):
                continue
            self._add_variable(file_id, m.group(1), m.group(2).strip())

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if part:
                arg_ids.append(self._add_arg(part))
        return arg_ids
