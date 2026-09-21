# Processing (.pde) analyzer.
#
# Processing sketches are Java with the class/method boilerplate implied, so we
# parse the same declarations Java exposes at the top level of a sketch:
#
#     import processing.sound.*;              -> import
#     int score = 0;                          -> variable (top-level field)
#     PVector pos;                            -> variable
#     void setup() { ... }                    -> function
#     int add(int a, int b) { ... }           -> function
#     class Ball extends Sprite { ... }       -> class (methods as members)
#     interface Drawable { ... }              -> class
#
# Comments are '//' and '/* */'; strings use '"' and "'".
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_$][A-Za-z0-9_$]*"
_TYPE = r"[A-Za-z_$][A-Za-z0-9_$<>\[\].]*"
_KEYWORDS = {
    "if", "for", "while", "switch", "return", "else", "do", "catch", "try",
    "synchronized", "new", "case", "break", "continue", "super", "this",
}


class ProcessingAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "processing"
    EXTENSIONS = (".pde",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _IMPORT = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)\s*;")
    _CLASS = re.compile(
        r"(?m)^\s*(?:public\s+|abstract\s+|final\s+|static\s+)*"
        r"(class|interface)\s+(" + _ID + r")"
        r"(?:\s+extends\s+(" + _TYPE + r"))?"
        r"(?:\s+implements\s+([\w.,<>\s]+?))?\s*\{")
    _FUNC = re.compile(
        r"(?m)^[ \t]*(?:public\s+|private\s+|protected\s+|static\s+|final\s+"
        r"|abstract\s+)*(" + _TYPE + r")\s+(" + _ID + r")\s*\(([^)]*)\)\s*\{")
    _METHOD = _FUNC
    _FIELD = re.compile(
        r"(?m)^[ \t]*(?:public\s+|private\s+|protected\s+|static\s+|final\s+)*"
        r"(" + _TYPE + r")\s+(" + _ID + r")\s*(?:=[^;]*)?;")

    def _args(self, inner):
        ids = []
        for a in self._split_top_level(inner):
            a = a.strip().replace("final ", "")
            if not a:
                continue
            parts = a.split()
            nm = parts[-1].split("[")[0]
            typ = " ".join(parts[:-1]) or None
            if re.match(_ID + r"$", nm):
                ids.append(self._add_arg(nm, arg_type=typ))
        return ids

    def _class_spans(self, clean):
        spans = []
        for m in self._CLASS.finditer(clean):
            end = self._find_matching(clean, m.end() - 1)
            spans.append((m.start(), end))
        return spans

    def _in_class(self, pos, spans):
        return any(a <= pos < b for a, b in spans)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            leaf = src.rstrip(".*").split(".")[-1]
            self._add_import(file_id, leaf, src)

        spans = self._class_spans(clean)

        for m in self._CLASS.finditer(clean):
            body_start, body_end = m.end() - 1, self._find_matching(clean, m.end() - 1)
            body = clean[m.end():body_end]
            method_ids = []
            for mm in self._METHOD.finditer(body):
                if mm.group(1) in _KEYWORDS or mm.group(2) in _KEYWORDS:
                    continue
                method_ids.append(self._add_function(
                    file_id, mm.group(2), self._args(mm.group(3)), [],
                    description="processing method"))
            parents = []
            if m.group(3):
                parents.append(self._register_class(m.group(3)))
            for impl in self._split_top_level(m.group(4) or ""):
                parents.append(self._register_class(impl.strip()))
            self._add_class(file_id, m.group(2), description="processing " + m.group(1),
                            parent_ids=parents or None, method_ids=method_ids or None)

        # top-level functions and fields (outside any class body)
        for m in self._FUNC.finditer(clean):
            if self._in_class(m.start(), spans):
                continue
            if m.group(1) in _KEYWORDS or m.group(2) in _KEYWORDS:
                continue
            self._add_function(file_id, m.group(2), self._args(m.group(3)), [],
                               description="processing function")
        for m in self._FIELD.finditer(clean):
            if self._in_class(m.start(), spans):
                continue
            if m.group(1) in _KEYWORDS or m.group(2) in _KEYWORDS:
                continue
            self._add_variable(file_id, m.group(2), scope="module")
