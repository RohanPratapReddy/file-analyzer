# Simula (.simula/.sim) analyzer  (Simula 67, the original OO language).
#
# Real parser for Simula:
#
#     Class Point(x, y); Integer x, y; ...  -> class
#     Point Class ColouredPoint(c); ...      -> class (prefix = base class)
#     Integer Procedure Add(a, b); ...       -> function
#     Procedure Draw; ...                    -> function
#     Integer i, j;   Ref(Point) p;          -> variables
#     External Class Simset;                 -> import
#
# Simula is case-insensitive.  Comments are 'comment ... ;' and '! ... ;'
# (both terminated by a semicolon, NOT a newline); strings use '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_]*"
_TYPE = r"(?:integer|short\s+integer|real|long\s+real|boolean|character|text|ref\s*\([^)]*\))"
_ML = re.IGNORECASE | re.MULTILINE


class SimulaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "simula"
    EXTENSIONS = (".simula", ".sim")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _CLASS = re.compile(r"\bclass\s+(" + _ID + r")", _ML)
    _PARENT = re.compile(r"(" + _ID + r")\s+class\s+(" + _ID + r")", _ML)
    _PROC = re.compile(
        r"(?:" + _TYPE + r"\s+)?\bprocedure\s+(" + _ID + r")", _ML)
    _VARDECL = re.compile(
        r"(?:(?<=;)|^)[ \t]*(" + _TYPE +
        r")\s+((?:array\s+)?[A-Za-z][\w, ()\[\]:.+*-]*?)\s*;",
        _ML)
    _EXTERNAL = re.compile(
        r"^[ \t]*external\b[^;]*?\b(?:class|procedure)\s+(" + _ID + r")", _ML)
    _IDRX = re.compile(_ID)

    def _scrub(self, text):
        """Remove Simula 'comment ... ;' and '! ... ;' comments (string-aware),
        preserving newlines so line-anchored patterns keep aligning."""
        out, i, n = [], 0, len(text)
        while i < n:
            c = text[i]
            if c == '"':
                out.append(c); i += 1
                while i < n:
                    out.append(text[i])
                    if text[i] == '"':
                        i += 1; break
                    i += 1
                continue
            start_comment = False
            if c == "!":
                start_comment = True
            elif c in "cC" and text[i:i + 7].lower() == "comment":
                before = text[i - 1] if i else " "
                after = text[i + 7] if i + 7 < n else " "
                if not (before.isalnum() or before == "_") and \
                   not (after.isalnum() or after == "_"):
                    start_comment = True
            if start_comment:
                j = text.find(";", i)
                j = n if j == -1 else j + 1
                out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
                i = j
                continue
            out.append(c); i += 1
        return "".join(out)

    def _names(self, blob):
        blob = re.sub(r"(?i)^\s*array\s+", "", blob)
        names = []
        for part in blob.split(","):
            m = self._IDRX.match(part.strip())
            if m:
                names.append(m.group(0))
        return names

    def _register_types(self, file_id, text, path):
        clean = self._scrub(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._scrub(text)

        for m in self._EXTERNAL.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        parents = {}   # derived name -> base id
        for m in self._PARENT.finditer(clean):
            parents[m.group(2)] = self._register_class(m.group(1))
        for m in self._CLASS.finditer(clean):
            name = m.group(1)
            pid = parents.get(name)
            self._add_class(file_id, name, description="simula class",
                            parent_ids=[pid] if pid else None)

        for m in self._PROC.finditer(clean):
            self._add_function(file_id, m.group(1), [], [],
                               description="simula procedure")

        for m in self._VARDECL.finditer(clean):
            rest = m.group(2)
            if re.search(r"(?i)\bprocedure\b|\bclass\b", rest):
                continue
            for nm in self._names(rest):
                self._add_variable(file_id, nm)
