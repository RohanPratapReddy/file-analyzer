# MoonScript (.moon) analyzer.
#
# Real parser for MoonScript (an indentation-based language compiling to Lua;
# '--' line comments, no block comments; strings "..." and '...'):
#   import insert, concat from table                -> import (+ names)
#   import "socket"                                  -> import
#   export foo, bar                                  -> (export marker)
#   PI = 3.14159                                     -> variable
#   square = (x) -> x * x                            -> function
#   add = (a, b) -> a + b                            -> function
#   greet = (name) => print name                     -> function (fat arrow)
#   class Animal                                      -> class
#     new: (name) => @name = name                     -> method (constructor)
#     speak: => print @name                            -> method
#   class Dog extends Animal                          -> class (+ parent)
import re

from .regex_base import RegexCodeAnalyzer


class MoonScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "moonscript"
    EXTENSIONS = (".moon",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _IMPORT = re.compile(
        r"^\s*import\s+(.+?)\s+from\s+(.+)$|^\s*import\s+(['\"][^'\"]+['\"]|\S+)\s*$",
        re.MULTILINE,
    )
    _CLASS = re.compile(
        r"^([ \t]*)(?:export\s+)?class\s+([A-Za-z_]\w*)" r"(?:\s+extends\s+([\w.]+))?",
        re.MULTILINE,
    )
    _ASSIGN = re.compile(r"^([ \t]*)([A-Za-z_]\w*)\s*=\s*(.*)$", re.MULTILINE)
    # `export` explicitly marks module-level bindings regardless of nesting
    # depth (e.g. inside a top-level `do` block): `export a, b = 1, 2` /
    # `export foo = -> ...`. Bare `export name` (no `=`) just re-exports an
    # existing local and introduces no new binding, so it is ignored here.
    _EXPORT = re.compile(
        r"^[ \t]*export\s+(?!class\b|\*|\^|default\b)"
        r"([A-Za-z_][\w, ]*?)\s*=\s*(.*)$",
        re.MULTILINE,
    )
    _METHOD = re.compile(
        r"^([ \t]+)([A-Za-z_]\w*)\s*:\s*(?:\(([^)]*)\))?\s*(?:=>|->)", re.MULTILINE
    )

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._CLASS.finditer(text):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._IMPORT.finditer(text):
            if m.group(1) is not None:  # import a, b from mod
                names, mod = m.group(1), m.group(2).strip().strip("'\"")
                for nm in names.split(","):
                    nm = nm.strip().lstrip("\\")  # \method = colon-import sugar
                    if nm:
                        self._add_import(file_id, nm, f"{mod}.{nm}")
            else:  # import "mod"
                mod = m.group(3).strip().strip("'\"")
                self._add_import(file_id, re.split(r"[./]", mod)[-1], mod)

        # class bodies: capture parent + indented methods
        class_ranges = []
        for m in self._CLASS.finditer(text):
            name, parent = m.group(2), m.group(3)
            body = self._indent_body(text, m.start(), len(m.group(1)))
            bstart = text.find("\n", m.start()) + 1
            class_ranges.append((bstart, bstart + len(body)))
            parents = []
            if parent and parent in self._class_registry:
                parents.append(self._class_registry[parent])
            methods = []
            for mm in self._METHOD.finditer(body):
                params = mm.group(3) or ""
                arg_ids = [
                    self._add_arg(p.strip().lstrip("@"))
                    for p in params.split(",")
                    if p.strip()
                ]
                methods.append(
                    self._add_function(
                        file_id,
                        mm.group(2),
                        arg_ids,
                        [],
                        class_id=self._class_registry.get(name),
                        description="moonscript method",
                    )
                )
            self._add_class(
                file_id,
                name,
                description="moonscript class",
                parent_ids=parents,
                method_ids=methods,
            )

        def in_class(pos):
            return any(a <= pos < b for a, b in class_ranges)

        # explicit `export name(s) = value` -- module-level at any depth
        for m in self._EXPORT.finditer(text):
            if in_class(m.start()):
                continue
            names = [n.strip() for n in m.group(1).split(",") if n.strip()]
            val = m.group(2).strip()
            am = re.match(r"\(([^)]*)\)\s*(=>|->)", val)
            single_fn = len(names) == 1 and (
                am or val.startswith("->") or val.startswith("=>")
            )
            for nm in names:
                if single_fn:
                    params = am.group(1) if am else ""
                    arg_ids = [
                        self._add_arg(p.strip().lstrip("@"))
                        for p in params.split(",")
                        if p.strip()
                    ]
                    self._add_function(
                        file_id, nm, arg_ids, [], description="moonscript function"
                    )
                else:
                    self._add_variable(file_id, nm, val[:80] or None)

        # top-level assignments -> function (if value is an arrow) or variable
        for m in self._ASSIGN.finditer(text):
            if in_class(m.start()):
                continue
            if len(m.group(1)) != 0:  # only module-level (col 0)
                continue
            name, val = m.group(2), m.group(3).strip()
            am = re.match(r"\(([^)]*)\)\s*(=>|->)", val)
            if am or val.startswith("->") or val.startswith("=>"):
                params = am.group(1) if am else ""
                arg_ids = [
                    self._add_arg(p.strip().lstrip("@"))
                    for p in params.split(",")
                    if p.strip()
                ]
                self._add_function(
                    file_id, name, arg_ids, [], description="moonscript function"
                )
            else:
                self._add_variable(file_id, name, val[:80] or None)

    # ------------------------------------------------------------------
    def _indent_body(self, text, decl_start, base_indent):
        nl = text.find("\n", decl_start)
        if nl == -1:
            return ""
        out = []
        for line in text[nl + 1 :].splitlines(keepends=True):
            if line.strip() and self._indent_of(line) <= base_indent:
                break
            out.append(line)
        return "".join(out)
