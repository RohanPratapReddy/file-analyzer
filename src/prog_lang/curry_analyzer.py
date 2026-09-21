# Curry (.curry) analyzer.
#
# Real parser for Curry (a functional-logic language, Haskell-like; '--' line
# and nested '{- -}' block comments; strings "..."):
#   module Sort(sort) where                       -> (module marker)
#   import Data.List                               -> import
#   import Data.Maybe (fromJust) as M              -> import (aliased)
#   data Tree a = Leaf | Node a (Tree a)           -> type (class + constructors)
#   newtype Wrap = Wrap Int                         -> type (class)
#   type Name = String                              -> (type synonym) -> class
#   class Eq a where  eq :: a -> a -> Bool           -> class (+ member sigs)
#   instance Eq Int where ...                         -> (instance marker)
#   perm :: [a] -> [a]                                -> (type signature)
#   perm []     = []                                   -> function
#   solve x | x > 0 = ...                               -> function (guarded)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class CurryAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "curry"
    EXTENSIONS = (".curry",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()          # nested {- -} handled below
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r"^import\s+(?:qualified\s+)?([\w.]+)(?:.*?\bas\s+([\w.]+))?",
        re.MULTILINE)
    _DATA = re.compile(r"^(?:data|newtype)\s+([A-Z]\w*)", re.MULTILINE)
    _TYPESYN = re.compile(r"^type\s+([A-Z]\w*)", re.MULTILINE)
    _CLASS = re.compile(r"^class\s+(?:.*?=>\s*)?([A-Z]\w*)", re.MULTILINE)
    _SIG = re.compile(r"^([a-z_]\w*'?)\s*::\s*(.+)$", re.MULTILINE)
    _DEF = re.compile(r"^([a-z_]\w*'?)\s+([^=\n|]*?)(?:\|.*?)?=(?!=)", re.MULTILINE)

    def _strip_block(self, text):
        out, i, n, depth = [], 0, len(text), 0
        while i < n:
            if depth == 0 and text[i] == '"':
                out.append('"'); i += 1
                while i < n:
                    c = text[i]; out.append(c)
                    if c == "\\" and i + 1 < n:
                        out.append(text[i + 1]); i += 2; continue
                    i += 1
                    if c == '"':
                        break
                continue
            if text[i:i + 2] == "{-":
                depth += 1; out.append("  "); i += 2; continue
            if text[i:i + 2] == "-}" and depth > 0:
                depth -= 1; out.append("  "); i += 2; continue
            if depth > 0:
                out.append("\n" if text[i] == "\n" else " "); i += 1; continue
            out.append(text[i]); i += 1
        return "".join(out)

    def _clean(self, text):
        return self._strip_comments(self._strip_block(text))

    def _indent_body(self, text, decl_start):
        nl = text.find("\n", decl_start)
        if nl == -1:
            return ""
        base = self._indent_of(text[decl_start:nl])
        out = []
        for line in text[nl + 1:].splitlines(keepends=True):
            if line.strip() and self._indent_of(line) <= base:
                break
            out.append(line)
        return "".join(out)

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for rx in (self._DATA, self._TYPESYN, self._CLASS):
            for m in rx.finditer(text):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        for m in self._IMPORT.finditer(text):
            mod, alias = m.group(1), m.group(2)
            self._add_import(file_id, (alias or mod).split(".")[-1], mod, alias)

        # data / newtype -> constructors as attrs
        for m in self._DATA.finditer(text):
            name = m.group(1)
            line_end = text.find("\n", m.end())
            head = text[m.end():line_end if line_end != -1 else len(text)]
            cons = []
            if "=" in head:
                for part in head.split("=", 1)[1].split("|"):
                    cm = re.match(r"\s*([A-Z]\w*)", part)
                    if cm:
                        cons.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="curry data", attr_ids=cons)

        for m in self._TYPESYN.finditer(text):
            self._add_class(file_id, m.group(1), description="curry type synonym")

        # class -> member signatures as methods
        for m in self._CLASS.finditer(text):
            name = m.group(1)
            body = self._indent_body(text, m.start())
            methods = []
            for mm in re.finditer(r"^\s+([a-z_]\w*'?)\s*::", body, re.MULTILINE):
                methods.append(self._add_function(
                    file_id, mm.group(1), [], [],
                    class_id=self._class_registry.get(name),
                    description="curry class member"))
            self._add_class(file_id, name, description="curry class",
                            method_ids=methods)

        signatures = {}
        for m in self._SIG.finditer(text):
            signatures.setdefault(m.group(1), m.group(2).strip())

        reserved = {"module", "import", "data", "newtype", "type", "class",
                    "instance", "where", "let", "in", "if", "then", "else",
                    "case", "of", "do", "infixl", "infixr", "infix", "qualified"}
        emitted = set()
        for m in self._DEF.finditer(text):
            name, params = m.group(1), m.group(2).strip()
            if name in emitted or name in reserved:
                continue
            emitted.add(name)
            pnames = [p for p in re.split(r"\s+", params)
                      if re.match(r"^[a-z_]\w*'?$", p)]
            out_ids = ([self._add_output(signatures[name].split("->")[-1].strip())]
                       if name in signatures and "->" in signatures[name] else [])
            if pnames:
                arg_ids = [self._add_arg(p) for p in pnames]
                self._add_function(file_id, name, arg_ids, out_ids)
            elif name in signatures and "->" in signatures[name]:
                self._add_function(file_id, name, [], out_ids)
            else:
                self._add_variable(file_id, name, None)
