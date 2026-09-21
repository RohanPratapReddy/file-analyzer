# PureScript (.purs) analyzer.
#
# Real parser for PureScript (Haskell-like; '--' line and nested '{- -}' block
# comments; strings "..."):
#   module Data.Foo (bar, Baz(..)) where                 -> (module marker)
#   import Data.List (head, tail)                          -> import (+ symbols)
#   import Data.Map as M                                   -> import (aliased)
#   data Color = Red | Green | Blue                        -> type (class + cons)
#   newtype Wrapper = Wrapper Int                           -> type (class)
#   type Point = { x :: Int, y :: Int }                    -> type alias (class + fields)
#   class Show a where show :: a -> String                 -> type class
#   area :: Number -> Number                                -> (type annotation)
#   area r = pi * r * r                                     -> function
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class PureScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "purescript"
    EXTENSIONS = (".purs",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()             # nested {- -} handled below
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r"^import\s+([\w.]+)(?:\s*\(([^)]*)\))?(?:\s+as\s+(\w+))?"
        r"(?:\s+hiding\s*\([^)]*\))?", re.MULTILINE)
    _DATA = re.compile(r"^(?:data|newtype)\s+([A-Z]\w*)", re.MULTILINE)
    _TYPE = re.compile(r"^type\s+([A-Z]\w*)", re.MULTILINE)
    _CLASS = re.compile(r"^class\s+(?:.*?=>\s*)?([A-Z]\w*)", re.MULTILINE)
    _ANNOT = re.compile(r"^([a-z_]\w*'?)\s*::\s*(.+)$", re.MULTILINE)
    _DEF = re.compile(r"^([a-z_]\w*'?)\s+([^=\n|]*?)=(?!=)", re.MULTILINE)
    _VALDEF = re.compile(r"^([a-z_]\w*'?)\s*=(?!=)", re.MULTILINE)

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

    def _decl_body(self, text, start):
        nl = text.find("\n", start)
        if nl == -1:
            return text[start:]
        end = nl + 1
        for line in text[nl + 1:].splitlines(keepends=True):
            if line[:1] not in (" ", "\t", "\n", "\r", ""):
                break
            end += len(line)
        return text[start:end]

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for rx in (self._DATA, self._TYPE, self._CLASS):
            for m in rx.finditer(text):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        # imports
        for m in self._IMPORT.finditer(text):
            mod, syms, alias = m.group(1), m.group(2), m.group(3)
            self._add_import(file_id, alias or mod.split(".")[-1], mod, alias)
            if syms:
                for sym in self._split_top_level(syms):
                    s = sym.split("(")[0].strip()
                    if s and re.match(r"^[A-Za-z_]", s):
                        self._add_import(file_id, s, f"{mod}.{s}")

        # data / newtype -> constructors as attrs
        for m in self._DATA.finditer(text):
            name = m.group(1)
            body = self._decl_body(text, m.end())
            rhs = body.split("=", 1)[1] if "=" in body else ""
            cons = []
            for part in rhs.split("|"):
                cm = re.match(r"\s*([A-Z]\w*)", part)
                if cm:
                    cons.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="purescript data", attr_ids=cons)

        # type alias -> record fields as attrs (when a record literal)
        for m in self._TYPE.finditer(text):
            name = m.group(1)
            body = self._decl_body(text, m.end())
            attrs = []
            rec = re.search(r"\{(.*)\}", body, re.DOTALL)
            if rec:
                for field in self._split_top_level(rec.group(1)):
                    fm = re.match(r"(\w+)\s*::\s*(.+)", field.strip(), re.DOTALL)
                    if fm:
                        attrs.append(self._add_arg(fm.group(1), fm.group(2).strip()))
            self._add_class(file_id, name, description="purescript type", attr_ids=attrs)

        # type classes -> class row with member method names
        for m in self._CLASS.finditer(text):
            name = m.group(1)
            body = self._decl_body(text, m.end())
            methods = []
            for mm in re.finditer(r"^\s+([a-z_]\w*'?)\s*::", body, re.MULTILINE):
                methods.append(self._add_function(file_id, mm.group(1), [], [],
                               class_id=self._class_registry.get(name),
                               description="purescript class member"))
            self._add_class(file_id, name, description="purescript class",
                            method_ids=methods)

        # top-level annotations (for return types)
        annotations = {}
        for m in self._ANNOT.finditer(text):
            annotations[m.group(1)] = m.group(2).strip()

        # top-level function/value definitions (column 0)
        emitted = set()
        for m in self._DEF.finditer(text):
            name, params = m.group(1), m.group(2).strip()
            if name in emitted or name in ("module", "import", "data", "type",
                                           "newtype", "class", "instance", "derive",
                                           "foreign", "where", "let", "in", "if",
                                           "then", "else", "case", "of"):
                continue
            emitted.add(name)
            pnames = [p for p in re.split(r"\s+", params) if re.match(r"^[a-z_]\w*'?$", p)]
            if pnames:
                arg_ids = [self._add_arg(p) for p in pnames]
                out_ids = ([self._add_output(annotations[name].split("->")[-1].strip())]
                           if name in annotations and "->" in annotations[name] else [])
                self._add_function(file_id, name, arg_ids, out_ids)
            else:
                if name in annotations and "->" in annotations[name]:
                    self._add_function(file_id, name, [], [])
                else:
                    self._add_variable(file_id, name, None)
