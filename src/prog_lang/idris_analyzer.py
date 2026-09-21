# Idris (.idr / .lidr) analyzer.
#
# Real parser for Idris 2 (Haskell-like; '--' line and nested '{- -}' block
# comments; strings "..."):
#   module Data.Vect                                     -> (module marker)
#   import Data.List                                       -> import
#   import public Data.Maybe as M                          -> import (aliased)
#   data Nat = Z | S Nat                                   -> type (class + cons)
#   record Point where constructor MkPoint; x : Int        -> record (class + fields)
#   interface Show a where show : a -> String              -> interface (class + members)
#   area : Double -> Double                                -> (type annotation)
#   area r = pi * r * r                                     -> function
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class IdrisAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "idris"
    EXTENSIONS = (".idr", ".lidr")
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()             # nested {- -} handled below
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r"^import\s+(?:public\s+)?([\w.]+)(?:\s+as\s+([\w.]+))?", re.MULTILINE)
    _DATA = re.compile(r"^data\s+([A-Z]\w*)", re.MULTILINE)
    _RECORD = re.compile(r"^record\s+([A-Z]\w*)", re.MULTILINE)
    _IFACE = re.compile(r"^(?:interface|class)\s+(?:.*?=>\s*)?([A-Z]\w*)", re.MULTILINE)
    _ANNOT = re.compile(r"^([a-z_]\w*'?)\s*:\s+(.+)$", re.MULTILINE)
    _DEF = re.compile(r"^([a-z_]\w*'?)\s+([^=\n|:]*?)=(?!=)", re.MULTILINE)

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
        """Indented block belonging to a declaration starting at line `decl_start`."""
        nl = text.find("\n", decl_start)
        if nl == -1:
            return ""
        base = self._indent_of(text[decl_start:nl])
        out, end = [], nl + 1
        for line in text[nl + 1:].splitlines(keepends=True):
            if line.strip() and self._indent_of(line) <= base:
                break
            out.append(line)
        return "".join(out)

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for rx in (self._DATA, self._RECORD, self._IFACE):
            for m in rx.finditer(text):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        for m in self._IMPORT.finditer(text):
            mod, alias = m.group(1), m.group(2)
            self._add_import(file_id, (alias or mod).split(".")[-1], mod, alias)

        # data -> constructors as attrs (both `= A | B` and GADT `where` forms)
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
            else:  # GADT: constructors are indented `Name : Type` lines
                body = self._indent_body(text, m.start())
                for cm in re.finditer(r"^\s+([A-Z]\w*)\s*:", body, re.MULTILINE):
                    cons.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="idris data", attr_ids=cons)

        # record -> fields as attrs
        for m in self._RECORD.finditer(text):
            name = m.group(1)
            body = self._indent_body(text, m.start())
            attrs = []
            for fm in re.finditer(r"^\s+([a-z_]\w*)\s*:\s+(.+)$", body, re.MULTILINE):
                if fm.group(1) != "constructor":
                    attrs.append(self._add_arg(fm.group(1), fm.group(2).strip()))
            self._add_class(file_id, name, description="idris record", attr_ids=attrs)

        # interface -> member signatures as methods
        for m in self._IFACE.finditer(text):
            name = m.group(1)
            body = self._indent_body(text, m.start())
            methods = []
            for mm in re.finditer(r"^\s+([a-z_]\w*'?)\s*:\s+", body, re.MULTILINE):
                methods.append(self._add_function(file_id, mm.group(1), [], [],
                               class_id=self._class_registry.get(name),
                               description="idris interface member"))
            self._add_class(file_id, name, description="idris interface",
                            method_ids=methods)

        annotations = {}
        for m in self._ANNOT.finditer(text):
            annotations.setdefault(m.group(1), m.group(2).strip())

        emitted = set()
        reserved = {"module", "import", "data", "record", "interface", "class",
                    "implementation", "where", "let", "in", "if", "then", "else",
                    "case", "of", "do", "mutual", "namespace", "public", "export",
                    "private", "total", "partial", "covering", "constructor"}
        for m in self._DEF.finditer(text):
            name, params = m.group(1), m.group(2).strip()
            if name in emitted or name in reserved:
                continue
            emitted.add(name)
            pnames = [p for p in re.split(r"\s+", params) if re.match(r"^[a-z_]\w*'?$", p)]
            if pnames:
                arg_ids = [self._add_arg(p) for p in pnames]
                out_ids = ([self._add_output(annotations[name].split("->")[-1].strip())]
                           if name in annotations and "->" in annotations[name] else [])
                self._add_function(file_id, name, arg_ids, out_ids)
            elif name in annotations:
                if "->" in annotations[name]:
                    self._add_function(file_id, name, [], [])
                else:
                    self._add_variable(file_id, name, None)
