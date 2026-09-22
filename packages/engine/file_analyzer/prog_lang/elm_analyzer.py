# Elm (.elm) analyzer.
#
# Real parser for Elm (layout-sensitive, '--' line and nested '{- -}' block
# comments; strings "..."):
#   module Main exposing (main, view)                    -> (module marker)
#   import Html exposing (text, div)                      -> import (module + symbols)
#   import Json.Decode as Decode                           -> import (aliased)
#   type alias Point = { x : Int, y : Int }               -> record alias (class)
#   type Color = Red | Green | Blue                        -> union type (class + cons)
#   add : Int -> Int -> Int                                -> (type annotation)
#   add a b = a + b                                         -> function
#   config = { debug = True }                               -> variable
import re

from .regex_base import RegexCodeAnalyzer


class ElmAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "elm"
    EXTENSIONS = (".elm",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()  # nested {- -} handled below
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r"^import\s+([\w.]+)(?:\s+as\s+(\w+))?(?:\s+exposing\s*\(([^)]*)\))?",
        re.MULTILINE,
    )
    _TYPE_ALIAS = re.compile(r"^type\s+alias\s+([A-Z]\w*)\s*(?:[\w ]*)=", re.MULTILINE)
    _TYPE = re.compile(r"^type\s+([A-Z]\w*)\s*(?:[\w ]*)=", re.MULTILINE)
    _DEF = re.compile(r"^([a-z]\w*)\s+([^=\n]*?)=", re.MULTILINE)
    _VALDEF = re.compile(r"^([a-z]\w*)\s*=", re.MULTILINE)
    _ANNOT = re.compile(r"^([a-z]\w*)\s*:\s*(.+)$", re.MULTILINE)

    def _strip_block(self, text):
        """Remove nested {- -} comments, preserving newlines/strings."""
        out = []
        i, n, depth = 0, len(text), 0
        while i < n:
            if depth == 0 and text[i] == '"':
                out.append('"')
                i += 1
                while i < n:
                    c = text[i]
                    out.append(c)
                    if c == "\\" and i + 1 < n:
                        out.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    if c == '"':
                        break
                continue
            if text[i : i + 2] == "{-":
                depth += 1
                out.append("  ")
                i += 2
                continue
            if text[i : i + 2] == "-}" and depth > 0:
                depth -= 1
                out.append("  ")
                i += 2
                continue
            if depth > 0:
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
                continue
            out.append(text[i])
            i += 1
        return "".join(out)

    def _clean(self, text):
        return self._strip_comments(self._strip_block(text))

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for m in self._TYPE_ALIAS.finditer(text):
            self._register_class(m.group(1))
        for m in self._TYPE.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        # imports
        for m in self._IMPORT.finditer(text):
            mod, alias, exposing = m.group(1), m.group(2), m.group(3)
            self._add_import(file_id, alias or mod.split(".")[-1], mod, alias)
            if exposing and exposing.strip() != "..":
                for sym in exposing.split(","):
                    sym = sym.strip().split("(")[0].strip()
                    if sym and sym not in ("", ".."):
                        self._add_import(file_id, sym, f"{mod}.{sym}")

        # collect type annotations (return-type info for functions)
        annotations = {}
        for m in self._ANNOT.finditer(text):
            annotations[m.group(1)] = m.group(2).strip()

        # type alias -> record fields as attrs (if a record body)
        alias_names = set()
        for m in self._TYPE_ALIAS.finditer(text):
            name = m.group(1)
            alias_names.add(name)
            body = self._decl_body(text, m.end())
            attrs = []
            rec = re.search(r"\{(.*)\}", body, re.DOTALL)
            if rec:
                for field in self._split_top_level(rec.group(1)):
                    fm = re.match(r"(\w+)\s*:\s*(.+)", field.strip(), re.DOTALL)
                    if fm:
                        attrs.append(self._add_arg(fm.group(1), fm.group(2).strip()))
            self._add_class(file_id, name, description="elm type alias", attr_ids=attrs)

        # union types -> constructors as attrs
        for m in self._TYPE.finditer(text):
            name = m.group(1)
            if name in alias_names:
                continue
            body = self._decl_body(text, m.end())
            cons = []
            for con in body.split("|"):
                cm = re.match(r"\s*([A-Z]\w*)", con)
                if cm:
                    cons.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="elm union type", attr_ids=cons)

        # top-level definitions (column-0 lowercase name)
        emitted = set()
        for m in self._DEF.finditer(text):
            name, params_raw = m.group(1), m.group(2).strip()
            if name in emitted or name in (
                "module",
                "import",
                "type",
                "port",
                "if",
                "then",
                "else",
                "let",
                "in",
                "case",
            ):
                continue
            emitted.add(name)
            params = [
                p
                for p in re.split(r"\s+", params_raw)
                if p and re.match(r"^[a-z_]\w*$", p)
            ]
            if params:
                arg_ids = [self._add_arg(p) for p in params]
                out_ids = (
                    [self._add_output(annotations[name].split("->")[-1].strip())]
                    if name in annotations and "->" in annotations[name]
                    else []
                )
                self._add_function(file_id, name, arg_ids, out_ids)
            else:
                # nullary def: function if annotated with '->', else variable
                if name in annotations and "->" in annotations[name]:
                    self._add_function(file_id, name, [], [])
                else:
                    self._add_variable(file_id, name, None)

    def _decl_body(self, text, start):
        """Text of a declaration from `start` up to the next top-level (col-0) line."""
        nl = text.find("\n", start)
        if nl == -1:
            return text[start:]
        rest = text[nl + 1 :]
        end = nl + 1
        for line in rest.splitlines(keepends=True):
            if line[:1] not in (" ", "\t", "\n", "\r", ""):
                break
            end += len(line)
        return text[start:end]
