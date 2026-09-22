# Gleam (.gleam) analyzer.
#
# Real parser for Gleam ('//' line, '///' doc, '////' module-doc comments; no block
# comments; strings "..."):
#   import gleam/list                                     -> import
#   import gleam/io.{println, print}                       -> import (+ symbols)
#   import gleam/string as str                             -> import (aliased)
#   pub type Point { Point(x: Int, y: Int) }               -> type (class + cons + fields)
#   pub type Color { Red  Green  Blue }                    -> type (class + variants)
#   pub fn area(r: Float) -> Float { ... }                 -> function
#   pub const pi: Float = 3.14159                           -> variable
import re

from .regex_base import RegexCodeAnalyzer


class GleamAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "gleam"
    EXTENSIONS = (".gleam",)
    LINE_COMMENTS = ("//",)  # covers // /// ////
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r"^\s*import\s+([\w/]+)(?:\.\{([^}]*)\})?(?:\s+as\s+(\w+))?", re.MULTILINE
    )
    _TYPE = re.compile(r"^\s*(?:pub\s+)?(?:opaque\s+)?type\s+([A-Z]\w*)", re.MULTILINE)
    _ALIAS = re.compile(
        r"^\s*(?:pub\s+)?type\s+([A-Z]\w*)\s*(?:\([^)]*\))?\s*=", re.MULTILINE
    )
    _FN = re.compile(
        r"^\s*(?:pub\s+)?fn\s+([a-z_]\w*)\s*\(([^)]*)\)"
        r"(?:\s*->\s*([\w()/., ]+?))?\s*\{",
        re.MULTILINE,
    )
    _CONST = re.compile(r"^\s*(?:pub\s+)?const\s+([a-z_]\w*)", re.MULTILINE)
    _EXTFN = re.compile(
        r"^\s*@external\([^)]*\)\s*(?:pub\s+)?fn\s+([a-z_]\w*)", re.MULTILINE
    )

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._TYPE.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        # imports
        for m in self._IMPORT.finditer(text):
            mod, syms, alias = m.group(1), m.group(2), m.group(3)
            leaf = mod.split("/")[-1]
            self._add_import(file_id, alias or leaf, mod, alias)
            if syms:
                for sym in syms.split(","):
                    s = sym.strip()
                    s = re.sub(r"^(?:type\s+)?", "", s).split(" as ")[0].strip()
                    if s:
                        self._add_import(file_id, s, f"{mod}.{s}")

        alias_names = {m.group(1) for m in self._ALIAS.finditer(text)}

        # custom types -> variants (constructors) + their labelled fields as attrs
        for m in self._TYPE.finditer(text):
            name = m.group(1)
            if name in alias_names:
                self._add_class(file_id, name, description="gleam type alias")
                continue
            lb = text.find("{", m.end())
            attrs = []
            if lb != -1 and (text.find("=", m.end(), lb) == -1):
                rb = self._find_matching(text, lb, "{", "}")
                body = text[lb + 1 : rb - 1]
                # variant constructors:  Name(field: Type, ...)  or bare  Name
                for vm in re.finditer(r"([A-Z]\w*)\s*(?:\(([^)]*)\))?", body):
                    attrs.append(self._add_arg(vm.group(1), "variant"))
                    if vm.group(2):
                        for fld in self._split_top_level(vm.group(2)):
                            fm = re.match(r"(\w+)\s*:\s*(.+)", fld.strip())
                            if fm:
                                attrs.append(
                                    self._add_arg(fm.group(1), fm.group(2).strip())
                                )
            self._add_class(file_id, name, description="gleam type", attr_ids=attrs)

        # functions
        ext_names = {m.group(1) for m in self._EXTFN.finditer(text)}
        for m in self._FN.finditer(text):
            name = m.group(1)
            arg_ids = []
            for part in self._split_top_level(m.group(2) or ""):
                pm = re.match(r"(?:_\s+)?(\w+)\s*(?::\s*(.+))?", part.strip())
                if pm:
                    arg_ids.append(
                        self._add_arg(
                            pm.group(1), pm.group(2).strip() if pm.group(2) else None
                        )
                    )
            out_ids = [self._add_output(m.group(3).strip())] if m.group(3) else []
            self._add_function(file_id, name, arg_ids, out_ids)
        for name in ext_names:
            self._add_function(file_id, name, [], [], description="gleam external")

        # constants
        for m in self._CONST.finditer(text):
            self._add_variable(file_id, m.group(1), None)
