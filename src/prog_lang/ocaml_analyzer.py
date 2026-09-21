# OCaml (.ml implementation, .mli interface) analyzer.
#
# Real parser for OCaml ((* nesting *) comments, no line comments):
#   open Printf                                  -> import
#   module M = struct ... end                     -> module (class row)
#   module type S = sig ... end                   -> module type (class row)
#   type point = { x : float; y : float }         -> record type (class, fields)
#   type color = Red | Green | Blue               -> variant type (class, ctors)
#   let rec fact n = ...                           -> function
#   let pi = 3.14                                  -> value binding (variable)
#   class counter = object ... end                 -> class
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class OCamlAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ocaml"
    EXTENSIONS = (".ml", ".mli")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("(*", "*)"),)

    _OPEN = re.compile(r"^\s*open\s+([\w.]+)", re.MULTILINE)
    _INCLUDE = re.compile(r"^\s*include\s+([\w.]+)", re.MULTILINE)
    _MODULE = re.compile(r"^\s*module\s+(?:type\s+)?(\w+)", re.MULTILINE)
    _TYPE = re.compile(
        r"^\s*(?:and|type)\s+(?:'[\w\s']+\s+)?(\w+)\s*=\s*(.*?)(?=^\s*(?:let|type|and|module|class|exception|val|external|open|include)\b|\Z)",
        re.MULTILINE | re.DOTALL)
    _CLASS = re.compile(r"^\s*class\s+(?:virtual\s+)?(\w+)", re.MULTILINE)
    # A function binding has >=1 parameter token before '='; a value binding has
    # only the (optionally type-annotated) name.
    _LET_FUN = re.compile(r"^\s*let\s+(?:rec\s+)?(\w+)[ \t]+[^\n=]*[^\s=][ \t]*=(?!=)",
                          re.MULTILINE)
    _LET_VAL = re.compile(r"^\s*let\s+(?:rec\s+)?(\w+)\s*(?::[^=]+)?=(?!=)",
                          re.MULTILINE)
    _VAL = re.compile(r"^\s*(?:val|external)\s+(\w+)\s*:", re.MULTILINE)
    _FIELD = re.compile(r"(\w+)\s*:\s*([\w.'\s]+?)(?:;|\})")

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._MODULE.finditer(t):
            self._register_class(m.group(1))
        for m in self._TYPE.finditer(t):
            self._register_class(m.group(1))
        for m in self._CLASS.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._OPEN.finditer(t):
            self._add_import(file_id, m.group(1).split(".")[-1], m.group(1))
        for m in self._INCLUDE.finditer(t):
            self._add_import(file_id, m.group(1).split(".")[-1], m.group(1))

        for m in self._MODULE.finditer(t):
            self._add_class(file_id, m.group(1), description="ocaml module")

        for m in self._TYPE.finditer(t):
            name, rhs = m.group(1), m.group(2)
            attr_ids = []
            if "{" in rhs:  # record
                for fm in self._FIELD.finditer(rhs):
                    attr_ids.append(self._add_arg(fm.group(1),
                                                  fm.group(2).strip()))
            else:  # variant
                for ctor in rhs.split("|"):
                    cm = re.match(r"\s*([A-Z]\w*)", ctor)
                    if cm:
                        attr_ids.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="ocaml type",
                            attr_ids=attr_ids)

        for m in self._CLASS.finditer(t):
            self._add_class(file_id, m.group(1), description="ocaml class")

        emitted = set()
        for m in self._LET_FUN.finditer(t):
            name = m.group(1)
            emitted.add(name)
            self._add_function(file_id, name, description="ocaml let-binding")
        for m in self._VAL.finditer(t):
            name = m.group(1)
            if name not in emitted:
                emitted.add(name)
                self._add_function(file_id, name, description="ocaml val")
        for m in self._LET_VAL.finditer(t):
            name = m.group(1)
            if name not in emitted:
                emitted.add(name)
                self._add_variable(file_id, name)
