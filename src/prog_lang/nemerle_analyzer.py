# Nemerle (.n, .nemerle) analyzer -- .NET language with ML-style features.
#
#     using System;                              -> import
#     using SC = System.Console;                 -> import (alias)
#     namespace Foo { ... }                      -> class (namespace)
#     class Point : Base, IShape { ... }         -> class (+ parents)
#     variant Tree { | Leaf | Node { ... } }     -> class (variant)
#     interface IDrawable { ... }                -> class
#     struct Vec { ... }                         -> class
#     module Utils { ... }                       -> class
#     enum Color { | Red | Green }               -> class
#     public Add(a : int, b : int) : int { ... } -> function
#     Main() : void { ... }                      -> function
#     def x = 5;   /   mutable y : int = 0;      -> variable
#
# Comments are '//' and '/* */'; strings use '"' and '@"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
# optional leading .NET-style attribute lists:  [Record] [Accessor(...)] ...
_ATTRS = r"(?:\[[^\]]*\]\s*)*"
_MODS = (r"(?:public\s+|private\s+|protected\s+|internal\s+|static\s+|abstract\s+|"
         r"sealed\s+|partial\s+|virtual\s+|override\s+|mutable\s+|volatile\s+|"
         r"new\s+|extern\s+|ref\s+)*")


class NemerleAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "nemerle"
    EXTENSIONS = (".n", ".nemerle")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _USING = re.compile(r"(?m)^\s*using\s+(?:(" + _ID + r")\s*=\s*)?([\w.]+)\s*;")
    _TYPE = re.compile(r"(?m)^\s*" + _ATTRS + _MODS +
                       r"(?:class|variant|interface|struct|module|enum)\s+(" +
                       _ID + r")\s*(?:\[[^\]]*\])?\s*(?::\s*([^\{]+))?")
    _NAMESPACE = re.compile(r"(?m)^\s*namespace\s+([\w.]+)")
    # method: [attrs] modifiers Name[gen](args) : Ret
    _METHOD = re.compile(r"(?m)^\s*" + _ATTRS + _MODS + r"(" + _ID +
                         r")\s*(?:\[[^\]]*\])?\s*\(")
    # `def`/`mutable` bindings, which may appear inline inside a block body
    _DEF = re.compile(r"(?<![\w.])(?:def|mutable)\s+(" + _ID + r")\b")

    _TYPE_KWS = {"class", "variant", "interface", "struct", "module", "enum",
                 "namespace", "using", "def", "mutable", "when", "unless",
                 "match", "if", "else", "while", "for", "foreach", "do",
                 "return", "throw", "try", "catch", "finally", "lock", "get",
                 "set", "this", "base"}

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._NAMESPACE.finditer(clean):
            self._register_class(m.group(1).split(".")[-1])
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._USING.finditer(clean):
            alias, src = m.group(1), m.group(2)
            leaf = src.split(".")[-1]
            self._add_import(file_id, leaf, src, alias=alias)

        for m in self._NAMESPACE.finditer(clean):
            self._add_class(file_id, m.group(1).split(".")[-1],
                            description="nemerle namespace")

        for m in self._TYPE.finditer(clean):
            parents = []
            if m.group(2):
                for p in self._split_top_level(m.group(2).strip()):
                    p = p.strip().split("[")[0].split("(")[0].strip()
                    pid = self._register_class(p.split(".")[-1]) if p else None
                    if pid is not None:
                        parents.append(pid)
            self._add_class(file_id, m.group(1), description="nemerle type",
                            parent_ids=parents or None)

        for m in self._METHOD.finditer(clean):
            name = m.group(1)
            if name in self._TYPE_KWS:
                continue
            open_paren = clean.index("(", m.end() - 1)
            args = self._method_args(clean, open_paren)
            out = self._method_output(clean, open_paren)
            self._add_function(file_id, name, args,
                               [out] if out is not None else [],
                               description="nemerle method")

        for m in self._DEF.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="local")

    def _method_args(self, clean, open_paren):
        end = self._find_matching(clean, open_paren, "(", ")")
        body = clean[open_paren + 1:end - 1]
        arg_ids = []
        for part in self._split_top_level(body):
            part = part.strip()
            if not part:
                continue
            name = part.split(":")[0].split("=")[0].strip()
            name = name.split()[-1] if name.split() else name
            if name and re.match(r"[A-Za-z_]", name):
                atype = part.split(":", 1)[1].strip() if ":" in part else None
                arg_ids.append(self._add_arg(name, atype))
        return arg_ids

    def _method_output(self, clean, open_paren):
        end = self._find_matching(clean, open_paren, "(", ")")
        tail = clean[end:]
        m = re.match(r"\s*:\s*([\w.<>\[\], ]+)", tail)
        if m:
            rt = m.group(1).strip()
            if rt:
                return self._add_output(rt)
        return None
