# Dart (.dart) analyzer.
#
# Real parser for Dart (`//` line, `/* */` block, `///` doc comments):
#   import 'package:flutter/material.dart';       -> import
#   class Foo extends Bar implements Baz { ... }   -> class (parents recorded)
#   mixin M on N { ... }                            -> mixin (class row)
#   enum Color { red, green }                       -> enum (class row, members)
#   abstract class Shape { double area(); }         -> class
#   ReturnType name(args) { ... }                   -> function / method
#   final int x = 5;  var y;  const z = 1;          -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class DartAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "dart"
    EXTENSIONS = (".dart",)
    LINE_COMMENTS = ("///", "//")
    BLOCK_COMMENTS = (("/*", "*/"),)

    _IMPORT = re.compile(r"""^\s*(?:import|export|part)\s+['"]([^'"]+)['"]"""
                         r"""(?:\s+as\s+(\w+))?""", re.MULTILINE)
    _CLASS = re.compile(
        r"^\s*(?:abstract\s+|base\s+|final\s+|sealed\s+|interface\s+)*"
        r"class\s+(\w+)(?:<[^>]*>)?"
        r"(?:\s+extends\s+([\w.<>]+))?"
        r"(?:\s+with\s+([\w.,<>\s]+?))?"
        r"(?:\s+implements\s+([\w.,<>\s]+?))?\s*\{", re.MULTILINE)
    _MIXIN = re.compile(r"^\s*mixin\s+(\w+)(?:\s+on\s+([\w.,\s]+))?",
                        re.MULTILINE)
    _ENUM = re.compile(r"^\s*enum\s+(\w+)\s*\{([^}]*)\}", re.MULTILINE)
    _FUNC = re.compile(
        r"^\s*(?:(?:static|final|const|external|factory)\s+)*"
        r"(?:[\w$<>,.\s?]+?\s+)?(\w+)\s*(?:<[^>]*>)?\(([^;{]*?)\)\s*(?:async\*?\s*)?(?:\{|=>)",
        re.MULTILINE)
    _VAR = re.compile(
        r"^\s*(?:final|const|var|late)\s+(?:[\w$<>,.?]+\s+)?(\w+)\s*(?:=|;)",
        re.MULTILINE)

    _KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "do",
                 "else", "get", "set", "new", "await", "yield", "assert"}

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._CLASS.finditer(t):
            self._register_class(m.group(1))
        for m in self._MIXIN.finditer(t):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._IMPORT.finditer(t):
            uri = m.group(1)
            self._add_import(file_id, uri.split("/")[-1], uri, alias=m.group(2))

        class_spans = []
        for m in self._CLASS.finditer(t):
            end = self._find_matching(t, t.index("{", m.start()))
            class_spans.append((m.start(), end, m.group(1)))
            parents = []
            for grp in (m.group(2), m.group(3), m.group(4)):
                if grp:
                    for p in grp.split(","):
                        pid = self._register_class(p.strip().split("<")[0])
                        if pid is not None:
                            parents.append(pid)
            self._add_class(file_id, m.group(1), description="dart class",
                            parent_ids=parents)

        for m in self._MIXIN.finditer(t):
            self._add_class(file_id, m.group(1), description="dart mixin")
        for m in self._ENUM.finditer(t):
            attr_ids = [self._add_arg(v.strip().split("(")[0])
                        for v in m.group(2).split(",") if v.strip()]
            self._add_class(file_id, m.group(1), description="dart enum",
                            attr_ids=attr_ids)

        def owner(pos):
            for a, b, name in class_spans:
                if a <= pos < b:
                    return self._class_registry.get(name)
            return None

        for m in self._FUNC.finditer(t):
            name = m.group(1)
            if name in self._KEYWORDS or name[0].isupper() and name in \
                    self._class_registry:
                continue
            arg_ids = self._args(m.group(2))
            self._add_function(file_id, name, arg_ids, class_id=owner(m.start()))

        for m in self._VAR.finditer(t):
            self._add_variable(file_id, m.group(1))

    def _args(self, params):
        ids = []
        params = params.strip().strip("{}[]")
        for p in self._split_top_level(params):
            p = p.split("=")[0].strip()
            if not p:
                continue
            parts = p.replace("required ", "").split()
            if len(parts) >= 2:
                ids.append(self._add_arg(parts[-1], " ".join(parts[:-1])))
            elif parts:
                ids.append(self._add_arg(parts[-1]))
        return ids
