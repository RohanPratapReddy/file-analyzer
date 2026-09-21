# Ada (.ada / .adb body / .ads spec) analyzer.
#
# Real parser for Ada (Wirth-family, keyword blocks closed with ``end``, case
# INSENSITIVE keywords, ``--`` line comments only):
#   with Ada.Text_IO; use Ada.Text_IO;        -> import (context clause)
#   package Foo is ... end Foo;                -> package  (class row)
#   package body Foo is ... end Foo;           -> package body (merges into Foo)
#   type Rec is record F : Integer; end record;-> record   (class row, fields)
#   type Color is (Red, Green, Blue);          -> enum     (class row, members)
#   procedure Name (P : in Integer) is ...     -> procedure (function row)
#   function Name (P : T) return R is ...      -> function  (function row, output)
#   X : Integer := 5;                          -> variable
#
# Ada is not brace-delimited; package/subprogram membership is resolved by the
# nearest enclosing ``package [body] Name is`` seen before a declaration.
import re

from .regex_base import RegexCodeAnalyzer


class AdaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ada"
    EXTENSIONS = (".ada", ".adb", ".ads")
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()

    _WITH = re.compile(
        r"^\s*with\s+([\w.]+(?:\s*,\s*[\w.]+)*)\s*;", re.IGNORECASE | re.MULTILINE
    )
    _PACKAGE = re.compile(r"\bpackage\s+(?:body\s+)?([\w.]+)\s+is\b", re.IGNORECASE)
    _TYPE_REC = re.compile(
        r"\btype\s+(\w+)\b[^;]*?\bis\b[^;]*?\brecord\b(.*?)\bend\s+record\b",
        re.IGNORECASE | re.DOTALL,
    )
    _TYPE_ENUM = re.compile(r"\btype\s+(\w+)\s+is\s*\(([^)]*)\)\s*;", re.IGNORECASE)
    _SUBPROG = re.compile(
        r"\b(procedure|function)\s+(\w+)\s*(?:\(([^)]*)\))?"
        r"(?:\s*return\s+([\w.]+))?",
        re.IGNORECASE,
    )
    _FIELD = re.compile(
        r"(\w+(?:\s*,\s*\w+)*)\s*:\s*(?:aliased\s+)?([\w.][\w.\s]*?)"
        r"(?:\s*:=\s*([^;]+))?\s*;"
    )

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._PACKAGE.finditer(t):
            self._register_class(m.group(1).split(".")[-1])
        for m in self._TYPE_REC.finditer(t):
            self._register_class(m.group(1))
        for m in self._TYPE_ENUM.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._WITH.finditer(text):
            for unit in m.group(1).split(","):
                unit = unit.strip()
                if unit:
                    self._add_import(file_id, unit.split(".")[-1], unit)

        # Package declarations: (start_pos, name) so we can find the enclosing one.
        packages = [
            (m.start(), m.group(1).split(".")[-1]) for m in self._PACKAGE.finditer(text)
        ]

        def enclosing_pkg(pos):
            owner = None
            for start, name in packages:
                if start <= pos:
                    owner = name
                else:
                    break
            return owner

        # Records -> class rows with fields; skip subprogram scan inside them.
        rec_spans = []
        for m in self._TYPE_REC.finditer(text):
            name, body = m.group(1), m.group(2)
            rec_spans.append((m.start(), m.end()))
            attr_ids = []
            for fm in self._FIELD.finditer(body):
                names, ftype = fm.group(1), fm.group(2).strip()
                for nm in names.split(","):
                    nm = nm.strip()
                    if nm:
                        attr_ids.append(
                            self._add_arg(
                                nm, ftype, fm.group(3).strip() if fm.group(3) else None
                            )
                        )
            self._add_class(file_id, name, description="ada record", attr_ids=attr_ids)

        for m in self._TYPE_ENUM.finditer(text):
            attr_ids = [
                self._add_arg(v.strip(), "enum")
                for v in m.group(2).split(",")
                if v.strip()
            ]
            self._add_class(
                file_id, m.group(1), description="ada enum", attr_ids=attr_ids
            )

        def in_record(pos):
            return any(a <= pos < b for a, b in rec_spans)

        subprog_headers = []
        for m in self._SUBPROG.finditer(text):
            if in_record(m.start()):
                continue
            kind, name, params, ret = m.group(1), m.group(2), m.group(3), m.group(4)
            subprog_headers.append((m.start(), m.end()))
            arg_ids = self._params(params or "")
            out_ids = [self._add_output(ret.strip())] if ret else []
            owner = enclosing_pkg(m.start())
            cid = self._class_registry.get(owner) if owner else None
            self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)

        # Emit the package "class" rows (methods already linked via class_id).
        seen = set()
        for _, name in packages:
            if name not in seen:
                seen.add(name)
                self._add_class(file_id, name, description="ada package")

        # Top-level object declarations `X : Type := val;` outside records/params.
        def in_span(pos, spans):
            return any(a <= pos < b for a, b in spans)

        for m in self._FIELD.finditer(text):
            if in_record(m.start()):
                continue
            names, vtype = m.group(1), m.group(2).strip()
            if re.match(
                r"(?i)(procedure|function|type|package|with|use|"
                r"return|record|end|is|begin|for|while|loop|if|case)$",
                vtype.split()[0] if vtype.split() else "",
            ):
                continue
            for nm in names.split(","):
                nm = nm.strip()
                if nm:
                    self._add_variable(
                        file_id, nm, m.group(3).strip() if m.group(3) else None
                    )

    def _params(self, params):
        arg_ids = []
        # Ada params separated by ';', each: names : [mode] type [:= default]
        for part in params.split(";"):
            part = part.strip()
            if not part or ":" not in part:
                continue
            names, rest = part.split(":", 1)
            default = None
            if ":=" in rest:
                rest, default = rest.split(":=", 1)
                default = default.strip()
            rest = re.sub(
                r"(?i)^\s*(in\s+out|in|out|access|aliased)\s+", "", rest.strip()
            )
            atype = rest.strip()
            for nm in names.split(","):
                nm = nm.strip()
                if nm:
                    arg_ids.append(self._add_arg(nm, atype or None, default))
        return arg_ids
