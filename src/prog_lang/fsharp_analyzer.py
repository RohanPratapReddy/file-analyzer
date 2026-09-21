# F# (.fsharp / alternate F# source) analyzer.
#
# Real parser for F# (ML-family; '//' line, '(* *)' block comments; strings
# "...", triple """...""", verbatim @"..."):
#   namespace My.Space                              -> (namespace marker)
#   module Foo                                        -> (module marker)
#   open System.Collections.Generic                   -> import
#   open type System.Math                             -> import
#   let pi = 3.14159                                  -> variable
#   let add x y = x + y                               -> function
#   let rec fact n = if n <= 1 then 1 else n*fact(n-1) -> function
#   let inline sq (x: float) : float = x * x          -> function
#   type Point = { X: float; Y: float }               -> class (record + fields)
#   type Shape = Circle of float | Rect of float*float -> class (union + cases)
#   type Animal(name: string) =                        -> class
#       member this.Name = name                         -> method
#       member this.Speak() = printfn "%s" name          -> method
import re

from .regex_base import RegexCodeAnalyzer


class FSharpAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "fsharp"
    EXTENSIONS = (".fsharp",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _OPEN = re.compile(r"^[ \t]*open\s+(?:type\s+)?([\w.]+)", re.MULTILINE)
    _TYPE = re.compile(
        r"^[ \t]*(?:\[<[^>]*>\][ \t]*)?type\s+"
        r"(?:internal\s+|private\s+|public\s+)?"
        r"([A-Za-z_]\w*)(?:<[^>]*>)?(?:\s*\(([^)]*)\))?",
        re.MULTILINE,
    )
    _LET = re.compile(
        r"^([ \t]*)let\s+(?:rec\s+|inline\s+|mutable\s+|private\s+|internal\s+|public\s+)*"
        r"(?:\(\s*)?([A-Za-z_]\w*|\([^)]{1,6}\))\s*([^=\n]*?)=(?!=)",
        re.MULTILINE,
    )
    _MEMBER = re.compile(
        r"^[ \t]*(?:static\s+|abstract\s+|override\s+|default\s+)*member\s+"
        r"(?:\w+\.)?([A-Za-z_]\w*)\s*([^=\n]*?)(?:=|$)",
        re.MULTILINE,
    )

    def _indent_body(self, text, decl_start):
        """Lines more-indented than the declaration line (its layout block)."""
        nl = text.find("\n", decl_start)
        if nl == -1:
            return ""
        base = self._indent_of(text[decl_start:nl])
        out = []
        for line in text[nl + 1 :].splitlines(keepends=True):
            if line.strip() and self._indent_of(line) <= base:
                break
            out.append(line)
        return "".join(out)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._TYPE.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._OPEN.finditer(text):
            mod = m.group(1)
            self._add_import(file_id, mod.split(".")[-1], mod)

        # types: record / union / class-with-primary-ctor
        for m in self._TYPE.finditer(text):
            name = m.group(1)
            ctor = m.group(2)
            attrs, methods = [], []
            if ctor:
                for part in self._split_top_level(ctor):
                    pm = re.match(
                        r"(?:mutable\s+)?([A-Za-z_]\w*)\s*(?::\s*(.+))?", part.strip()
                    )
                    if pm:
                        attrs.append(
                            self._add_arg(
                                pm.group(1),
                                pm.group(2).strip() if pm.group(2) else None,
                            )
                        )
            eq = text.find("=", m.end())
            nl = text.find("\n", m.end())
            head = ""
            if eq != -1 and (nl == -1 or eq < nl + 1):
                head_end = text.find("\n", eq)
                head = text[eq + 1 : head_end if head_end != -1 else len(text)]
            # record: { X: T; Y: T }
            if "{" in head:
                lb = text.find("{", eq)
                rb = self._find_matching(text, lb, "{", "}")
                for fld in re.split(r"[;\n]", text[lb + 1 : rb - 1]):
                    fm = re.match(r"\s*(?:mutable\s+)?([A-Za-z_]\w*)\s*:\s*(.+)", fld)
                    if fm:
                        attrs.append(self._add_arg(fm.group(1), fm.group(2).strip()))
            # union: | Case of T | Case2
            body = self._indent_body(text, m.start())
            for um in re.finditer(r"^\s*\|\s*([A-Za-z_]\w*)", body, re.MULTILINE):
                attrs.append(self._add_arg(um.group(1), "union-case"))
            for mm in self._MEMBER.finditer(body):
                methods.append(
                    self._add_function(
                        file_id,
                        mm.group(1),
                        [],
                        [],
                        class_id=self._class_registry.get(name),
                        description="fsharp member",
                    )
                )
            self._add_class(
                file_id,
                name,
                description="fsharp type",
                attr_ids=attrs,
                method_ids=methods,
            )

        # collect member spans so top-level `let` scan skips members (they are
        # matched as class methods above)
        member_lines = {
            text.count("\n", 0, mm.start()) for mm in self._MEMBER.finditer(text)
        }

        for m in self._LET.finditer(text):
            name = m.group(2).strip("() ")
            params = m.group(3).strip()
            if text.count("\n", 0, m.start()) in member_lines:
                continue
            # parameter groups:  x y (z: int) or a single tuple pattern
            arg_ids = []
            for pm in re.finditer(r"\(([^)]*)\)|([A-Za-z_]\w*)", params):
                if pm.group(2):
                    arg_ids.append(self._add_arg(pm.group(2)))
                elif pm.group(1).strip():
                    tm = re.match(
                        r"([A-Za-z_]\w*)\s*(?::\s*(.+))?", pm.group(1).strip()
                    )
                    if tm:
                        arg_ids.append(
                            self._add_arg(
                                tm.group(1),
                                tm.group(2).strip() if tm.group(2) else None,
                            )
                        )
            if arg_ids:
                self._add_function(
                    file_id, name, arg_ids, [], description="fsharp function"
                )
            else:
                self._add_variable(file_id, name, None)
