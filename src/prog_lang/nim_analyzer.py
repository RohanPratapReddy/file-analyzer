# Nim (.nim) analyzer.
#
# Real parser for Nim (indentation blocks, `#` line, `#[ ]#` block comments):
#   import strutils, os                          -> import
#   from sequtils import map                      -> import
#   type Point = object x, y: float               -> object type (class, fields)
#   type Color = enum Red, Green                   -> enum (class, members)
#   proc area(r: float): float = ...               -> function
#   func / method / template / macro / iterator    -> function
#   var x = 5;  let y = 1;  const z = 2             -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class NimAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "nim"
    EXTENSIONS = (".nim",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("#[", "]#"),)

    _IMPORT = re.compile(r"^[ \t]*import[ \t]+([\w/][\w/, \t]*)", re.MULTILINE)
    _FROM = re.compile(r"^[ \t]*from[ \t]+([\w/]+)[ \t]+import[ \t]+([\w,* \t]+)",
                       re.MULTILINE)
    _INCLUDE = re.compile(r"^[ \t]*include[ \t]+([\w/]+)", re.MULTILINE)
    # An object/enum/tuple body runs until the next type member (an indented
    # `Name = ...`) or the next top-level section keyword.
    _TYPE = re.compile(
        r"^[ \t]*(\w+)\*?\s*(?:\[[^\]]*\])?\s*=\s*(?:ref\s+|ptr\s+)?"
        r"(object|enum|tuple)\b(.*?)"
        r"(?=^[ \t]*\w+\*?\s*(?:\[[^\]]*\])?\s*=\s*(?:ref\s+|ptr\s+)?"
        r"(?:object|enum|tuple)\b|"
        r"^(?:proc|func|method|template|macro|iterator|converter|var|let|const|"
        r"type|import|from|include)\b|\Z)",
        re.MULTILINE | re.DOTALL)
    _ROUTINE = re.compile(
        r"^\s*(proc|func|method|template|macro|iterator|converter)\s+"
        r"`?([\w=+\-*/<>]+)`?\s*(?:\*)?\s*(?:\[[^\]]*\])?\s*\(([^)]*)\)"
        r"(?:\s*:\s*([\w\[\], ]+))?", re.MULTILINE)
    _VAR = re.compile(r"^\s*(var|let|const)\s+(\w+)\*?\s*(?::[^=\n]+)?=?",
                      re.MULTILINE)
    _FIELD = re.compile(r"^\s+([\w,\s*]+?)\s*:\s*([\w\[\], ]+)", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        # `type` sections: register the LHS names before their object/enum body.
        for m in self._TYPE.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._IMPORT.finditer(t):
            for mod in re.split(r"[,\s]+", m.group(1).strip()):
                if mod:
                    self._add_import(file_id, mod.split("/")[-1], mod)
        for m in self._FROM.finditer(t):
            base = m.group(1)
            for sym in re.split(r"[,\s]+", m.group(2).strip()):
                if sym and sym != "*":
                    self._add_import(file_id, sym, f"{base}.{sym}")
        for m in self._INCLUDE.finditer(t):
            self._add_import(file_id, m.group(1).split("/")[-1], m.group(1))

        for m in self._TYPE.finditer(t):
            name, kind, body = m.group(1), m.group(2), m.group(3)
            attr_ids = []
            if kind == "enum":
                for v in re.split(r"[,\n]", body):
                    v = v.strip().split("=")[0].strip()
                    if v and re.match(r"^\w+$", v):
                        attr_ids.append(self._add_arg(v, "enum"))
            else:
                for fm in self._FIELD.finditer(body):
                    for nm in fm.group(1).split(","):
                        nm = nm.strip().rstrip("*")
                        if nm:
                            attr_ids.append(self._add_arg(nm, fm.group(2).strip()))
            self._add_class(file_id, name, description=f"nim {kind}",
                            attr_ids=attr_ids)

        for m in self._ROUTINE.finditer(t):
            kind, name, params, ret = m.groups()
            arg_ids = self._args(params)
            out_ids = [self._add_output(ret.strip())] if ret else []
            self._add_function(file_id, name, arg_ids, out_ids,
                               description=f"nim {kind}")

        for m in self._VAR.finditer(t):
            self._add_variable(file_id, m.group(2), scope=m.group(1))

    def _args(self, params):
        ids = []
        for part in params.split(","):
            part = part.split("=")[0].strip()
            if not part:
                continue
            if ":" in part:
                names, ty = part.split(":", 1)
                for nm in names.split(","):
                    nm = nm.strip()
                    if nm:
                        ids.append(self._add_arg(nm, ty.strip()))
            else:
                ids.append(self._add_arg(part))
        return ids
