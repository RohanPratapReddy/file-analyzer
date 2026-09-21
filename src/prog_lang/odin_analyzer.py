# Odin (.odin) analyzer.
#
# Real parser for Odin (data-oriented systems language, ``::`` declarations):
#   package game                              -> (package decl)
#   import "core:fmt"                          -> import
#   import rl "vendor:raylib"                  -> aliased import
#   Foo :: struct { x, y: int }                -> struct (class row, fields as attrs)
#   Color :: enum { RED, GREEN }               -> enum   (class row)
#   Shape :: union { Circle, Square }          -> union  (class row)
#   main :: proc() { }                         -> function
#   add :: proc(a, b: int) -> int { }          -> function (params, return)
#   PI :: 3.14159                              -> constant variable
#   speed := 5     /  hp: int = 100            -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_TYPE_KW = ("struct", "enum", "union", "bit_set", "bit_field")


class OdinAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "odin"
    EXTENSIONS = (".odin",)

    _IMPORT = re.compile(
        r'^[ \t]*(?:@\s*\([^)]*\)\s*)*'          # optional @(require) etc. attrs
        r'(?:foreign\s+import|import)\s+'
        r'(?:([A-Za-z_]\w*)\s+)?"([^"]+)"', re.MULTILINE)
    _DECL = re.compile(r"(^|\n)[ \t]*([A-Za-z_]\w*)\s*::\s*")
    _VAR = re.compile(
        r"(^|\n)[ \t]*([A-Za-z_]\w*)\s*(?::\s*([^=\n]+?)\s*)?(:=|=)\s*([^\n]+)")

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._DECL.finditer(text):
            after = text[m.end():m.end() + 40].lstrip()
            for kw in _TYPE_KW:
                if after.startswith(kw) and (len(after) == len(kw) or not after[len(kw)].isalnum()):
                    self._register_class(m.group(2))
                    break

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._IMPORT.finditer(text):
            alias, src = m.group(1), m.group(2)
            name = alias or src.split(":")[-1].split("/")[-1]
            self._add_import(file_id, name, src, alias)

        proc_spans = []
        for m in self._DECL.finditer(text):
            name = m.group(2)
            pos = m.end()
            after = text[pos:]
            stripped = after.lstrip()
            lead = len(after) - len(stripped)

            if stripped.startswith("proc"):
                self._parse_proc(file_id, text, pos + lead, name, proc_spans)
                continue

            handled = False
            for kw in _TYPE_KW:
                if stripped.startswith(kw) and (len(stripped) == len(kw) or not stripped[len(kw)].isalnum()):
                    self._parse_type(file_id, text, pos + lead, name, kw)
                    handled = True
                    break
            if handled:
                continue

            # constant :: value
            if not any(a <= m.start() < b for a, b in proc_spans):
                val = stripped.split("\n", 1)[0].strip()
                if val and not val.startswith(("#", "struct", "enum", "union")):
                    self._add_variable(file_id, name, val, scope="const")

        for m in self._VAR.finditer(text):
            if any(a <= m.start(2) < b for a, b in proc_spans):
                continue
            name, vtype, val = m.group(2), m.group(3), m.group(5)
            self._add_variable(file_id, name, val.strip(),
                               scope="module" if vtype is None else "module")

    def _parse_proc(self, file_id, text, pos, name, proc_spans):
        popen = text.find("(", pos)
        if popen == -1:
            return
        pclose = self._find_matching(text, popen, "(", ")")
        params = text[popen + 1:pclose - 1]
        rest = text[pclose:]
        ret = None
        rm = re.match(r"\s*->\s*([^{]+?)\s*(?:\{|---|\Z)", rest)
        if rm:
            ret = rm.group(1).strip()
        body = text.find("{", pclose)
        if body != -1:
            end = self._find_matching(text, body)
            proc_spans.append((pos, end))
        arg_ids = self._params(params)
        out_ids = [self._add_output(ret)] if ret else []
        self._add_function(file_id, name, arg_ids, out_ids, class_id=None)

    def _parse_type(self, file_id, text, pos, name, kw):
        bopen = text.find("{", pos)
        if bopen == -1:
            self._register_class(name)
            self._add_class(file_id, name, description=f"odin {kw}")
            return
        bclose = self._find_matching(text, bopen)
        body = text[bopen + 1:bclose - 1]
        attr_ids = []
        if kw in ("struct", "bit_field"):
            for field in self._split_top_level(body):
                if ":" not in field:
                    continue
                names, ftype = field.split(":", 1)
                ftype = ftype.split("|")[0].strip()
                for nm in names.split(","):
                    nm = nm.strip()
                    if nm and nm != "using":
                        attr_ids.append(self._add_arg(nm.replace("using ", ""), ftype))
        else:  # enum / union members
            for member in self._split_top_level(body):
                member = member.split("=")[0].strip()
                if member:
                    attr_ids.append(self._add_arg(member, kw))
        self._register_class(name)
        self._add_class(file_id, name, description=f"odin {kw}", attr_ids=attr_ids)

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if not part or part in ("..", "..."):
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            if ":" in part:
                names, atype = part.split(":", 1)
                atype = atype.strip()
                for nm in names.split(","):
                    nm = nm.strip().lstrip("$")
                    if nm:
                        arg_ids.append(self._add_arg(nm, atype, default))
            elif part:
                arg_ids.append(self._add_arg(part.lstrip("$"), None, default))
        return arg_ids
