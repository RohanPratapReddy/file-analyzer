# Zig (.zig) analyzer.
#
# Real parser for Zig (`//` line comments, no block comments):
#   const std = @import("std");                  -> import + variable
#   const Point = struct { x: f32, y: f32 };      -> struct (class, fields)
#   const Color = enum { red, green };             -> enum (class, members)
#   const Shape = union(enum) { ... };             -> union (class)
#   pub fn add(a: i32, b: i32) i32 { ... }         -> function
#   var count: u32 = 0;   const MAX = 100;         -> variable
import re

from .regex_base import RegexCodeAnalyzer


class ZigAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "zig"
    EXTENSIONS = (".zig",)
    LINE_COMMENTS = ("///", "//")
    BLOCK_COMMENTS = ()

    _IMPORT = re.compile(r'\bconst\s+(\w+)\s*=\s*@import\s*\(\s*"([^"]+)"\s*\)')
    _CONTAINER = re.compile(
        r"\b(?:pub\s+)?const\s+(\w+)\s*=\s*(?:packed\s+|extern\s+)?"
        r"(struct|enum|union)(?:\s*\([^)]*\))?\s*\{"
    )
    _FUNC = re.compile(
        r"^\s*(?:pub\s+|export\s+|extern\s+(?:\"[^\"]*\"\s+)?|inline\s+)*"
        r"fn\s+(\w+)\s*\(([^)]*)\)\s*(?:callconv\([^)]*\)\s*)?"
        r"([\w.!\[\]*?]+)?",
        re.MULTILINE,
    )
    _VAR = re.compile(
        r"^\s*(?:pub\s+)?(const|var)\s+(\w+)(?:\s*:\s*[^=;]+)?\s*=", re.MULTILINE
    )

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._CONTAINER.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        import_names = set()
        for m in self._IMPORT.finditer(t):
            alias, mod = m.group(1), m.group(2)
            import_names.add(alias)
            self._add_import(
                file_id, mod.split("/")[-1].replace(".zig", ""), mod, alias=alias
            )

        container_spans = []
        for m in self._CONTAINER.finditer(t):
            name, kind = m.group(1), m.group(2)
            brace = t.index("{", m.start())
            end = self._find_matching(t, brace)
            container_spans.append((brace, end))
            body = t[brace + 1 : end - 1]
            attr_ids = []
            if kind == "enum":
                for v in self._split_top_level(body):
                    fm = re.match(r"(\w+)", v.strip())
                    if fm:
                        attr_ids.append(self._add_arg(fm.group(1), "enum"))
            else:
                for fld in self._split_top_level(body):
                    fm = re.match(r"(\w+)\s*:\s*([^=]+)", fld.strip())
                    if fm:
                        attr_ids.append(self._add_arg(fm.group(1), fm.group(2).strip()))
            self._add_class(file_id, name, description=f"zig {kind}", attr_ids=attr_ids)

        for m in self._FUNC.finditer(t):
            name, params, ret = m.group(1), m.group(2), m.group(3)
            arg_ids = self._args(params)
            out_ids = [self._add_output(ret)] if ret and ret != "void" else []
            self._add_function(file_id, name, arg_ids, out_ids)

        for m in self._VAR.finditer(t):
            name = m.group(2)
            if name in import_names:
                continue
            self._add_variable(file_id, name, scope=m.group(1))

    def _args(self, params):
        ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if not part or part == "...":
                continue
            if ":" in part:
                nm, ty = part.split(":", 1)
                ids.append(self._add_arg(nm.strip(), ty.strip()))
            else:
                ids.append(self._add_arg(part))
        return ids
