# Julia (.jl) analyzer (covers Pluto notebooks .pluto.jl, same suffix).
#
# Real parser for Julia (`#` line, `#= =#` block comments):
#   using LinearAlgebra                         -> import
#   import Base: show, +                         -> import
#   module Foo ... end                           -> module (class row)
#   struct Point x::Float64; y::Float64 end      -> struct (class row, fields)
#   mutable struct S ... end                      -> struct (class row)
#   abstract type Shape end                       -> abstract type (class row)
#   function f(a, b::Int) ... end                 -> function
#   g(x) = x^2                                     -> function (assignment form)
#   const C = 3.0                                  -> variable
import re

from .regex_base import RegexCodeAnalyzer


class JuliaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "julia"
    EXTENSIONS = (".jl",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("#=", "=#"),)

    # Whitespace restricted to spaces/tabs so a `using`/`import` never spans the
    # newline into the following declaration.
    _USING = re.compile(
        r"^[ \t]*(using|import)[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*)"
        r"(?:[ \t]*:[ \t]*([\w,! \t*+]+))?",
        re.MULTILINE,
    )
    _MODULE = re.compile(r"^\s*(?:module|baremodule)\s+(\w+)", re.MULTILINE)
    _STRUCT = re.compile(
        r"^\s*(?:mutable\s+)?struct\s+(\w+)(?:\{[^}]*\})?(?:\s*<:\s*[\w.{}]+)?"
        r"(.*?)^\s*end",
        re.MULTILINE | re.DOTALL,
    )
    _ABSTRACT = re.compile(r"^\s*(?:abstract|primitive)\s+type\s+(\w+)", re.MULTILINE)
    _FUNC = re.compile(r"^\s*function\s+([\w.!]+)\s*\(([^)]*)\)", re.MULTILINE)
    _ASSIGN_FUNC = re.compile(r"^\s*([\w.!]+)\s*\(([^)]*)\)\s*=(?!=)", re.MULTILINE)
    _CONST = re.compile(r"^\s*(?:const|global)\s+(\w+)\s*=", re.MULTILINE)
    _FIELD = re.compile(r"^\s*(\w+)\s*(?:::\s*([\w.{}, ]+))?\s*$", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._MODULE.finditer(t):
            self._register_class(m.group(1))
        for m in self._STRUCT.finditer(t):
            self._register_class(m.group(1))
        for m in self._ABSTRACT.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._USING.finditer(t):
            base = m.group(2)
            if m.group(3):
                for sym in re.split(r"[,\s]+", m.group(3).strip()):
                    if sym:
                        self._add_import(file_id, sym, f"{base}.{sym}")
            else:
                for mod in base.split(","):
                    mod = mod.strip()
                    if mod:
                        self._add_import(file_id, mod.split(".")[-1], mod)

        for m in self._MODULE.finditer(t):
            self._add_class(file_id, m.group(1), description="julia module")

        struct_spans = []
        for m in self._STRUCT.finditer(t):
            struct_spans.append((m.start(), m.end()))
            name, body = m.group(1), m.group(2)
            attr_ids = []
            for fm in self._FIELD.finditer(body):
                fname = fm.group(1)
                if fname in ("end", "function", "return"):
                    continue
                attr_ids.append(self._add_arg(fname, fm.group(2)))
            self._add_class(
                file_id, name, description="julia struct", attr_ids=attr_ids
            )

        for m in self._ABSTRACT.finditer(t):
            self._add_class(file_id, m.group(1), description="julia abstract type")

        def in_struct(pos):
            return any(a <= pos < b for a, b in struct_spans)

        emitted = set()
        for m in self._FUNC.finditer(t):
            name = m.group(1).split(".")[-1]
            self._add_function(file_id, name, self._args(m.group(2)))
            emitted.add((name, m.start()))
        for m in self._ASSIGN_FUNC.finditer(t):
            if in_struct(m.start()):
                continue
            name = m.group(1).split(".")[-1]
            self._add_function(
                file_id,
                name,
                self._args(m.group(2)),
                description="julia short-form function",
            )

        for m in self._CONST.finditer(t):
            self._add_variable(file_id, m.group(1))

    def _args(self, params):
        ids = []
        for p in self._split_top_level(params):
            p = p.split("=")[0].strip()
            if not p:
                continue
            if "::" in p:
                nm, ty = p.split("::", 1)
                ids.append(self._add_arg(nm.strip(), ty.strip()))
            else:
                ids.append(self._add_arg(p))
        return ids
