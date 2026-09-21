# WebAssembly Text (.wat / .wast) analyzer.
#
# Real parser for the WebAssembly text format (an S-expression syntax; ';;' line
# and nested '(; ;)' block comments; strings "..."):
#   (module
#     (import "env" "log" (func $log (param i32)))   -> import
#     (global $g (mut i32) (i32.const 0))             -> variable
#     (memory (export "mem") 1)                        -> variable
#     (table 1 funcref)                                 -> variable
#     (type $ft (func (param i32) (result i32)))        -> class (function type)
#     (func $add (param $a i32) (param $b i32) (result i32) ...) -> function
#     (func (export "sub") (param i32 i32) (result i32) ...)      -> function
#     (start $main))
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class WatAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "wat"
    EXTENSIONS = (".wat", ".wast")
    LINE_COMMENTS = (";;",)
    BLOCK_COMMENTS = ()          # nested (; ;) handled below
    STRING_DELIMS = ('"',)

    def _strip_block(self, text):
        out, i, n, depth = [], 0, len(text), 0
        while i < n:
            if depth == 0 and text[i] == '"':
                out.append('"'); i += 1
                while i < n:
                    c = text[i]; out.append(c)
                    if c == "\\" and i + 1 < n:
                        out.append(text[i + 1]); i += 2; continue
                    i += 1
                    if c == '"':
                        break
                continue
            if text[i:i + 2] == "(;":
                depth += 1; out.append("  "); i += 2; continue
            if text[i:i + 2] == ";)" and depth > 0:
                depth -= 1; out.append("  "); i += 2; continue
            if depth > 0:
                out.append("\n" if text[i] == "\n" else " "); i += 1; continue
            out.append(text[i]); i += 1
        return "".join(out)

    def _clean(self, text):
        return self._strip_comments(self._strip_block(text))

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for m in re.finditer(r"\(\s*type\s+(\$[^\s()]+)", text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        # imports:  (import "mod" "name" (func $id ...)) -- record the import and
        # remember its span so the inner descriptor form is not double-counted.
        import_spans = []
        for m in re.finditer(r'\(\s*import\s+"([^"]*)"\s+"([^"]*)"', text):
            mod, name = m.group(1), m.group(2)
            self._add_import(file_id, name or mod, f"{mod}/{name}")
            open_pos = text.rfind("(", 0, m.end())
            import_spans.append((open_pos,
                                 self._find_matching(text, open_pos, "(", ")")))

        def _in_import(pos):
            return any(a <= pos < b for a, b in import_spans)

        # function-type definitions -> classes
        for m in re.finditer(r"\(\s*type\s+(\$[^\s()]+)", text):
            self._add_class(file_id, m.group(1), description="wat type")

        # globals / memories / tables -> variables
        for m in re.finditer(r"\(\s*global\s+(\$[^\s()]+)", text):
            self._add_variable(file_id, m.group(1), None)
        for kind in ("memory", "table"):
            for m in re.finditer(r"\(\s*" + kind + r"\s+(\$[^\s()]+)", text):
                self._add_variable(file_id, m.group(1), kind)

        # functions (skip (func ...) descriptors that sit inside an import form).
        anon = 0
        for m in re.finditer(r"\(\s*func\b", text):
            start = text.rfind("(", 0, m.end())
            if _in_import(start):
                continue
            end = self._find_matching(text, start, "(", ")")
            form = text[start:end]
            head = re.sub(r"^\(\s*func\b", "", form)
            nm = re.match(r"\s*(\$[^\s()]+)", head)
            if nm:
                name = nm.group(1)
            else:
                em = re.match(r'\s*\(\s*export\s+"([^"]*)"', head)
                name = em.group(1) if em else f"$func{anon}"
                if not em:
                    anon += 1
            arg_ids = []
            for pm in re.finditer(r"\(\s*param\s+([^)]*)\)", form):
                inner = pm.group(1).strip()
                idm = re.match(r"(\$[^\s()]+)\s+(.+)", inner)
                if idm:
                    arg_ids.append(self._add_arg(idm.group(1), idm.group(2).strip()))
                else:
                    for ty in inner.split():
                        arg_ids.append(self._add_arg(None, ty))
            out_ids = []
            for rm in re.finditer(r"\(\s*result\s+([^)]*)\)", form):
                for ty in rm.group(1).split():
                    out_ids.append(self._add_output(ty))
            self._add_function(file_id, name, arg_ids, out_ids)
