# Bluespec SystemVerilog (.bsv) hardware-description analyzer.
#
# Real parser for Bluespec (BSV):
#
#     package Foo;                                  -> (namespace, not emitted)
#     import FIFO :: * ;                            -> import
#     interface Counter#(type t);                   -> class (interface)
#         method Action increment();                -> function (method)
#         method t read();
#     endinterface
#     typedef Bit#(8) Byte;                         -> class (type alias)
#     typedef struct { Bool v; } Flag deriving(Bits); -> class
#     module mkCounter (Counter#(int));             -> function (module ctor)
#         rule step;  ... endrule                   -> function (rule)
#         function int dbl (int x);  ... endfunction -> function
#     endmodule
#
# Comments are '//' and '/* */'.
import re

from .regex_base import RegexCodeAnalyzer


class BluespecAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "bluespec"
    EXTENSIONS = (".bsv",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(r"^[ \t]*import\s+([A-Za-z_]\w*)\s*::", re.MULTILINE)
    _INTERFACE = re.compile(r"^[ \t]*interface\s+([A-Za-z_]\w*)", re.MULTILINE)
    _MODULE = re.compile(
        r"^[ \t]*module\s+([A-Za-z_]\w*)\s*(?:#\([^)]*\))?\s*" r"(?:\(([^;]*)\))?",
        re.MULTILINE,
    )
    # The return type may itself contain `#( ... )` type parameters (e.g.
    # `function a#(n) adjustSize(a#(m) x)`), so the pre-name portion must be
    # allowed to contain parens.  The declared name is the identifier that is
    # directly followed by the argument-list `(` -- a `(` never immediately
    # preceded by `#` (which introduces a type-parameter list instead).
    _FUNC = re.compile(r"^[ \t]*function\b[^;{]*?([A-Za-z_]\w*)\s*\(", re.MULTILINE)
    _METHOD = re.compile(r"^[ \t]*method\b[^;{]*?([A-Za-z_]\w*)\s*(\(|;)", re.MULTILINE)
    _RULE = re.compile(r"^[ \t]*rule\s+([A-Za-z_]\w*)", re.MULTILINE)
    _TYPEDEF = re.compile(r"^[ \t]*typedef\b", re.MULTILINE)

    def _typedef_name(self, clean, start):
        """Return the declared name of the typedef beginning at `start`."""
        # skip to end of statement (the ';' that is not inside braces)
        depth = 0
        i = start
        body_end = len(clean)
        while i < len(clean):
            c = clean[i]
            if c in "{(":
                depth += 1
            elif c in "})":
                depth -= 1
            elif c == ";" and depth == 0:
                body_end = i
                break
            i += 1
        seg = clean[start:body_end]
        # name is the last identifier, before an optional `deriving(...)` and
        # before an optional `#(...)` provisos/params on the new type.
        seg = re.sub(r"\bderiving\b.*$", "", seg, flags=re.DOTALL)
        seg = re.sub(r"#\([^)]*\)\s*$", "", seg.rstrip())
        names = re.findall(r"[A-Za-z_]\w*", seg)
        return names[-1] if names else None

    def _split_params(self, blob):
        ids = []
        for part in self._split_top_level(blob or ""):
            nm = re.search(r"([A-Za-z_]\w*)\s*$", part)
            if nm:
                ids.append(self._add_arg(nm.group(1), part))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._INTERFACE.finditer(clean):
            self._register_class(m.group(1))
        for m in self._TYPEDEF.finditer(clean):
            nm = self._typedef_name(clean, m.end())
            if nm:
                self._register_class(nm)

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        for m in self._INTERFACE.finditer(clean):
            self._add_class(file_id, m.group(1), description="bluespec interface")
        for m in self._TYPEDEF.finditer(clean):
            nm = self._typedef_name(clean, m.end())
            if nm:
                self._add_class(file_id, nm, description="bluespec typedef")

        for m in self._MODULE.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._split_params(m.group(2)),
                [],
                description="bluespec module",
            )
        for m in self._FUNC.finditer(clean):
            lp = m.end() - 1  # position of the arg-list '('
            rp = self._find_matching(clean, lp, "(", ")")
            self._add_function(
                file_id,
                m.group(1),
                self._split_params(clean[lp + 1 : rp - 1]),
                [],
                description="bluespec function",
            )
        for m in self._METHOD.finditer(clean):
            if m.group(2) == "(":
                lp = m.end() - 1
                rp = self._find_matching(clean, lp, "(", ")")
                arg_ids = self._split_params(clean[lp + 1 : rp - 1])
            else:
                arg_ids = []
            self._add_function(
                file_id, m.group(1), arg_ids, [], description="bluespec method"
            )
        for m in self._RULE.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], description="bluespec rule")
