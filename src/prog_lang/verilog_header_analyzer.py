# Verilog / SystemVerilog header (.vh, .svh) analyzer.
#
# Real parser for (System)Verilog header files:
#
#     `include "defs.vh"                            -> import
#     `define WIDTH 8                               -> variable (macro)
#     parameter DEPTH = 16;                         -> variable
#     localparam ADDR_W = 4;                        -> variable
#     module fifo #(parameter W=8) (input clk);     -> class
#     interface axi_if;  ... endinterface           -> class
#     package types_pkg;  ... endpackage            -> class
#     class Packet;  ... endclass                   -> class
#     typedef struct packed { ... } flit_t;         -> class
#     function automatic int clog2(input int v);    -> function
#     task drive(input logic [7:0] d);              -> function
#
# Comments are '//' and '/* */'.
import re

from .regex_base import RegexCodeAnalyzer


class VerilogHeaderAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "verilog_header"
    EXTENSIONS = (".vh", ".svh")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _INCLUDE = re.compile(r'^[ \t]*`include\s+"([^"]+)"', re.MULTILINE)
    _DEFINE = re.compile(r"^[ \t]*`define\s+([A-Za-z_]\w*)", re.MULTILINE)
    _PARAM = re.compile(
        r"^[ \t]*(?:parameter|localparam)\b(?:\s+\w+)?(?:\s*\[[^\]]*\])?\s+"
        r"([A-Za-z_]\w*)\s*=",
        re.MULTILINE,
    )
    _MODULE = re.compile(r"^[ \t]*module\s+([A-Za-z_]\w*)", re.MULTILINE)
    _INTERFACE = re.compile(r"^[ \t]*interface\s+([A-Za-z_]\w*)", re.MULTILINE)
    _PACKAGE = re.compile(r"^[ \t]*package\s+([A-Za-z_]\w*)", re.MULTILINE)
    _CLASS = re.compile(r"^[ \t]*(?:virtual\s+)?class\s+([A-Za-z_]\w*)", re.MULTILINE)
    _TYPEDEF = re.compile(r"^[ \t]*typedef\b", re.MULTILINE)
    _FUNCTION = re.compile(
        r"^[ \t]*function\b(?:\s+automatic)?[^;(]*?\b([A-Za-z_]\w*)\s*[;(]",
        re.MULTILINE,
    )
    _TASK = re.compile(
        r"^[ \t]*task\b(?:\s+automatic)?\s+([A-Za-z_]\w*)\s*[;(]", re.MULTILINE
    )

    def _typedef_name(self, clean, start):
        """Return the declared name of a typedef beginning at `start` (just
        past the `typedef` keyword).  The body may contain brace-enclosed
        struct/union/enum members with their own semicolons, so skip balanced
        {...} regions and stop at the statement-terminating ';'."""
        i, n = start, len(clean)
        end = n
        while i < n:
            c = clean[i]
            if c == "{":
                i = self._find_matching(clean, i, "{", "}")
                continue
            if c == ";":
                end = i
                break
            i += 1
        seg = clean[start:end]
        # drop a trailing packed-dimension like `[3:0]` on the new type name
        seg = re.sub(r"\[[^\]]*\]\s*$", "", seg.rstrip())
        names = re.findall(r"[A-Za-z_]\w*", seg)
        return names[-1] if names else None

    def _args(self, blob):
        ids = []
        for part in self._split_top_level(blob or ""):
            nm = re.search(r"([A-Za-z_]\w*)\s*$", part.split("=")[0])
            if nm:
                ids.append(self._add_arg(nm.group(1), part.strip()))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (self._MODULE, self._INTERFACE, self._PACKAGE, self._CLASS):
            for m in rx.finditer(clean):
                self._register_class(m.group(1))
        for m in self._TYPEDEF.finditer(clean):
            nm = self._typedef_name(clean, m.end())
            if nm:
                self._register_class(nm)

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            hdr = m.group(1)
            self._add_import(file_id, hdr.replace("\\", "/").split("/")[-1], hdr)

        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), "macro")
        for m in self._PARAM.finditer(clean):
            self._add_variable(file_id, m.group(1), "parameter")

        for rx, desc in (
            (self._MODULE, "verilog module"),
            (self._INTERFACE, "verilog interface"),
            (self._PACKAGE, "verilog package"),
            (self._CLASS, "verilog class"),
        ):
            for m in rx.finditer(clean):
                self._add_class(file_id, m.group(1), description=desc)
        for m in self._TYPEDEF.finditer(clean):
            nm = self._typedef_name(clean, m.end())
            if nm:
                self._add_class(file_id, nm, description="verilog typedef")

        for m in self._FUNCTION.finditer(clean):
            if clean[m.end() - 1] == "(":
                lp = m.end() - 1
                rp = self._find_matching(clean, lp, "(", ")")
                arg_ids = self._args(clean[lp + 1 : rp - 1])
            else:
                arg_ids = []
            self._add_function(
                file_id, m.group(1), arg_ids, [], description="verilog function"
            )
        for m in self._TASK.finditer(clean):
            if clean[m.end() - 1] == "(":
                lp = m.end() - 1
                rp = self._find_matching(clean, lp, "(", ")")
                arg_ids = self._args(clean[lp + 1 : rp - 1])
            else:
                arg_ids = []
            self._add_function(
                file_id, m.group(1), arg_ids, [], description="verilog task"
            )
