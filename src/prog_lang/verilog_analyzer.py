# Verilog (.v) and SystemVerilog (.sv) analyzer.
#
# Real parser for (System)Verilog (`//` line, `/* */` block comments):
#   `include "defs.vh"                            -> import
#   module cpu (input clk, output reg [7:0] q);  -> module (class, ports)
#     input clk;  output [7:0] q;  wire w;  reg r; -> ports / nets (variables)
#   endmodule
#   class Packet; ... endclass                    -> SV class
#   function int add(int a, b); ... endfunction   -> function
#   task run(); ... endtask                        -> function (task)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class VerilogAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "verilog"
    EXTENSIONS = (".v", ".sv")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)

    _INCLUDE = re.compile(r'^\s*`include\s+"([^"]+)"', re.MULTILINE)
    _MODULE = re.compile(
        r"^\s*module\s+(\w+)\s*(?:#\([^)]*\)\s*)?(?:\(([^;]*?)\))?\s*;",
        re.MULTILINE | re.DOTALL)
    _CLASS = re.compile(r"^\s*(?:virtual\s+)?class\s+(\w+)"
                        r"(?:\s+extends\s+(\w+))?", re.MULTILINE)
    _FUNC = re.compile(
        r"^\s*function\s+(?:automatic\s+)?(?:[\w\[\]:.]+\s+)?(\w+)\s*"
        r"(?:\(([^;]*?)\))?\s*;", re.MULTILINE | re.DOTALL)
    _TASK = re.compile(
        r"^\s*task\s+(?:automatic\s+)?(\w+)\s*(?:\(([^;]*?)\))?\s*;",
        re.MULTILINE | re.DOTALL)
    def _parse_ports(self, text):
        """Split a port/parameter list into (name, type) pairs. The declared
        name is the LAST identifier of each comma-separated entry; the leading
        direction / net-type / packed-range tokens form its type."""
        pairs = []
        # collapse packed ranges so [7:0] does not hide the signal name
        cleaned = re.sub(r"\[[^\]]*\]", " ", text)
        for part in self._split_top_level(cleaned):
            toks = part.replace("signed", " ").split()
            if not toks:
                continue
            name = toks[-1]
            ty = " ".join(toks[:-1]) or None
            if re.match(r"^\w+$", name) and name not in (
                    "input", "output", "inout", "wire", "reg", "logic"):
                pairs.append((name, ty))
        return pairs

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._MODULE.finditer(t):
            self._register_class(m.group(1))
        for m in self._CLASS.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._INCLUDE.finditer(t):
            self._add_import(file_id, m.group(1).split("/")[-1], m.group(1))

        module_spans = []
        for m in self._MODULE.finditer(t):
            name, ports = m.group(1), m.group(2) or ""
            end = t.find("endmodule", m.end())
            end = end if end != -1 else len(t)
            module_spans.append((m.start(), end, name))
            attr_ids = [self._add_arg(pn, pt)
                        for pn, pt in self._parse_ports(ports)]
            cid = self._add_class(file_id, name, description="verilog module",
                                  attr_ids=attr_ids)

        for m in self._CLASS.finditer(t):
            parents = []
            if m.group(2):
                pid = self._register_class(m.group(2))
                if pid is not None:
                    parents.append(pid)
            self._add_class(file_id, m.group(1), description="systemverilog class",
                            parent_ids=parents)

        def owner(pos):
            for a, b, name in module_spans:
                if a <= pos < b:
                    return self._class_registry.get(name)
            return None

        for m in self._FUNC.finditer(t):
            self._add_function(file_id, m.group(1),
                               [self._add_arg(n, ty) for n, ty
                                in self._parse_ports(m.group(2) or "")],
                               class_id=owner(m.start()),
                               description="verilog function")
        for m in self._TASK.finditer(t):
            self._add_function(file_id, m.group(1),
                               [self._add_arg(n, ty) for n, ty
                                in self._parse_ports(m.group(2) or "")],
                               class_id=owner(m.start()),
                               description="verilog task")
