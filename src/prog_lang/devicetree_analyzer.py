# Device Tree source (.dts, .dtsi) analyzer.
#
# Real parser for the DTS grammar (nodes + properties):
#
#     /dts-v1/;
#     #include "common.dtsi"                        -> import
#     /include/ "board.dtsi"                        -> import
#     / { ... };                                    -> class (root node)
#     cpus { ... };                                 -> class (node)
#     ethernet@ff000000 { ... };                    -> class (node)
#     uart0: serial@101f1000 { ... };               -> class (labelled node)
#     compatible = "arm,pl011";                     -> variable (property)
#     reg = <0x101f1000 0x1000>;                    -> variable
#     interrupt-controller;                          -> variable (bool property)
#     #define GIC_SPI 0                              -> variable (cpp macro)
#
# Comments are '//' and '/* */'.
import re

from .regex_base import RegexCodeAnalyzer


class DeviceTreeAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "devicetree"
    EXTENSIONS = (".dts", ".dtsi")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _INC_C = re.compile(r'^[ \t]*#\s*include\s+[<"]([^>"]+)[>"]', re.MULTILINE)
    _INC_DT = re.compile(r'^[ \t]*/include/\s+"([^"]+)"', re.MULTILINE)
    _DEFINE = re.compile(r"^[ \t]*#\s*define\s+([A-Za-z_]\w*)", re.MULTILINE)
    # a node opens a brace: optional `label:` then a node-name (or `/` root or
    # an `&reference`) then `{`
    _NODE = re.compile(
        r"^[ \t]*(?:([A-Za-z_]\w*)\s*:\s*)?"
        r"(/|&?[A-Za-z_][\w,.+-]*(?:@[\w,.+-]+)?)\s*\{",
        re.MULTILINE,
    )
    # a property is `name = ...;` or a boolean `name;` (name may start with '#')
    _PROP = re.compile(r"^[ \t]*([#A-Za-z_][\w,.+?#-]*)\s*(=|;)", re.MULTILINE)

    def _node_name(self, m):
        label, node = m.group(1), m.group(2)
        if label:
            return label
        if node == "/":
            return "root"
        return node.lstrip("&")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._NODE.finditer(clean):
            self._register_class(self._node_name(m))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INC_C.finditer(clean):
            hdr = m.group(1)
            self._add_import(file_id, hdr.replace("\\", "/").split("/")[-1], hdr)
        for m in self._INC_DT.finditer(clean):
            hdr = m.group(1)
            self._add_import(file_id, hdr.replace("\\", "/").split("/")[-1], hdr)

        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), "macro")

        # remember node-open positions so property scan can skip node headers
        node_ends = set()
        for m in self._NODE.finditer(clean):
            self._add_class(file_id, self._node_name(m), description="dts node")
            node_ends.add(m.end())

        for m in self._PROP.finditer(clean):
            name = m.group(1)
            # A node opener `foo {` cannot match _PROP (next char is '{' or
            # '@'), so any _PROP hit is a genuine property assignment/flag.
            self._add_variable(file_id, name, "property")
