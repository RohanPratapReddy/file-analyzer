# VHDL (.vhdl / .vhd) analyzer.
#
# Real parser for VHDL (`--` line comments, case INSENSITIVE keywords):
#   library IEEE;                                 -> import
#   use IEEE.STD_LOGIC_1164.ALL;                   -> import
#   entity counter is port ( clk : in std_logic; ...); end  -> entity (class, ports)
#   architecture rtl of counter is ... begin ... end -> architecture (class)
#   signal q : std_logic_vector(7 downto 0);        -> variable
#   function inc (a : integer) return integer        -> function
#   procedure reset (signal s : out std_logic)       -> function
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class VhdlAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "vhdl"
    EXTENSIONS = (".vhdl", ".vhd")
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()

    _LIBRARY = re.compile(r"^\s*library\s+([\w,\s]+);", re.I | re.MULTILINE)
    _USE = re.compile(r"^\s*use\s+([\w.]+)", re.I | re.MULTILINE)
    _ENTITY = re.compile(
        r"\bentity\s+(\w+)\s+is\b(.*?)\bend\b\s*(?:entity\b)?\s*\w*\s*;",
        re.I | re.DOTALL)
    _ARCH = re.compile(r"\barchitecture\s+(\w+)\s+of\s+(\w+)\s+is",
                       re.I)
    _SIGNAL = re.compile(r"^\s*signal\s+([\w,\s]+?)\s*:\s*([^;:=]+)",
                         re.I | re.MULTILINE)
    _SUBPROG = re.compile(
        r"\b(function|procedure)\s+(\w+)\s*(?:\(([^)]*)\))?"
        r"(?:\s*return\s+(\w+))?", re.I)
    _PORT = re.compile(r"(\w+)\s*:\s*(in|out|inout|buffer)\s+([\w()' downto0-9]+)",
                       re.I)

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._ENTITY.finditer(t):
            self._register_class(m.group(1))
        for m in self._ARCH.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._LIBRARY.finditer(t):
            for lib in m.group(1).split(","):
                lib = lib.strip()
                if lib:
                    self._add_import(file_id, lib, lib)
        for m in self._USE.finditer(t):
            parts = m.group(1).split(".")
            # `use lib.pkg.all` selects everything in a package: name the import
            # after the package, not the trailing `all` clause.
            segs = [p for p in parts if p]
            name = segs[-1]
            if name.lower() == "all" and len(segs) >= 2:
                name = segs[-2]
            self._add_import(file_id, name, m.group(1))

        for m in self._ENTITY.finditer(t):
            name, body = m.group(1), m.group(2)
            attr_ids = []
            for pm in self._PORT.finditer(body):
                attr_ids.append(self._add_arg(pm.group(1),
                                f"{pm.group(2)} {pm.group(3).strip()}"))
            self._add_class(file_id, name, description="vhdl entity",
                            attr_ids=attr_ids)

        for m in self._ARCH.finditer(t):
            parents = []
            pid = self._class_registry.get(m.group(2))
            if pid is not None:
                parents.append(pid)
            self._add_class(file_id, m.group(1), description="vhdl architecture",
                            parent_ids=parents)

        for m in self._SIGNAL.finditer(t):
            for nm in m.group(1).split(","):
                nm = nm.strip()
                if nm:
                    self._add_variable(file_id, nm, m.group(2).strip(),
                                       scope="signal")

        for m in self._SUBPROG.finditer(t):
            kind, name, params, ret = m.groups()
            arg_ids = []
            for pm in self._PORT.finditer(params or ""):
                arg_ids.append(self._add_arg(pm.group(1), pm.group(3).strip()))
            if not arg_ids and params:
                for part in params.split(";"):
                    if ":" in part:
                        nm = part.split(":")[0].strip().split()[-1]
                        arg_ids.append(self._add_arg(nm))
            out_ids = [self._add_output(ret)] if ret else []
            self._add_function(file_id, name, arg_ids, out_ids,
                               description=f"vhdl {kind}")
