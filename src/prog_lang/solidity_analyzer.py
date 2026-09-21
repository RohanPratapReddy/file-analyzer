# Solidity (.sol) smart-contract analyzer.
#
# Real parser for Solidity (`//` line, `/* */` block, `///` NatSpec):
#   pragma solidity ^0.8.0;                       -> pragma (import row)
#   import "./Ownable.sol";  import {A} from "x"   -> import
#   contract Token is ERC20, Ownable { ... }       -> contract (class, parents)
#   interface IERC20 { ... }   library SafeMath     -> class row
#   struct Account { uint balance; }                -> struct (class, fields)
#   enum State { Active, Closed }                    -> enum (class, members)
#   function transfer(address to, uint amt) public returns (bool) -> function
#   event Transfer(address indexed from, ...)        -> function (event)
#   uint256 public totalSupply;                      -> state variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class SolidityAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "solidity"
    EXTENSIONS = (".sol",)
    LINE_COMMENTS = ("///", "//")
    BLOCK_COMMENTS = (("/*", "*/"),)

    _PRAGMA = re.compile(r"^\s*pragma\s+([^;]+);", re.MULTILINE)
    _IMPORT = re.compile(r"""^\s*import\s+(?:.*?\bfrom\s+)?['"]([^'"]+)['"]""",
                         re.MULTILINE)
    _CONTRACT = re.compile(
        r"^\s*(?:abstract\s+)?(contract|interface|library)\s+(\w+)"
        r"(?:\s+is\s+([\w.,\s()]+?))?\s*\{", re.MULTILINE)
    _STRUCT = re.compile(r"\bstruct\s+(\w+)\s*\{([^}]*)\}")
    _ENUM = re.compile(r"\benum\s+(\w+)\s*\{([^}]*)\}")
    _FUNC = re.compile(
        r"\bfunction\s+(\w+)\s*\(([^)]*)\)"
        r"([^{;]*?)(?:returns\s*\(([^)]*)\))?\s*[{;]")
    _EVENT = re.compile(r"\bevent\s+(\w+)\s*\(([^)]*)\)")
    _MODIFIER = re.compile(r"\bmodifier\s+(\w+)\s*(?:\(([^)]*)\))?")
    _STATEVAR = re.compile(
        r"^\s*(address|uint\d*|int\d*|bool|string|bytes\d*|mapping)"
        r"[\w\[\]() =>]*?\s+(?:public\s+|private\s+|internal\s+|constant\s+|"
        r"immutable\s+)*(\w+)\s*[=;]", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._CONTRACT.finditer(t):
            self._register_class(m.group(2))
        for m in self._STRUCT.finditer(t):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        # `pragma` is a compiler directive, not a module dependency: record it
        # as a module-scope variable rather than an import.
        for m in self._PRAGMA.finditer(t):
            self._add_variable(file_id, "pragma", m.group(1).strip(),
                               scope="directive")
        for m in self._IMPORT.finditer(t):
            uri = m.group(1)
            self._add_import(file_id, uri.split("/")[-1], uri)

        contract_spans = []
        for m in self._CONTRACT.finditer(t):
            kind, name, bases = m.group(1), m.group(2), m.group(3)
            end = self._find_matching(t, t.index("{", m.start()))
            contract_spans.append((m.start(), end, name))
            parents = []
            if bases:
                for b in bases.split(","):
                    b = b.strip().split("(")[0].strip()
                    if b:
                        pid = self._register_class(b)
                        if pid is not None:
                            parents.append(pid)
            self._add_class(file_id, name, description=f"solidity {kind}",
                            parent_ids=parents)

        for m in self._STRUCT.finditer(t):
            attr_ids = []
            for fld in m.group(2).split(";"):
                fm = re.match(r"\s*([\w\[\].=> ]+?)\s+(\w+)\s*$", fld.strip())
                if fm:
                    attr_ids.append(self._add_arg(fm.group(2),
                                                  fm.group(1).strip()))
            self._add_class(file_id, m.group(1), description="solidity struct",
                            attr_ids=attr_ids)
        for m in self._ENUM.finditer(t):
            attr_ids = [self._add_arg(v.strip(), "enum")
                        for v in m.group(2).split(",") if v.strip()]
            self._add_class(file_id, m.group(1), description="solidity enum",
                            attr_ids=attr_ids)

        def owner(pos):
            for a, b, name in contract_spans:
                if a <= pos < b:
                    return self._class_registry.get(name)
            return None

        for m in self._FUNC.finditer(t):
            name = m.group(1)
            arg_ids = self._params(m.group(2))
            out_ids = []
            if m.group(4):
                for r in self._split_top_level(m.group(4)):
                    out_ids.append(self._add_output(r.strip()))
            self._add_function(file_id, name, arg_ids, out_ids,
                               class_id=owner(m.start()),
                               description="solidity function")
        for m in self._EVENT.finditer(t):
            self._add_function(file_id, m.group(1), self._params(m.group(2)),
                               class_id=owner(m.start()),
                               description="solidity event")
        for m in self._MODIFIER.finditer(t):
            self._add_function(file_id, m.group(1),
                               self._params(m.group(2) or ""),
                               class_id=owner(m.start()),
                               description="solidity modifier")

        for m in self._STATEVAR.finditer(t):
            self._add_variable(file_id, m.group(2), scope="state")

    def _params(self, params):
        ids = []
        for part in self._split_top_level(params):
            toks = part.strip().split()
            if not toks:
                continue
            # last token is the name (unless anonymous); first is the type
            name = toks[-1]
            ty = toks[0]
            if name in ("memory", "calldata", "storage", "indexed"):
                name = ty
            ids.append(self._add_arg(name, ty))
        return ids
