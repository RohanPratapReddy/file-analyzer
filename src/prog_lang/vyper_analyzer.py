# Vyper (.vy) analyzer -- Ethereum smart-contract language (Pythonic).
#
# Real parser for Vyper (INDENTATION blocks, Python-like, ``#`` comments):
#   import ERC20                                    -> import
#   from vyper.interfaces import ERC20              -> import
#   from ethereum.ercs import IERC20                -> import
#   interface Foo: ...                              -> interface (class row)
#   struct Point:  \n  x: uint256  \n  y: uint256   -> struct (fields)
#   event Transfer: ...                             -> event (class row)
#   flag Roles: ADMIN / USER                        -> enum/flag (class row)
#   @external\ndef name(a: uint256, b: address) -> bool: ...  -> function
#   balances: public(HashMap[address, uint256])     -> state variable
#   TOTAL: constant(uint256) = 100                  -> constant variable
import re

from .regex_base import RegexCodeAnalyzer


class VyperAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "vyper"
    EXTENSIONS = (".vy",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (('"""', '"""'), ("'''", "'''"))

    _IMPORT = re.compile(r"^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?", re.MULTILINE)
    _FROM = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+([\w., *]+)", re.MULTILINE)
    _TYPE = re.compile(
        r"^(\s*)(interface|struct|event|enum|flag)\s+([A-Za-z_]\w*)\s*:",
    )
    _DEF = re.compile(
        r"^(\s*)def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*" r"(?:->\s*([^:]+?)\s*)?:"
    )
    _STATEVAR = re.compile(r"^([A-Za-z_]\w*)\s*:\s*(.+)$")

    def _register_types(self, file_id, text, path):
        for line in self._strip_comments(text).splitlines():
            m = self._TYPE.match(line)
            if m:
                self._register_class(m.group(3))

    def _extract_entities(self, file_id, text, path):
        lines = self._strip_comments(text).splitlines()

        for line in lines:
            im = self._IMPORT.match(line)
            if im:
                mod, alias = im.group(1), im.group(2)
                self._add_import(file_id, alias or mod.split(".")[-1], mod, alias)
                continue
            fm = self._FROM.match(line)
            if fm:
                pkg = fm.group(1)
                for sym in fm.group(2).split(","):
                    sym = sym.strip().split(" as ")[0].strip()
                    if sym and sym != "*":
                        self._add_import(file_id, sym, f"{pkg}.{sym}")

        n = len(lines)
        emitted = {}

        def body_indent(i, header_indent):
            for j in range(i + 1, n):
                if not lines[j].strip():
                    continue
                return self._indent_of(lines[j])
            return header_indent + 4

        i = 0
        # decorator/attribute tracking for functions
        while i < n:
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            indent = self._indent_of(line)

            tm = self._TYPE.match(line)
            if tm:
                kind, name = tm.group(2), tm.group(3)
                bi = body_indent(i, indent)
                attrs, methods = [], []
                j = i + 1
                while j < n:
                    if not lines[j].strip():
                        j += 1
                        continue
                    if self._indent_of(lines[j]) < bi:
                        break
                    if self._indent_of(lines[j]) == bi:
                        member = lines[j].strip()
                        # interface: `def foo(...) -> T: view`
                        dm = self._DEF.match(lines[j])
                        if dm:
                            arg_ids = self._params(dm.group(3))
                            out_ids = (
                                [self._add_output(dm.group(4).strip())]
                                if dm.group(4)
                                else []
                            )
                            cid = self._class_registry.get(name)
                            fid = self._add_function(
                                file_id, dm.group(2), arg_ids, out_ids, class_id=cid
                            )
                            methods.append(fid)
                        elif ":" in member:
                            fn = member.split(":", 1)[0].strip()
                            ft = member.split(":", 1)[1].strip()
                            if fn and re.match(r"^[A-Za-z_]\w*$", fn):
                                attrs.append(self._add_arg(fn, ft or kind))
                        else:
                            # flag/enum member (bare name)
                            nm = member.rstrip(",").strip()
                            if re.match(r"^[A-Za-z_]\w*$", nm):
                                attrs.append(self._add_arg(nm, kind))
                    j += 1
                emitted[name] = {"kind": kind, "attrs": attrs, "methods": methods}
                i = j
                continue

            dm = self._DEF.match(line)
            if dm and indent == 0:
                arg_ids = self._params(dm.group(3))
                out_ids = [self._add_output(dm.group(4).strip())] if dm.group(4) else []
                self._add_function(file_id, dm.group(2), arg_ids, out_ids)
                # skip body
                bi = body_indent(i, indent)
                j = i + 1
                while j < n and (
                    not lines[j].strip() or self._indent_of(lines[j]) >= bi
                ):
                    j += 1
                i = j
                continue

            # top-level state variable / constant: `name: type` at indent 0
            if indent == 0:
                sm = self._STATEVAR.match(line)
                if sm and sm.group(1) not in (
                    "import",
                    "from",
                    "def",
                    "interface",
                    "struct",
                    "event",
                    "enum",
                    "flag",
                    "implements",
                    "if",
                    "for",
                    "return",
                ):
                    self._add_variable(file_id, sm.group(1), sm.group(2).strip())
            i += 1

        for name, row in emitted.items():
            self._add_class(
                file_id,
                name,
                description=f"vyper {row['kind']}",
                method_ids=row["methods"],
                attr_ids=row["attrs"],
            )

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if not part or part == "self":
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            if ":" in part:
                nm, atype = part.split(":", 1)
                nm, atype = nm.strip(), atype.strip()
            else:
                nm, atype = part, None
            arg_ids.append(self._add_arg(nm, atype, default))
        return arg_ids
