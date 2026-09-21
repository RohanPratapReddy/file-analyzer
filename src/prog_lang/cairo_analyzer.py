# Cairo (.cairo) analyzer -- Cairo 1.0 / StarkNet smart-contract language.
#
# Real parser for Cairo (Rust-derived, C-family braces):
#   use starknet::ContractAddress;                 -> import
#   use array::ArrayTrait;                          -> import
#   mod foo { ... }                                 -> module (namespace)
#   struct Point { x: felt252, y: felt252 }         -> struct (fields)
#   enum Direction { North, South }                 -> enum (variants)
#   trait IShape<T> { fn area(self: @T) -> u256; }  -> trait (class row)
#   impl PointImpl of IShape { fn area ... }         -> impl (methods)
#   #[starknet::contract] mod contract { ... }       -> attributes ignored
#   fn name(a: felt252, b: u256) -> felt252 { }      -> function (params, return)
#   const N: felt252 = 5;   let x = 3;               -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class CairoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "cairo"
    EXTENSIONS = (".cairo",)

    _USE = re.compile(r"^\s*use\s+([\w:]+(?:\s*::\s*\{[^}]*\})?)\s*;", re.MULTILINE)
    _TYPE = re.compile(
        r"\b(struct|enum|trait|impl)\s+([A-Za-z_]\w*)"
        r"(?:<[^{>]*>)?"
        r"(?:\s+of\s+([\w:]+))?"                     # impl X of Trait
        r"(?:\s*<[^{>]*>)?"
        r"\s*\{")
    _FN = re.compile(
        r"(?:pub\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>(]*>)?\s*"
        r"\(([^{;]*?)\)\s*"
        r"(?:->\s*([^{]+?)\s*)?\{")
    _FIELD = re.compile(
        r"^\s*([A-Za-z_]\w*)\s*:\s*([^,{}\n]+?)\s*,?\s*$", re.MULTILINE)
    _CONST = re.compile(
        r"\b(?:const|let)\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::\s*([\w:<>@, ]+?))?"
        r"\s*=\s*([^;]+);")

    def _register_types(self, file_id, text, path):
        for m in self._TYPE.finditer(self._strip_comments(text)):
            if m.group(1) != "impl":
                self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._USE.finditer(text):
            body = m.group(1)
            base = body.split("::{")[0]
            if "::{" in body or body.endswith("}"):
                grp = re.search(r"\{([^}]*)\}", body)
                if grp:
                    for sym in grp.group(1).split(","):
                        sym = sym.strip().split(" as ")[0].strip()
                        if sym and sym != "*":
                            self._add_import(file_id, sym.split("::")[-1],
                                             base + "::" + sym)
                    continue
            name = base.split("::")[-1]
            self._add_import(file_id, name, base)

        types = []
        for m in self._TYPE.finditer(text):
            kind, name = m.group(1), m.group(2)
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            parents = []
            if kind == "impl" and m.group(3):
                tname = m.group(3).split("::")[-1]
                if tname in self._class_registry:
                    parents.append(self._class_registry[tname])
            types.append({"name": name, "kind": kind, "bstart": bstart,
                          "bend": bend, "parents": parents, "methods": [],
                          "attrs": [], "is_impl": kind == "impl"})

        def enclosing(pos):
            best = None
            for t in types:
                if t["bstart"] <= pos < t["bend"] and (best is None or t["bstart"] > best["bstart"]):
                    best = t
            return best

        # struct/enum fields
        for t in types:
            if t["kind"] == "struct":
                body = text[t["bstart"] + 1:t["bend"] - 1]
                for fm in self._FIELD.finditer(body):
                    t["attrs"].append(self._add_arg(fm.group(1), fm.group(2).strip()))
            elif t["kind"] == "enum":
                body = text[t["bstart"] + 1:t["bend"] - 1]
                for variant in self._split_top_level(body):
                    nm = variant.split(":")[0].strip()
                    if nm:
                        t["attrs"].append(self._add_arg(nm, "variant"))

        covered = 0
        for m in self._FN.finditer(text):
            if m.start() < covered:
                pass
            name, params, ret = m.group(1), m.group(2), m.group(3)
            body = text.index("{", m.end() - 1)
            end = self._find_matching(text, body)
            covered = max(covered, end)
            arg_ids = self._params(params)
            out_ids = [self._add_output(ret.strip())] if ret and ret.strip() else []
            owner = enclosing(m.start())
            cid = None
            if owner is not None:
                cid = self._class_registry.get(owner["name"]) if not owner["is_impl"] \
                    else (owner["parents"][0] if owner["parents"] else None)
            fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
            if owner is not None:
                owner["methods"].append(fid)

        for m in self._CONST.finditer(text):
            owner = enclosing(m.start())
            if owner is None:
                self._add_variable(file_id, m.group(1), m.group(3).strip())

        for t in types:
            if t["is_impl"]:
                # merge impl methods into the trait/struct it implements, if known
                target = t["parents"][0] if t["parents"] else None
                if target is not None:
                    # attach methods to that class row on next _add_class merge
                    tgt_name = next((n for n, i in self._class_registry.items() if i == target), None)
                    if tgt_name:
                        self._add_class(file_id, tgt_name, method_ids=t["methods"])
                        continue
            self._add_class(file_id, t["name"], description=f"cairo {t['kind']}",
                            parent_ids=t["parents"], method_ids=t["methods"],
                            attr_ids=t["attrs"])

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if not part:
                continue
            part = re.sub(r"^(ref|mut)\s+", "", part)
            if part in ("self", "@self", "ref self", "@T"):
                self._add_arg("self", "self")
                continue
            if ":" in part:
                nm, atype = part.split(":", 1)
                nm, atype = nm.strip(), atype.strip()
            else:
                nm, atype = part, None
            arg_ids.append(self._add_arg(nm, atype))
        return arg_ids
