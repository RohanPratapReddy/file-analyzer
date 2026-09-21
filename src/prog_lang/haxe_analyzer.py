# Haxe (.hx) analyzer.
#
# Real parser for Haxe (ECMAScript/ActionScript-family, strongly typed):
#   package foo.bar;                          -> (namespace, ignored as entity)
#   import foo.Bar;  using foo.Tools;         -> import
#   class Foo extends Bar implements IBaz {}  -> class (+ parents)
#   interface I extends J {}                   -> interface (class row)
#   enum Color {} / enum abstract E(Int) {}    -> class row
#   typedef Point = { x:Int, y:Int }           -> class row
#   abstract Meters(Float) {}                   -> class row
#   function name(a:Int, b="x"):Void {}         -> method / function
#   var x:Int = 0;  final y = 1;                -> field / variable
import re

from .regex_base import RegexCodeAnalyzer

_MOD = (
    r"(?:public|private|static|inline|override|dynamic|macro|extern|"
    r"final|abstract|overload)\s+"
)


class HaxeAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "haxe"
    EXTENSIONS = (".hx",)

    _IMPORT = re.compile(r"^\s*(?:import|using)\s+([\w.*]+)", re.MULTILINE)
    _TYPE = re.compile(
        r"\b(class|interface|enum|typedef|abstract)\s+"
        r"([A-Za-z_]\w*)"
        r"(?:\s*<[^{(=]*?>)?"
        r"(?:\s*\([^)]*\))?"  # abstract underlying type
        r"(?:\s*=\s*[^{;]*)?"  # typedef alias head
        r"(?:\s+(?:extends|implements|from|to)\s+[\w.<>, ]+?)*"
        r"\s*\{"
    )
    _EXTENDS = re.compile(r"(?:extends|implements)\s+([\w.]+)")
    _METHOD = re.compile(
        r"(?:" + _MOD + r")*"
        r"function\s+([A-Za-z_]\w*)\s*"
        r"(?:<[^>]*>)?\s*"
        r"\(([^{;]*?)\)\s*"
        r"(?::\s*([\w.<>,\[\]{}? ]+?))?\s*\{"
    )
    _FIELD = re.compile(
        r"(?:" + _MOD + r")*"
        r"(?:var|final)\s+([A-Za-z_]\w*)\s*"
        r"(?:\([^)]*\))?"  # property access (get,set)
        r"(?::\s*([\w.<>,\[\]{}? ]+?))?\s*"
        r"(?:=\s*([^;]+?))?\s*;"
    )

    def _register_types(self, file_id, text, path):
        for m in self._TYPE.finditer(self._strip_comments(text)):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._IMPORT.finditer(text):
            src = m.group(1)
            self._add_import(file_id, src.split(".")[-1], src)

        types = []
        for m in self._TYPE.finditer(text):
            name = m.group(2)
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            header = text[m.start() : bstart]
            parents = [
                self._class_registry[p.split(".")[-1]]
                for p in self._EXTENDS.findall(header)
                if p.split(".")[-1] in self._class_registry
            ]
            types.append(
                {
                    "name": name,
                    "kind": m.group(1),
                    "bstart": bstart,
                    "bend": bend,
                    "parents": parents,
                    "methods": [],
                    "attrs": [],
                }
            )

        def enclosing(pos):
            best = None
            for t in types:
                if t["bstart"] <= pos < t["bend"] and (
                    best is None or t["bstart"] > best["bstart"]
                ):
                    best = t
            return best

        covered = 0
        method_spans = []
        for m in self._METHOD.finditer(text):
            if m.start() < covered:
                continue
            name, params, ret = m.group(1), m.group(2), m.group(3)
            body = text.index("{", m.end() - 1)
            covered = self._find_matching(text, body)
            method_spans.append((body, covered))
            arg_ids = self._params(params)
            out_ids = (
                [self._add_output(ret.strip())] if ret and ret.strip() != "Void" else []
            )
            owner = enclosing(m.start())
            cid = self._class_registry.get(owner["name"]) if owner else None
            fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
            if owner is not None:
                owner["methods"].append(fid)

        def in_method(pos):
            return any(a <= pos < b for a, b in method_spans)

        for m in self._FIELD.finditer(text):
            if in_method(m.start()):
                continue
            owner = enclosing(m.start())
            name, vtype, val = m.group(1), m.group(2), m.group(3)
            if owner is None:
                self._add_variable(file_id, name, val.strip() if val else None)
            else:
                owner["attrs"].append(
                    self._add_arg(
                        name,
                        vtype.strip() if vtype else None,
                        val.strip() if val else None,
                    )
                )

        for t in types:
            self._add_class(
                file_id,
                t["name"],
                description=f"haxe {t['kind']}",
                parent_ids=t["parents"],
                method_ids=t["methods"],
                attr_ids=t["attrs"],
            )

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip().lstrip("?")
            if not part:
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            if ":" in part:
                nm, atype = part.split(":", 1)
                nm, atype = nm.strip().lstrip("?"), atype.strip()
            else:
                nm, atype = part.lstrip("?"), None
            arg_ids.append(self._add_arg(nm, atype, default))
        return arg_ids
