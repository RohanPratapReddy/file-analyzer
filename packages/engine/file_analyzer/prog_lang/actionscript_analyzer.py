# ActionScript 3 (.as) analyzer.
#
# Real parser for ActionScript (ECMAScript-4 family, Java-like braces):
#   package foo.bar { ... }                       -> (namespace, ignored)
#   import flash.display.Sprite;                    -> import
#   public class Foo extends Bar implements IBaz {} -> class (+ parents)
#   public interface I extends J { }                -> interface (class row)
#   public function name(a:int, b:String="x"):void -> method / function
#   public function get width():Number { }          -> accessor (method)
#   public var x:int = 0;  private const Y:Number   -> field / variable
import re

from .regex_base import RegexCodeAnalyzer

_MOD = (
    r"(?:public|private|protected|internal|static|final|override|"
    r"dynamic|native|[\w.]+::)\s+"
)


class ActionScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "actionscript"
    EXTENSIONS = (".as",)

    _IMPORT = re.compile(r"^\s*import\s+([\w.*]+)\s*;", re.MULTILINE)
    _TYPE = re.compile(
        r"(?:" + _MOD + r")*"
        r"\b(class|interface)\s+([A-Za-z_]\w*)"
        r"(?:\s+extends\s+([\w.]+))?"
        r"(?:\s+implements\s+([\w.<>, ]+?))?"
        r"\s*\{"
    )
    _METHOD = re.compile(
        r"(?:" + _MOD + r")*"
        r"function\s+(?:(get|set)\s+)?([A-Za-z_]\w*)\s*"
        r"\(([^{;]*?)\)\s*"
        r"(?::\s*([\w.*<>]+))?\s*\{"
    )
    _FIELD = re.compile(
        r"(?:" + _MOD + r")*"
        r"(?:var|const)\s+([A-Za-z_]\w*)\s*"
        r"(?::\s*([\w.*<>]+))?\s*"
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
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            parents = []
            for grp in (m.group(3), m.group(4)):
                if grp:
                    for p in grp.split(","):
                        p = p.split(".")[-1].strip()
                        if p in self._class_registry:
                            parents.append(self._class_registry[p])
            types.append(
                {
                    "name": m.group(2),
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
            acc, name, params, ret = m.group(1), m.group(2), m.group(3), m.group(4)
            body = text.index("{", m.end() - 1)
            covered = self._find_matching(text, body)
            method_spans.append((body, covered))
            arg_ids = self._params(params)
            out_ids = [self._add_output(ret)] if ret and ret != "void" else []
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
            name, vtype, val = m.group(1), m.group(2), m.group(3)
            owner = enclosing(m.start())
            if owner is None:
                self._add_variable(file_id, name, val.strip() if val else None)
            else:
                owner["attrs"].append(
                    self._add_arg(name, vtype, val.strip() if val else None)
                )

        for t in types:
            self._add_class(
                file_id,
                t["name"],
                description=f"actionscript {t['kind']}",
                parent_ids=t["parents"],
                method_ids=t["methods"],
                attr_ids=t["attrs"],
            )

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if not part or part == "...":
                continue
            if part.startswith("..."):
                arg_ids.append(self._add_arg(part[3:].split(":")[0].strip(), "rest"))
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
