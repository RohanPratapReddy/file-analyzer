# Chapel (.chpl) analyzer.
#
# Real parser for Chapel (parallel HPC language, C-family braces):
#   use IO, Math;   import List;                    -> import
#   module M { ... }                                 -> module (namespace)
#   proc name(a: int, b: real = 1.0): int { }        -> procedure (function)
#   proc C.method() { }                              -> method on type C
#   iter myiter(): int { }                           -> iterator (function)
#   class Foo : Bar { var x: int; proc m() {} }       -> class (+ parent)
#   record R { var a: real; }                         -> record (class row)
#   var x: int = 5;   const PI = 3.14;   config var n -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_MOD = r"(?:inline|override|proc\s+)?"


class ChapelAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "chapel"
    EXTENSIONS = (".chpl",)

    _USE = re.compile(r"^\s*(?:use|import)\s+([\w., ]+?)\s*;", re.MULTILINE)
    _TYPE = re.compile(
        r"\b(class|record|union)\s+([A-Za-z_]\w*)"
        r"(?:\s*:\s*([\w., ]+?))?"
        r"\s*\{")
    _PROC = re.compile(
        r"(?:inline\s+|override\s+|proc\s+)*"
        r"\b(?:proc|iter|operator)\s+"
        r"(?:([A-Za-z_]\w*)\s*\.\s*)?"                   # optional receiver type
        r"([A-Za-z_]\w*|[-+*/<>=!]+)\s*"
        r"(?:\(([^{;]*?)\))?\s*"
        r"(?::\s*([\w()., \[\]]+?)\s*)?"
        r"(?:throws\s*)?\{")
    _PROTO = re.compile(
        r"^\s*(?:export\s+|extern\s+(?:\"[^\"]*\"\s+)?)"
        r"proc\s+"
        r"(?:([A-Za-z_]\w*)\s*\.\s*)?"
        r"([A-Za-z_]\w*)\s*"
        r"(?:\(([^{;]*?)\))?\s*"
        r"(?::\s*([\w()., \[\]]+?)\s*)?"
        r"(?:throws\s*)?;", re.MULTILINE)
    _VAR = re.compile(
        r"^\s*(?:config\s+)?(?:var|const|param)\s+([A-Za-z_]\w*)\s*"
        r"(?::\s*([\w()., \[\]]+?))?\s*(?:=\s*([^;]+?))?\s*;", re.MULTILINE)
    _FIELD = re.compile(
        r"^\s*(?:var|const|param)\s+([A-Za-z_]\w*)\s*"
        r"(?::\s*([\w()., \[\]]+?))?\s*(?:=\s*([^;]+?))?\s*;", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        for m in self._TYPE.finditer(self._strip_comments(text)):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._USE.finditer(text):
            for mod in m.group(1).split(","):
                mod = mod.strip().split(".")[-1].split(" as ")[0].strip()
                if mod:
                    self._add_import(file_id, mod, mod)

        types = []
        for m in self._TYPE.finditer(text):
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            parents = []
            if m.group(3):
                for p in m.group(3).split(","):
                    p = p.strip().split(".")[-1]
                    if p in self._class_registry:
                        parents.append(self._class_registry[p])
            types.append({"name": m.group(2), "kind": m.group(1), "bstart": bstart,
                          "bend": bend, "parents": parents, "methods": [], "attrs": []})

        def enclosing(pos):
            best = None
            for t in types:
                if t["bstart"] <= pos < t["bend"] and (best is None or t["bstart"] > best["bstart"]):
                    best = t
            return best

        covered = 0
        proc_spans = []
        for m in self._PROC.finditer(text):
            if m.start() < covered:
                continue
            recv, name, params, ret = m.group(1), m.group(2), m.group(3), m.group(4)
            body = text.index("{", m.end() - 1)
            covered = self._find_matching(text, body)
            proc_spans.append((body, covered))
            arg_ids = self._params(params or "")
            out_ids = [self._add_output(ret.strip())] if ret and ret.strip() != "void" else []
            owner = enclosing(m.start())
            cid = None
            if recv and recv in self._class_registry:
                cid = self._class_registry[recv]
            elif owner is not None:
                cid = self._class_registry.get(owner["name"])
            fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
            if recv and recv in self._class_registry:
                # attach to the receiver type row later
                for t in types:
                    if t["name"] == recv:
                        t["methods"].append(fid)
            elif owner is not None:
                owner["methods"].append(fid)

        def in_proc(pos):
            return any(a <= pos < b for a, b in proc_spans)

        # extern/export proc prototypes (no body, end in ';')
        for m in self._PROTO.finditer(text):
            if in_proc(m.start()):
                continue
            recv, name, params, ret = m.group(1), m.group(2), m.group(3), m.group(4)
            arg_ids = self._params(params or "")
            out_ids = [self._add_output(ret.strip())] if ret and ret.strip() != "void" else []
            cid = None
            if recv and recv in self._class_registry:
                cid = self._class_registry[recv]
            fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
            if cid is not None:
                for t in types:
                    if t["name"] == recv:
                        t["methods"].append(fid)

        # class/record fields
        for t in types:
            body = text[t["bstart"] + 1:t["bend"] - 1]
            for fm in self._FIELD.finditer(body):
                # ensure the field isn't inside a nested proc of this type
                abs_pos = t["bstart"] + 1 + fm.start()
                if in_proc(abs_pos):
                    continue
                t["attrs"].append(self._add_arg(fm.group(1),
                                  fm.group(2).strip() if fm.group(2) else None,
                                  fm.group(3).strip() if fm.group(3) else None))

        for m in self._VAR.finditer(text):
            if in_proc(m.start()) or enclosing(m.start()) is not None:
                continue
            self._add_variable(file_id, m.group(1),
                               m.group(3).strip() if m.group(3) else None)

        for t in types:
            self._add_class(file_id, t["name"], description=f"chapel {t['kind']}",
                            parent_ids=t["parents"], method_ids=t["methods"],
                            attr_ids=t["attrs"])

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if not part:
                continue
            part = re.sub(r"^(in|out|inout|ref|const\s+ref|const|param|type)\s+",
                          "", part)
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            if ":" in part:
                nm, atype = part.split(":", 1)
                nm, atype = nm.strip(), atype.strip()
            else:
                nm, atype = part, None
            if nm:
                arg_ids.append(self._add_arg(nm, atype, default))
        return arg_ids
