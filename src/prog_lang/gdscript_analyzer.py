# GDScript (.gd) analyzer.
#
# Real parser for GDScript (Godot's Python-like, indentation-scoped language).
# The file itself is a class; `class_name` names it and `extends` sets its base.
#   extends Node2D                        -> file-class parent
#   class_name Player                      -> file-class name
#   const Bullet = preload("res://b.gd")   -> import (preload/load)
#   signal hit(damage)                     -> signal (attribute)
#   func _ready(): / func f(x: int) -> T:  -> method
#   var speed = 5 / @export var hp: int    -> field (attribute)
#   const MAX = 10                         -> constant (attribute)
#   enum State { IDLE, RUN }               -> nested enum (class row)
#   class Inner extends Ref: ...           -> inner class (indented body)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class GDScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "gdscript"
    EXTENSIONS = (".gd",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()

    _FUNC = re.compile(r"^func\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:->\s*([\w.\[\], ]+?))?\s*:")
    _VAR = re.compile(r"^(?:@\w+(?:\([^)]*\))?\s*)*(?:static\s+)?var\s+([A-Za-z_]\w*)\s*(?::\s*([\w.\[\], ]+?))?\s*(?:=\s*(.+?))?\s*$")
    _CONST = re.compile(r"^const\s+([A-Za-z_]\w*)\s*(?::\s*[\w.]+)?\s*=\s*(.+?)\s*$")
    _SIGNAL = re.compile(r"^signal\s+([A-Za-z_]\w*)\s*(?:\(([^)]*)\))?")
    _CLASS = re.compile(r"^class\s+([A-Za-z_]\w*)\s*(?:extends\s+([\w.\"']+)\s*)?:")
    _ENUM = re.compile(r"^enum\s+([A-Za-z_]\w*)?\s*\{([^}]*)\}")
    _PRELOAD = re.compile(r'(?:preload|load)\s*\(\s*["\']([^"\']+)["\']\s*\)')

    def _register_types(self, file_id, text, path):
        stem = path.stem
        text = self._strip_comments(text)
        cm = re.search(r"^class_name\s+([A-Za-z_]\w*)", text, re.MULTILINE)
        self._register_class(cm.group(1) if cm else stem)
        for m in self._CLASS.finditer(text):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(text):
            if m.group(1):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        stem = path.stem
        cm = re.search(r"^class_name\s+([A-Za-z_]\w*)", text, re.MULTILINE)
        file_name = cm.group(1) if cm else stem
        em = re.search(r"^extends\s+([\w.\"']+)", text, re.MULTILINE)
        file_parents = []
        if em:
            base = em.group(1).strip("\"'").split(".")[-1].replace(".gd", "")
            if base in self._class_registry:
                file_parents.append(self._class_registry[base])
        file_cls = {"name": file_name, "kind": "gdscript", "parents": file_parents,
                    "methods": [], "attrs": [], "header_indent": -1, "is_class": True}
        emitted = [file_cls]
        scopes = [file_cls]

        for raw in text.splitlines():
            if not raw.strip():
                continue
            ind = self._indent_of(raw)
            line = raw.strip()

            while len(scopes) > 1 and ind <= scopes[-1]["header_indent"]:
                scopes.pop()
            cur = scopes[-1]
            cur_class = next((s for s in reversed(scopes) if s.get("is_class")), file_cls)

            for pm in self._PRELOAD.finditer(line):
                src = pm.group(1)
                self._add_import(file_id, src.split("/")[-1], src)

            cmatch = self._CLASS.match(line)
            if cmatch:
                parents = []
                if cmatch.group(2):
                    b = cmatch.group(2).strip("\"'").split(".")[-1]
                    if b in self._class_registry:
                        parents.append(self._class_registry[b])
                entry = {"name": cmatch.group(1), "kind": "inner class",
                         "parents": parents, "methods": [], "attrs": [],
                         "header_indent": ind, "is_class": True}
                emitted.append(entry)
                scopes.append(entry)
                continue

            fmatch = self._FUNC.match(line)
            if fmatch:
                arg_ids = self._params(fmatch.group(2))
                ret = fmatch.group(3)
                out_ids = [self._add_output(ret.strip())] if ret and ret.strip() != "void" else []
                fid = self._add_function(file_id, fmatch.group(1), arg_ids, out_ids,
                                         class_id=self._class_registry.get(cur_class["name"]))
                cur_class["methods"].append(fid)
                scopes.append({"is_class": False, "header_indent": ind})
                continue

            if not cur.get("is_class"):
                # inside a function body -> skip locals
                continue

            enm = self._ENUM.match(line)
            if enm:
                if enm.group(1):
                    members = [x.split("=")[0].strip() for x in enm.group(2).split(",") if x.strip()]
                    aids = [self._add_arg(x, "enum") for x in members]
                    self._add_class(file_id, enm.group(1), description="gdscript enum",
                                    attr_ids=aids)
                else:
                    for x in enm.group(2).split(","):
                        x = x.split("=")[0].strip()
                        if x:
                            cur_class["attrs"].append(self._add_arg(x, "enum"))
                continue

            smatch = self._SIGNAL.match(line)
            if smatch:
                cur_class["attrs"].append(self._add_arg(smatch.group(1), "signal"))
                continue

            komatch = self._CONST.match(line)
            if komatch:
                cur_class["attrs"].append(self._add_arg(komatch.group(1), "const",
                                                        komatch.group(2).strip()))
                continue

            vmatch = self._VAR.match(line)
            if vmatch:
                cur_class["attrs"].append(self._add_arg(
                    vmatch.group(1), vmatch.group(2).strip() if vmatch.group(2) else None,
                    vmatch.group(3).strip() if vmatch.group(3) else None))
                continue

        for t in emitted:
            self._add_class(file_id, t["name"], description=f"{t['kind']}",
                            parent_ids=t["parents"], method_ids=t["methods"],
                            attr_ids=t["attrs"])

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if not part:
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
