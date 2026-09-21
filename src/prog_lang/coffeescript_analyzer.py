# CoffeeScript (.coffee) / Literate CoffeeScript (.litcoffee) analyzer.
#
# Real parser for CoffeeScript (indentation-scoped, compiles to JavaScript):
#   fs = require 'fs'                     -> import
#   {readFile} = require 'fs'             -> destructured import
#   class Animal extends Base             -> class (+ superclass)
#   constructor: (@name) ->               -> constructor (method)
#   move: (meters) ->                     -> method (bound with => too)
#   square = (x) -> x * x                 -> top-level function
#   count = 0                             -> top-level variable
# Literate CoffeeScript keeps only indented (>=4 col / tab) lines as code.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class CoffeeScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "coffeescript"
    EXTENSIONS = (".coffee", ".litcoffee")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("###", "###"),)

    _REQUIRE = re.compile(
        r"^(?:\{([^}]*)\}|([A-Za-z_$][\w$]*))\s*=\s*require\s*\(?\s*['\"]([^'\"]+)['\"]")
    _CLASS = re.compile(
        r"^class\s+([A-Za-z_$][\w$.]*)(?:\s+extends\s+([\w$.]+))?")
    _METHOD = re.compile(
        r"^([A-Za-z_$@][\w$]*)\s*:\s*(?:\(([^)]*)\))?\s*[-=]>")
    _FUNC = re.compile(
        r"^([A-Za-z_$][\w$.]*)\s*[:=]\s*(?:\(([^)]*)\))?\s*[-=]>")
    _VAR = re.compile(r"^([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*$")

    def _litcode(self, text):
        out = []
        for line in text.splitlines():
            if not line.strip():
                out.append("")
            elif line.startswith("\t"):
                out.append(line[1:])
            elif line.startswith("    "):
                out.append(line[4:])
            else:
                out.append("")   # prose -> blank
        return "\n".join(out)

    def _prep(self, text, path):
        if path.suffix == ".litcoffee":
            text = self._litcode(text)
        return self._strip_comments(text)

    def _register_types(self, file_id, text, path):
        for m in self._CLASS.finditer(self._prep(text, path)):
            self._register_class(m.group(1).split(".")[-1])

    def _extract_entities(self, file_id, text, path):
        text = self._prep(text, path)
        classes = []
        scopes = []   # stack of {is_class, header_indent, ...}

        for raw in text.splitlines():
            if not raw.strip():
                continue
            ind = self._indent_of(raw)
            line = raw.strip()

            while scopes and ind <= scopes[-1]["header_indent"]:
                scopes.pop()
            cur_class = next((s for s in reversed(scopes) if s.get("is_class")), None)
            in_func = any(not s.get("is_class") for s in scopes)

            rm = self._REQUIRE.match(line)
            if rm:
                src = rm.group(3)
                self._add_import(file_id, src.split("/")[-1], src)
                continue

            cm = self._CLASS.match(line)
            if cm:
                name = cm.group(1).split(".")[-1]
                parents = []
                if cm.group(2):
                    p = cm.group(2).split(".")[-1]
                    if p in self._class_registry:
                        parents.append(self._class_registry[p])
                entry = {"name": name, "parents": parents, "methods": [],
                         "attrs": [], "header_indent": ind, "is_class": True}
                classes.append(entry)
                scopes.append(entry)
                continue

            if cur_class is not None and not in_func:
                mm = self._METHOD.match(line)
                if mm:
                    arg_ids = self._params(mm.group(2) or "")
                    fid = self._add_function(
                        file_id, mm.group(1).lstrip("@"), arg_ids, [],
                        class_id=self._class_registry.get(cur_class["name"]),
                        description="constructor" if mm.group(1) == "constructor" else None)
                    cur_class["methods"].append(fid)
                    scopes.append({"is_class": False, "header_indent": ind})
                    continue

            fm = self._FUNC.match(line)
            if fm and not in_func and cur_class is None:
                arg_ids = self._params(fm.group(2) or "")
                self._add_function(file_id, fm.group(1).split(".")[-1], arg_ids, [])
                scopes.append({"is_class": False, "header_indent": ind})
                continue

            if not in_func and cur_class is None:
                vm = self._VAR.match(line)
                if vm and "->" not in line and "=>" not in line:
                    self._add_variable(file_id, vm.group(1), vm.group(2).strip())
                    continue

        for c in classes:
            self._add_class(file_id, c["name"], description="coffeescript class",
                            parent_ids=c["parents"], method_ids=c["methods"],
                            attr_ids=c["attrs"])

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
            arg_ids.append(self._add_arg(part.lstrip("@."), None, default))
        return arg_ids
