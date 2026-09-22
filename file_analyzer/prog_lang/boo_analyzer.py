# Boo (.boo) analyzer.
#
# Real parser for Boo (Python-like .NET language, INDENTATION blocks):
#   import System                              -> import
#   import System.Drawing from System.Drawing  -> import (from assembly)
#   class Foo(Bar, IBaz):                       -> class (+ parents)
#   struct Point:                               -> struct (class row)
#   interface IShape:                           -> interface (class row)
#   enum Color: Red / Green                     -> enum (class row)
#   def name(a as int, b as string) as void:    -> method / function
#   field as int   /   x = 5                     -> attribute / variable
#   [property(Name)] name as string             -> property field
import re

from .regex_base import RegexCodeAnalyzer


class BooAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "boo"
    EXTENSIONS = (".boo",)
    LINE_COMMENTS = ("#", "//")
    BLOCK_COMMENTS = (("/*", "*/"),)

    _IMPORT = re.compile(
        r"^\s*import\s+([\w.]+)(?:\s+from\s+([\w.]+))?(?:\s+as\s+(\w+))?", re.MULTILINE
    )
    _TYPE = re.compile(
        r"^(\s*)(?:\[[^\]]*\]\s*)*(?:public\s+|internal\s+|abstract\s+|"
        r"partial\s+|final\s+|sealed\s+)*"
        r"(class|struct|interface|enum)\s+([A-Za-z_]\w*)"
        r"(?:\s*\(([^)]*)\))?\s*:"
    )
    _DEF = re.compile(
        r"^(\s*)(?:\[[^\]]*\]\s*)*(?:public\s+|private\s+|protected\s+|"
        r"internal\s+|static\s+|virtual\s+|override\s+|abstract\s+|final\s+)*"
        r"def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:as\s+([\w.\[\], ]+?))?\s*:"
    )
    _FIELD = re.compile(r"^(\s*)([A-Za-z_]\w*)\s+as\s+([\w.\[\], ]+?)\s*(?:=\s*(.+))?$")
    _ASSIGN = re.compile(r"^(\s*)([A-Za-z_]\w*)\s*=\s*(.+)$")

    def _register_types(self, file_id, text, path):
        for m in self._TYPE.finditer(self._strip_comments(text)):
            self._register_class(m.group(3))

    def _extract_entities(self, file_id, text, path):
        lines = self._strip_comments(text).splitlines()

        # scopes: stack of (indent, kind, class_name_or_None)
        scopes = []

        def cur_class():
            for indent, kind, name in reversed(scopes):
                if kind == "class":
                    return name
            return None

        def in_def():
            for indent, kind, name in reversed(scopes):
                if kind == "def":
                    return True
                if kind == "class":
                    return False
            return False

        emitted = {}

        def get_class_row(name):
            if name not in emitted:
                emitted[name] = {"methods": [], "attrs": []}
            return emitted[name]

        for raw in lines:
            if not raw.strip():
                continue
            indent = self._indent_of(raw)
            while scopes and indent <= scopes[-1][0]:
                scopes.pop()

            im = self._IMPORT.match(raw)
            if im:
                mod, asm, alias = im.group(1), im.group(2), im.group(3)
                self._add_import(file_id, alias or mod.split(".")[-1], mod, alias)
                continue

            tm = self._TYPE.match(raw)
            if tm:
                name = tm.group(3)
                parents = []
                if tm.group(4):
                    for p in tm.group(4).split(","):
                        p = p.strip().split(".")[-1]
                        if p in self._class_registry:
                            parents.append(self._class_registry[p])
                row = get_class_row(name)
                row["parents"] = parents
                row["kind"] = tm.group(2)
                scopes.append((indent, "class", name))
                continue

            dm = self._DEF.match(raw)
            if dm:
                name, params, ret = dm.group(2), dm.group(3), dm.group(4)
                arg_ids = self._params(params)
                out_ids = (
                    [self._add_output(ret.strip())]
                    if ret and ret.strip() != "void"
                    else []
                )
                owner = cur_class()
                cid = self._class_registry.get(owner) if owner else None
                fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
                if owner is not None:
                    get_class_row(owner)["methods"].append(fid)
                scopes.append((indent, "def", None))
                continue

            if in_def():
                continue

            fm = self._FIELD.match(raw)
            if fm:
                name, vtype, val = fm.group(2), fm.group(3).strip(), fm.group(4)
                owner = cur_class()
                if owner is None:
                    self._add_variable(file_id, name, val.strip() if val else None)
                else:
                    get_class_row(owner)["attrs"].append(
                        self._add_arg(name, vtype, val.strip() if val else None)
                    )
                continue

            am = self._ASSIGN.match(raw)
            if am:
                name, val = am.group(2), am.group(3)
                owner = cur_class()
                if owner is None:
                    self._add_variable(file_id, name, val.strip())
                else:
                    get_class_row(owner)["attrs"].append(
                        self._add_arg(name, None, val.strip())
                    )
                continue

        for name, row in emitted.items():
            self._add_class(
                file_id,
                name,
                description=f"boo {row.get('kind','class')}",
                parent_ids=row.get("parents", []),
                method_ids=row["methods"],
                attr_ids=row["attrs"],
            )

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip().lstrip("*")
            if not part or part == "self":
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            if " as " in part:
                nm, atype = part.split(" as ", 1)
                nm, atype = nm.strip(), atype.strip()
            else:
                nm, atype = part, None
            arg_ids.append(self._add_arg(nm, atype, default))
        return arg_ids
