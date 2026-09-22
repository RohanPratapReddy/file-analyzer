# Mojo (.mojo / .\U0001F525) analyzer.
#
# Real parser for Mojo (Python-superset systems language, indentation-scoped).
# Mojo ships two source extensions: ``.mojo`` and the emoji ``.\U0001F525``.
#   from memory import UnsafePointer        -> import
#   import math as m                          -> aliased import
#   struct Matrix[T: DType](Copyable):        -> struct (class row, + conformances)
#   trait Stringable:                          -> trait  (class row)
#   fn __init__(inout self, n: Int): ...       -> method
#   fn add(a: Int, b: Int) -> Int: ...         -> method / function
#   def run(x): ...                            -> Python-style function
#   var count: Int = 0                         -> field / variable
#   alias NUM = 8                              -> compile-time alias (variable)
import re

from .regex_base import RegexCodeAnalyzer


class MojoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "mojo"
    EXTENSIONS = (".mojo", ".\U0001f525")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()

    _FROM = re.compile(r"^from\s+([\w.]+)\s+import\s+(.+)$")
    _IMPORT = re.compile(r"^import\s+([\w.]+)(?:\s+as\s+([A-Za-z_]\w*))?")
    _TYPE = re.compile(
        r"^@?\w*\s*(struct|trait)\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:\(([^)]*)\))?\s*:"
    )
    _DEF = re.compile(r"^(fn|def)\s+([A-Za-z_]\w*[!?]?)\s*(?:\[[^\]]*\])?\s*\(")
    _FIELD = re.compile(
        r"^(var|let|alias)\s+([A-Za-z_]\w*)\s*(?::\s*([\w.\[\], ]+?))?\s*(?:=\s*(.+?))?\s*$"
    )

    def _register_types(self, file_id, text, path):
        for raw in self._strip_comments(text).splitlines():
            m = self._TYPE.match(raw.strip())
            if m:
                self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        scopes = []  # stack of {is_class, header_indent, ...}
        classes = []

        for raw in text.splitlines():
            if not raw.strip():
                continue
            ind = self._indent_of(raw)
            line = raw.strip()
            if line.startswith("@"):  # decorator line
                continue

            while scopes and ind <= scopes[-1]["header_indent"]:
                scopes.pop()
            cur_class = next((s for s in reversed(scopes) if s.get("is_class")), None)
            in_func = scopes and not scopes[-1].get("is_class")

            fm = self._FROM.match(line)
            if fm:
                module = fm.group(1)
                for nm in fm.group(2).replace("(", "").replace(")", "").split(","):
                    nm = nm.strip().split(" as ")[0].strip()
                    if nm and nm != "*":
                        self._add_import(file_id, nm, module)
                continue
            im = self._IMPORT.match(line)
            if im:
                self._add_import(
                    file_id,
                    im.group(2) or im.group(1).split(".")[-1],
                    im.group(1),
                    im.group(2),
                )
                continue

            tm = self._TYPE.match(line)
            if tm:
                parents = []
                if tm.group(3):
                    for p in tm.group(3).split(","):
                        p = p.strip().split("[")[0]
                        if p in self._class_registry:
                            parents.append(self._class_registry[p])
                entry = {
                    "name": tm.group(2),
                    "kind": tm.group(1),
                    "parents": parents,
                    "methods": [],
                    "attrs": [],
                    "header_indent": ind,
                    "is_class": True,
                }
                classes.append(entry)
                scopes.append(entry)
                continue

            dm = self._DEF.match(line)
            if dm:
                popen = line.index("(", dm.start())
                # params may be balanced on this line; fall back gracefully.
                pclose = self._find_matching(line, popen, "(", ")")
                params = line[popen + 1 : pclose - 1]
                rest = line[pclose:]
                ret = None
                rmatch = re.search(r"->\s*([\w.\[\], !]+?)\s*:", rest)
                if rmatch:
                    ret = rmatch.group(1).strip()
                arg_ids = self._params(params)
                out_ids = (
                    [self._add_output(ret)] if ret and ret not in ("None",) else []
                )
                cid = self._class_registry.get(cur_class["name"]) if cur_class else None
                fid = self._add_function(
                    file_id, dm.group(2), arg_ids, out_ids, class_id=cid
                )
                if cur_class is not None:
                    cur_class["methods"].append(fid)
                scopes.append({"is_class": False, "header_indent": ind})
                continue

            if in_func:
                continue
            xm = self._FIELD.match(line)
            if xm:
                kind, name, ftype, val = (
                    xm.group(1),
                    xm.group(2),
                    xm.group(3),
                    xm.group(4),
                )
                if cur_class is not None:
                    cur_class["attrs"].append(
                        self._add_arg(
                            name,
                            ftype.strip() if ftype else kind,
                            val.strip() if val else None,
                        )
                    )
                else:
                    self._add_variable(
                        file_id,
                        name,
                        val.strip() if val else None,
                        scope="const" if kind == "alias" else "module",
                    )

        for c in classes:
            self._add_class(
                file_id,
                c["name"],
                description=f"mojo {c['kind']}",
                parent_ids=c["parents"],
                method_ids=c["methods"],
                attr_ids=c["attrs"],
            )

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = re.sub(
                r"\b(?:inout|owned|borrowed|read|mut|ref)\b", "", part
            ).strip()
            if not part or part in ("self", "*", "/"):
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            if ":" in part:
                nm, atype = part.split(":", 1)
                nm, atype = nm.strip(), atype.strip()
            else:
                nm, atype = part.lstrip("*"), None
            if nm and nm != "self":
                arg_ids.append(self._add_arg(nm, atype, default))
        return arg_ids
