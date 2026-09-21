# Crystal (.cr) analyzer.
#
# Crystal is Ruby-like: blocks are closed with ``end`` (no braces), comments are
# ``#`` only. Real parser tracking a block stack so methods bind to the type that
# encloses them:
#   require "http/server"                 -> import
#   class Foo < Bar ... end               -> class (+ superclass)
#   module M ... end / struct S ... end   -> class row
#   enum Color ... end / lib LibC ... end -> class row
#   def name(a, b : Int32) : String ...   -> method / function
#   def self.name(...)                    -> static method
#   @ivar / @@cvar / CONST = value        -> variable / attribute
#   getter/setter/property name           -> attribute
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_TYPE_KINDS = ("class", "module", "struct", "enum", "lib", "annotation", "union")
_OPENERS = _TYPE_KINDS + ("def", "macro", "if", "unless", "while", "until",
                          "case", "begin", "select")


class CrystalAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "crystal"
    EXTENSIONS = (".cr",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()

    _REQUIRE = re.compile(r'^\s*require\s+"([^"]+)"')
    _TYPE = re.compile(
        r"^(?:abstract\s+|private\s+)*"
        r"(class|module|struct|enum|lib|annotation)\s+"
        r"([A-Z][\w:]*)"
        r"(?:\s*<\s*([\w:]+))?")
    _DEF = re.compile(
        r"^(?:abstract\s+|private\s+|protected\s+)*"
        r"def\s+(?:(self)\.)?([A-Za-z_]\w*[?!=]?)\s*(?:\(([^)]*)\))?"
        r"(?:\s*:\s*([\w:()\[\], ]+))?")
    # C-binding `fun` inside a lib: `fun name = c_name(args) : Ret` or
    # `fun name(args) : Ret`. Single-line, no body/end.
    _FUN = re.compile(
        r"^fun\s+([A-Za-z_]\w*[?!]?)\s*(?:=\s*[\w.]+)?"
        r"\s*(?:\(([^)]*)\))?\s*(?::\s*([\w:()\[\], *]+))?\s*$")
    _MACRO_ATTR = re.compile(
        r"^\s*(getter|setter|property|class_getter|class_property)[!?]?\s+(.+)$")
    _CONST = re.compile(r"^([A-Z][A-Z0-9_]*)\s*=\s*(.+)$")
    _IVAR = re.compile(r"^(@@?[a-z_]\w*)\s*=\s*(.+)$")

    def _register_types(self, file_id, text, path):
        for raw in self._strip_comments(text).splitlines():
            m = self._TYPE.match(raw.strip())
            if m:
                self._register_class(m.group(2).split("::")[-1])

    def _statements(self, line):
        return [s.strip() for s in self._split_top_level(line, ";") if s.strip()]

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        stack = []        # dicts for types; {"type_entry": False} sentinels for others
        emitted = []

        def enclosing_type():
            for e in reversed(stack):
                if e.get("is_type"):
                    return e
            return None

        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            rm = self._REQUIRE.match(raw)
            if rm:
                src = rm.group(1)
                self._add_import(file_id, src.split("/")[-1], src)
                continue

            for stmt in self._statements(line):
                if not stmt:
                    continue
                head = stmt.split()[0] if stmt.split() else ""

                tm = self._TYPE.match(stmt)
                if tm:
                    name = tm.group(2).split("::")[-1]
                    parents = []
                    if tm.group(3):
                        p = tm.group(3).split("::")[-1]
                        if p in self._class_registry:
                            parents.append(self._class_registry[p])
                    entry = {"is_type": True, "name": name, "kind": tm.group(1),
                             "parents": parents, "methods": [], "attrs": []}
                    stack.append(entry)
                    emitted.append(entry)
                    continue

                dm = self._DEF.match(stmt)
                if dm:
                    name = dm.group(2)
                    arg_ids = self._params(dm.group(3) or "")
                    out_ids = [self._add_output(dm.group(4).strip())] if dm.group(4) else []
                    owner = enclosing_type()
                    cid = self._class_registry.get(owner["name"]) if owner else None
                    fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
                    if owner is not None:
                        owner["methods"].append(fid)
                    # `abstract def` has no body/end; a one-line `def f; …; end`
                    # is popped by its own trailing `end` statement (same line).
                    if not stmt.startswith("abstract"):
                        stack.append({"is_type": False})
                    continue

                fm = self._FUN.match(stmt)
                if fm:
                    arg_ids = self._params(fm.group(2) or "")
                    out_ids = [self._add_output(fm.group(3).strip())] if fm.group(3) else []
                    owner = enclosing_type()
                    cid = self._class_registry.get(owner["name"]) if owner else None
                    fid = self._add_function(file_id, fm.group(1), arg_ids, out_ids,
                                             class_id=cid)
                    if owner is not None:
                        owner["methods"].append(fid)
                    continue

                am = self._MACRO_ATTR.match(stmt)
                if am:
                    owner = enclosing_type()
                    for spec in am.group(2).split(","):
                        nm = spec.strip().split(":")[0].lstrip("@").strip()
                        nm = nm.split("=")[0].strip()
                        if nm:
                            aid = self._add_arg(nm, "property")
                            if owner is not None:
                                owner["attrs"].append(aid)
                    continue

                cm = self._CONST.match(stmt)
                if cm and head not in _OPENERS:
                    owner = enclosing_type()
                    if owner is None:
                        self._add_variable(file_id, cm.group(1), cm.group(2).strip())
                    else:
                        owner["attrs"].append(self._add_arg(cm.group(1), "const",
                                                            cm.group(2).strip()))
                    continue

                im = self._IVAR.match(stmt)
                if im:
                    owner = enclosing_type()
                    if owner is not None:
                        owner["attrs"].append(self._add_arg(im.group(1), "ivar",
                                                            im.group(2).strip()))
                    else:
                        self._add_variable(file_id, im.group(1), im.group(2).strip())
                    continue

                # generic block bookkeeping
                if head in _OPENERS:
                    stack.append({"is_type": False})
                elif re.search(r"(^|\s)do(\s*\|[^|]*\|)?\s*$", stmt):
                    stack.append({"is_type": False})
                if stmt == "end" or stmt.startswith("end ") or stmt.endswith(" end") or stmt == "}":
                    for _ in range(stmt.count("end")):
                        if stack:
                            stack.pop()

        for t in emitted:
            self._add_class(file_id, t["name"], description=f"crystal {t['kind']}",
                            parent_ids=t["parents"], method_ids=t["methods"],
                            attr_ids=t["attrs"])

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip().lstrip("*&")
            if not part or part == "*":
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                default = default.strip()
            part = part.strip()
            if ":" in part:
                nm, atype = part.split(":", 1)
                nm, atype = nm.strip(), atype.strip()
            else:
                nm, atype = part, None
            # external name form:  def f(to file : String)
            nm = nm.split()[-1] if nm.split() else nm
            arg_ids.append(self._add_arg(nm, atype, default))
        return arg_ids
