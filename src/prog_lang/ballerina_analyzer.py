# Ballerina (.bal / .ballerina) analyzer.
#
# Real parser for Ballerina (cloud-native, C-family braces):
#   import ballerina/http;  import foo/bar as b;    -> import
#   public function name(int a, string b = "x") returns int { }   -> function
#   service /path on new http:Listener(9090) { resource function get x() {} }
#   type Person record { string name; int age; };   -> record (class row)
#   public type Shape object { ... };                -> object type (class row)
#   class Counter { int c = 0; function inc() {} }   -> class
#   enum Color { RED, GREEN, BLUE }                  -> enum (class row)
#   int x = 5;  final string NAME = "a";             -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_VIS = r"(?:public|private|isolated|transactional|distinct|readonly|client|service)\s+"


class BallerinaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ballerina"
    EXTENSIONS = (".bal", ".ballerina")

    _IMPORT = re.compile(
        r"^\s*import\s+([\w./]+)(?:\s+as\s+(\w+))?\s*;", re.MULTILINE)
    _TYPE = re.compile(
        r"(?:" + _VIS + r")*"
        r"\btype\s+([A-Za-z_]\w*)\s+"
        r"(record|object|table|abstract\s+object)\s*\{")
    _ENUM = re.compile(r"(?:" + _VIS + r")*\benum\s+([A-Za-z_]\w*)\s*\{([^}]*)\}")
    _CLASS = re.compile(
        r"(?:" + _VIS + r")*"
        r"\bclass\s+([A-Za-z_]\w*)\s*\{")
    _SERVICE = re.compile(r"\bservice\s+(?:([\w./]+)\s+)?on\b")
    _METHOD = re.compile(
        r"(?:" + _VIS + r")*"
        r"(?:resource\s+|remote\s+)?function\s+"
        r"(?:(get|post|put|delete|patch|head|options)\s+)?"
        r"([A-Za-z_][\w./\\]*)\s*"
        r"\(([^{;]*?)\)\s*"
        r"(?:returns\s+([\w:?|<>\[\], ]+?)\s*)?\{")
    _FIELD = re.compile(
        r"([\w:<>?\[\], ]+?)\s+([A-Za-z_]\w*)\s*(?:=\s*([^;]+?))?\s*;")

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._TYPE.finditer(t):
            self._register_class(m.group(1))
        for m in self._CLASS.finditer(t):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._IMPORT.finditer(text):
            src, alias = m.group(1), m.group(2)
            name = alias or src.split("/")[-1].split(".")[-1]
            self._add_import(file_id, name, src, alias)

        types = []
        for m in self._TYPE.finditer(text):
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            types.append({"name": m.group(1), "kind": m.group(2).split()[-1],
                          "bstart": bstart, "bend": bend, "isrec": True,
                          "methods": [], "attrs": []})
        for m in self._CLASS.finditer(text):
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            types.append({"name": m.group(1), "kind": "class", "bstart": bstart,
                          "bend": bend, "isrec": False, "methods": [], "attrs": []})

        for m in self._ENUM.finditer(text):
            attr_ids = [self._add_arg(v.split("=")[0].strip(), "enum")
                        for v in m.group(2).split(",") if v.strip()]
            self._add_class(file_id, m.group(1), description="ballerina enum",
                            attr_ids=attr_ids)

        def enclosing(pos):
            best = None
            for t in types:
                if t["bstart"] <= pos < t["bend"] and (best is None or t["bstart"] > best["bstart"]):
                    best = t
            return best

        covered = 0
        method_spans = []
        for m in self._METHOD.finditer(text):
            if m.start() < covered:
                continue
            verb, name, params, ret = m.group(1), m.group(2), m.group(3), m.group(4)
            body = text.index("{", m.end() - 1)
            covered = self._find_matching(text, body)
            method_spans.append((body, covered))
            arg_ids = self._params(params)
            out_ids = [self._add_output(ret.strip())] if ret and ret.strip() not in ("()", "") else []
            owner = enclosing(m.start())
            cid = self._class_registry.get(owner["name"]) if owner else None
            fname = f"{verb} {name}" if verb else name
            fid = self._add_function(file_id, fname, arg_ids, out_ids, class_id=cid)
            if owner is not None:
                owner["methods"].append(fid)

        def in_method(pos):
            return any(a <= pos < b for a, b in method_spans)

        for m in self._FIELD.finditer(text):
            if in_method(m.start()):
                continue
            vtype, name, val = m.group(1).strip(), m.group(2), m.group(3)
            if vtype.split()[0] in ("import", "function", "type", "class", "enum",
                                    "service", "return", "returns", "public",
                                    "private", "const", "final", "isolated"):
                # keep const/final/public as valid var modifiers only if a real type follows
                if vtype.split()[-1] in ("import", "function", "type", "class",
                                         "enum", "service", "return", "returns"):
                    continue
            owner = enclosing(m.start())
            if owner is None:
                self._add_variable(file_id, name, val.strip() if val else None)
            else:
                owner["attrs"].append(self._add_arg(name, vtype,
                                                    val.strip() if val else None))

        for t in types:
            self._add_class(file_id, t["name"], description=f"ballerina {t['kind']}",
                            method_ids=t["methods"], attr_ids=t["attrs"])

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip().lstrip("*")
            if not part:
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            toks = part.split()
            if len(toks) >= 2:
                atype, nm = " ".join(toks[:-1]), toks[-1]
            else:
                atype, nm = None, toks[-1] if toks else part
            arg_ids.append(self._add_arg(nm, atype, default))
        return arg_ids
