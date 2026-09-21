# Ceylon (.ceylon) analyzer.
#
# Real parser for Ceylon (JVM/JS language, C-family braces, annotations by name):
#   import ceylon.collection { HashMap, ArrayList }  -> import (each symbol)
#   import java.lang { ... }                          -> import
#   shared class Foo(Integer x) extends Bar() satisfies Baz { }  -> class
#   shared interface I satisfies J { }                 -> interface (class row)
#   shared object singleton { }                         -> object (class row)
#   shared void name(Integer a, String b="x") { }       -> method / function
#   shared Integer f() => a + b;                          -> function (expression)
#   shared variable Integer count = 0;                    -> field / variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ANN = (r"(?:shared|actual|formal|default|variable|abstract|final|sealed|"
        r"late|native|annotation|serializable|\w+\([^)]*\)|\"\"\"[^\"]*\"\"\")\s+")


class CeylonAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ceylon"
    EXTENSIONS = (".ceylon",)

    _IMPORT = re.compile(r"import\s+([\w.]+)\s*\{([^}]*)\}")
    _TYPE = re.compile(
        r"(?:" + _ANN + r")*"
        r"\b(class|interface|object)\s+([A-Za-z_]\w*)"
        r"(?:\s*\([^)]*\))?"                              # class param list
        r"(?:\s*<[^{]*?>)?"
        r"(?:\s+extends\s+([\w.]+)(?:\s*\([^)]*\))?)?"   # extends Base(args)
        r"(?:\s+satisfies\s+([\w.&| ]+?))?"
        r"\s*\{")
    _METHOD = re.compile(
        r"(?:" + _ANN + r")*"
        r"\b(?:void|[\w.<>?\[\]&|]+)\s+([A-Za-z_]\w*)\s*"
        r"(?:<[^>]*>)?\s*"
        r"\(([^{;=]*?)\)\s*"
        r"(?:\{|=>)")
    _FIELD = re.compile(
        r"(?:" + _ANN + r")*"
        r"\b(?:variable\s+)?([\w.<>?\[\]&|]+)\s+([A-Za-z_]\w*)\s*"
        r"(?:=\s*([^;]+?))?\s*;")

    def _register_types(self, file_id, text, path):
        for m in self._TYPE.finditer(self._strip_comments(text)):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._IMPORT.finditer(text):
            pkg = m.group(1)
            for sym in m.group(2).split(","):
                sym = sym.strip().split("=")[-1].strip().strip("...").strip()
                sym = sym.split()[-1] if sym.split() else sym
                if sym and sym != "...":
                    self._add_import(file_id, sym, f"{pkg}.{sym}")

        types = []
        for m in self._TYPE.finditer(text):
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            parents = []
            for grp in (m.group(3), m.group(4)):
                if grp:
                    for p in re.split(r"[&|,]", grp):
                        p = p.split("(")[0].split(".")[-1].strip()
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
        method_spans = []
        for m in self._METHOD.finditer(text):
            if m.start() < covered:
                continue
            name, params = m.group(1), m.group(2)
            if name in ("if", "for", "while", "switch", "return", "assert",
                        "value", "class", "interface", "object"):
                continue
            end_char = text[m.end() - 1]
            if end_char == "{":
                body = text.index("{", m.end() - 1)
                covered = self._find_matching(text, body)
                method_spans.append((body, covered))
            arg_ids = self._params(params)
            owner = enclosing(m.start())
            cid = self._class_registry.get(owner["name"]) if owner else None
            fid = self._add_function(file_id, name, arg_ids, [], class_id=cid)
            if owner is not None:
                owner["methods"].append(fid)

        def in_method(pos):
            return any(a <= pos < b for a, b in method_spans)

        for m in self._FIELD.finditer(text):
            if in_method(m.start()):
                continue
            vtype, name, val = m.group(1), m.group(2), m.group(3)
            if vtype in ("return", "import", "assert"):
                continue
            owner = enclosing(m.start())
            if owner is None:
                self._add_variable(file_id, name, val.strip() if val else None)
            else:
                owner["attrs"].append(self._add_arg(name, vtype,
                                                    val.strip() if val else None))

        for t in types:
            self._add_class(file_id, t["name"], description=f"ceylon {t['kind']}",
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
            toks = part.split()
            if len(toks) >= 2:
                atype, nm = " ".join(toks[:-1]), toks[-1]
            else:
                atype, nm = None, toks[-1] if toks else part
            arg_ids.append(self._add_arg(nm, atype, default))
        return arg_ids
