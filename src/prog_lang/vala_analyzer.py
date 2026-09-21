# Vala (.vala) / Vala API bindings (.vapi) analyzer.
#
# Real parser for the Vala language (GObject-oriented, C#/Java-like syntax):
#   using GLib;                                   -> import
#   namespace Foo { ... }                         -> nested scope
#   public class Foo : Bar, IBaz { ... }          -> class (+ parents)
#   public interface IFoo : GLib.Object { ... }   -> interface (class row)
#   public struct Color { ... }                   -> struct  (class row)
#   enum Season { SPRING, SUMMER }                -> enum    (class row)
#   errordomain IOError { FAILED }                -> error domain (class row)
#   public void foo (int a, string b = "x") {}    -> method / function
#   public int prop { get; set; }                 -> property (attribute)
#   private int count = 0;                         -> field / module variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_MODIFIERS = (r"(?:public|private|protected|internal|static|abstract|virtual|"
              r"override|sealed|extern|inline|async|weak|owned|unowned|const|"
              r"new|partial)\s+")


class ValaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "vala"
    EXTENSIONS = (".vala", ".vapi")

    _USING = re.compile(r"\busing\s+([\w.]+)\s*;")
    _TYPE = re.compile(
        r"(?:" + _MODIFIERS + r")*"
        r"\b(class|interface|struct|enum|errordomain|namespace)\s+"
        r"([\w.]+)"
        r"(?:\s*<[^{;]*?>)?"                       # generic params
        r"(?:\s*:\s*([^{]+?))?"                    # base list
        r"\s*\{")
    _METHOD = re.compile(
        r"(?:" + _MODIFIERS + r")*"
        r"(?:(?:async|signal)\s+)?"
        r"([\w.]+(?:\s*\*)?(?:\s*\?)?(?:\s*\[\s*\])?)\s+"   # return type
        r"([A-Za-z_]\w*)\s*"                                 # name
        r"\(([^;{]*?)\)\s*"                                  # params
        r"(?:throws\s+[\w.,\s]+?)?\s*\{")
    _PROP = re.compile(
        r"(?:" + _MODIFIERS + r")*"
        r"([\w.]+(?:\?)?)\s+([A-Za-z_]\w*)\s*\{\s*(?:get|set|owned|default)")
    _FIELD = re.compile(
        r"(?:" + _MODIFIERS + r")*"
        r"([\w.]+(?:\?)?(?:\s*\[\s*\])?)\s+([A-Za-z_]\w*)\s*(?:=\s*([^;]+?))?\s*;")

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._TYPE.finditer(text):
            self._register_class(m.group(2).split(".")[-1])

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._USING.finditer(text):
            src = m.group(1)
            self._add_import(file_id, src.split(".")[-1], src)

        types = []
        for m in self._TYPE.finditer(text):
            kind, raw_name = m.group(1), m.group(2).split(".")[-1]
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            parents = []
            if m.group(3):
                for base in self._split_top_level(m.group(3)):
                    base = base.split(".")[-1].split("<")[0].strip()
                    if base in self._class_registry:
                        parents.append(self._class_registry[base])
            types.append({"name": raw_name, "kind": kind, "bstart": bstart,
                          "bend": bend, "parents": parents,
                          "methods": [], "attrs": []})

        def enclosing(pos):
            best = None
            for t in types:
                if t["bstart"] <= pos < t["bend"]:
                    if best is None or t["bstart"] > best["bstart"]:
                        best = t
            return best

        covered = 0
        method_spans = []
        for m in self._METHOD.finditer(text):
            if m.start() < covered:
                continue
            ret, name, params = m.group(1).strip(), m.group(2), m.group(3)
            if name in ("if", "for", "while", "switch", "foreach", "catch", "return"):
                continue
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

        for m in self._PROP.finditer(text):
            if in_method(m.start()):
                continue
            owner = enclosing(m.start())
            aid = self._add_arg(m.group(2), m.group(1).strip(), None)
            if owner is not None:
                owner["attrs"].append(aid)

        for m in self._FIELD.finditer(text):
            if in_method(m.start()):
                continue
            owner = enclosing(m.start())
            vtype, name, val = m.group(1).strip(), m.group(2), m.group(3)
            if vtype in ("return", "case", "else"):
                continue
            if owner is None:
                self._add_variable(file_id, name, val.strip() if val else None,
                                   scope="module")
            else:
                owner["attrs"].append(self._add_arg(name, vtype, val.strip() if val else None))

        for t in types:
            desc = f"vala {t['kind']}"
            self._add_class(file_id, t["name"], description=desc,
                            parent_ids=t["parents"], method_ids=t["methods"],
                            attr_ids=t["attrs"])

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = re.sub(r"\b(?:out|ref|owned|unowned|params)\b", "", part).strip()
            if not part:
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            toks = part.split()
            if len(toks) >= 2:
                atype, aname = " ".join(toks[:-1]), toks[-1]
            else:
                atype, aname = None, toks[-1] if toks else part
            arg_ids.append(self._add_arg(aname, atype, default))
        return arg_ids
