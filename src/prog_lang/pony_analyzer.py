# Pony (.pony) analyzer.
#
# Real parser for Pony (actor-model, capabilities-secure). Type bodies are NOT
# brace-delimited: a type's members run from its header to the next top-level
# type declaration (or EOF).
#   use "collections"                     -> import
#   use rt = "path"                        -> aliased import
#   actor Main / class Foo / struct S      -> class row
#   primitive P / interface I / trait T    -> class row
#   type Alias is (A | B)                  -> class row
#   class Foo is Stringable                -> parents via `is`
#   new create(env: Env) =>                -> constructor (method)
#   fun ref bar(a: U32): U32 =>            -> method / function
#   be receive(msg: Msg) =>               -> behaviour (method)
#   let x: U32 = 0  /  var y: String       -> field (attribute)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_CAP = r"(?:ref|box|val|iso|trn|tag)"


class PonyAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "pony"
    EXTENSIONS = (".pony",)

    _USE = re.compile(r'^\s*use\s+(?:([A-Za-z_]\w*)\s*=\s*)?"([^"]+)"', re.MULTILINE)
    _TYPE = re.compile(
        r"(?m)^(actor|class|primitive|interface|trait|struct|type)\s+"
        r"(?:@\s*)?(?:" + _CAP + r"\s+)?"
        r"([A-Za-z_]\w*)")
    _METHOD = re.compile(
        r"(?m)^\s+(fun|be|new)\b\s*(?:" + _CAP + r"\s+)?"
        r"(?:@\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*"
        r"\(([^)]*)\)\s*(?::\s*([^=>?]+?))?\s*\??\s*=>",
        re.DOTALL)
    _FIELD = re.compile(
        r"(?m)^\s+(let|var|embed)\s+([A-Za-z_]\w*)\s*:\s*([^\n=]+?)"
        r"(?:\s*=\s*([^\n]+))?$")

    def _register_types(self, file_id, text, path):
        for m in self._TYPE.finditer(self._strip_comments(text)):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._USE.finditer(text):
            alias, src = m.group(1), m.group(2)
            self._add_import(file_id, alias or src.split("/")[-1], src, alias)

        heads = list(self._TYPE.finditer(text))
        types = []
        for i, m in enumerate(heads):
            start = m.start()
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            header_line = text[m.start():text.find("\n", m.start()) if "\n" in text[m.start():] else len(text)]
            parents = []
            im = re.search(r"\bis\b\s+(.+)$", header_line)
            if im:
                for p in re.split(r"[&|(),]", im.group(1)):
                    p = p.split("[")[0].strip()
                    if p in self._class_registry:
                        parents.append(self._class_registry[p])
            types.append({"name": m.group(2), "kind": m.group(1), "start": start,
                          "end": end, "parents": parents,
                          "methods": [], "attrs": []})

        def enclosing(pos):
            for t in types:
                if t["start"] <= pos < t["end"]:
                    return t
            return None

        for m in self._METHOD.finditer(text):
            name = m.group(2)
            arg_ids = self._params(m.group(3))
            ret = m.group(4).strip() if m.group(4) else None
            out_ids = [self._add_output(ret)] if ret and ret not in ("None", "") else []
            owner = enclosing(m.start())
            cid = self._class_registry.get(owner["name"]) if owner else None
            fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
            if owner is not None:
                owner["methods"].append(fid)

        for m in self._FIELD.finditer(text):
            owner = enclosing(m.start())
            name, ftype, val = m.group(2), m.group(3).strip(), m.group(4)
            aid = self._add_arg(name, ftype, val.strip() if val else None)
            if owner is not None:
                owner["attrs"].append(aid)
            else:
                self._add_variable(file_id, name, val.strip() if val else None)

        for t in types:
            self._add_class(file_id, t["name"], description=f"pony {t['kind']}",
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
