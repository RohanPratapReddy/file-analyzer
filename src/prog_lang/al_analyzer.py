# AL (.al) analyzer -- Microsoft Dynamics 365 Business Central.
#
# Real parser for AL (Pascal-flavoured begin/end bodies inside C-style braces):
#   codeunit 50100 "My Codeunit" { ... }        -> object (class row)
#   table 50100 Customer { fields { field(1; Name; Text[50]) {} } }
#   page / report / query / xmlport / enum / interface / controladdin
#   procedure Foo(Param: Integer; var Ref: Text): Boolean begin ... end;
#   trigger OnRun() begin ... end;               -> method
#   field(1; "No."; Code[20]) { ... }            -> attribute
#   var  X: Integer;                             -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_OBJECTS = ("table", "tableextension", "page", "pageextension", "codeunit",
            "report", "reportextension", "query", "xmlport", "enum",
            "enumextension", "interface", "controladdin", "profile",
            "permissionset", "entitlement", "dotnet")


class ALAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "al"
    EXTENSIONS = (".al",)

    _USING = re.compile(r"^\s*using\s+([\w.]+)\s*;", re.MULTILINE)
    _OBJECT = re.compile(
        r"^\s*(" + "|".join(_OBJECTS) + r")\s+"
        r"(?:(\d+)\s+)?"                                  # optional object id
        r'(?:"([^"]+)"|([A-Za-z_]\w*))'                   # name (quoted or bare)
        r'(?:\s+extends\s+(?:"([^"]+)"|([A-Za-z_]\w*)))?', re.IGNORECASE | re.MULTILINE)
    _METHOD = re.compile(
        r"(?:(?:local|internal|protected)\s+)*"
        r"\b(procedure|trigger)\s+"
        r'(?:"([^"]+)"|([A-Za-z_]\w*))\s*'
        r"\(([^)]*)\)"
        r"(?:\s*:\s*([\w\[\]. ]+?))?\s*", re.IGNORECASE)
    _FIELD = re.compile(
        r'\bfield\s*\(\s*\d+\s*;\s*(?:"([^"]+)"|([A-Za-z_]\w*))\s*;\s*'
        r"([^)]+?)\s*\)", re.IGNORECASE)
    _ENUMVAL = re.compile(
        r'\bvalue\s*\(\s*\d+\s*;\s*(?:"([^"]+)"|([A-Za-z_]\w*))\s*\)',
        re.IGNORECASE)
    _VAR = re.compile(
        r'^\s*(?:"([^"]+)"|([A-Za-z_]\w*))\s*:\s*'
        r"(Record|Codeunit|Page|Report|Integer|Decimal|Text|Code|Boolean|"
        r"Option|Date|Time|DateTime|Guid|BigInteger|Char|Byte|Duration|"
        r"List|Dictionary|JsonObject|JsonArray|JsonToken|Blob|RecordRef|"
        r"FieldRef|Variant|Label|Enum)[^\n;]*;", re.IGNORECASE | re.MULTILINE)

    def _register_types(self, file_id, text, path):
        for m in self._OBJECT.finditer(self._strip_comments(text)):
            self._register_class(m.group(3) or m.group(4))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._USING.finditer(text):
            ns = m.group(1)
            self._add_import(file_id, ns.split(".")[-1], ns)

        objects = []
        for m in self._OBJECT.finditer(text):
            name = m.group(3) or m.group(4)
            bstart = text.find("{", m.end())
            if bstart == -1:
                continue
            bend = self._find_matching(text, bstart)
            parents = []
            pname = m.group(5) or m.group(6)
            if pname and pname in self._class_registry:
                parents.append(self._class_registry[pname])
            objects.append({"name": name, "kind": m.group(1).lower(),
                            "bstart": bstart, "bend": bend, "parents": parents,
                            "methods": [], "attrs": []})

        def enclosing(pos):
            best = None
            for o in objects:
                if o["bstart"] <= pos < o["bend"] and (best is None or o["bstart"] > best["bstart"]):
                    best = o
            return best

        # field(...) declarations -> attributes of the enclosing object.
        method_spans = []
        for m in self._METHOD.finditer(text):
            kind, name = m.group(1), (m.group(2) or m.group(3))
            arg_ids = self._params(m.group(4))
            out_ids = [self._add_output(m.group(5).strip())] if m.group(5) else []
            body = text.find("begin", m.end())
            owner = enclosing(m.start())
            cid = self._class_registry.get(owner["name"]) if owner else None
            fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
            if owner is not None:
                owner["methods"].append(fid)

        for m in self._FIELD.finditer(text):
            name = m.group(1) or m.group(2)
            ftype = m.group(3).strip()
            owner = enclosing(m.start())
            aid = self._add_arg(name, ftype)
            if owner is not None:
                owner["attrs"].append(aid)

        for m in self._ENUMVAL.finditer(text):
            name = m.group(1) or m.group(2)
            owner = enclosing(m.start())
            aid = self._add_arg(name, "enumvalue")
            if owner is not None:
                owner["attrs"].append(aid)

        for m in self._VAR.finditer(text):
            name = m.group(1) or m.group(2)
            if name.lower() in ("procedure", "trigger", "var", "begin", "end"):
                continue
            self._add_variable(file_id, name, None)

        for o in objects:
            self._add_class(file_id, o["name"], description=f"al {o['kind']}",
                            parent_ids=o["parents"], method_ids=o["methods"],
                            attr_ids=o["attrs"])

    def _params(self, params):
        arg_ids = []
        for part in params.split(";"):
            part = part.strip()
            if not part:
                continue
            part = re.sub(r"(?i)^\s*var\s+", "", part)
            if ":" in part:
                nm, atype = part.split(":", 1)
                nm = nm.strip().strip('"')
                atype = atype.strip()
            else:
                nm, atype = part.strip('"'), None
            if nm:
                arg_ids.append(self._add_arg(nm, atype))
        return arg_ids
