# Pascal / Object Pascal / Delphi (.pas / .dpr / .dpk) analyzer.
#
# Real parser for Object Pascal (case-insensitive; '//', '{ }' and '(* *)'
# comments):
#   unit Geometry;                                      -> unit (skipped as entity)
#   uses SysUtils, Classes;                             -> import (each unit)
#   type
#     TPoint = class(TObject)                            -> class (+ parent)
#       private FX: Integer;                             -> attribute
#       public  procedure Move(dx: Integer);            -> method
#               function  Area: Integer;                -> method
#               property X: Integer read FX write FX;    -> attribute
#     end;
#     TColor = (Red, Green, Blue);                        -> enum (class row)
#     TRec   = record a: Integer; end;                    -> record (class row)
#   var GlobalCount: Integer;                              -> variable
#   procedure TPoint.Move(dx: Integer); begin ... end;     -> method impl (TPoint)
#   function  StandAlone(x: Integer): Integer;             -> free function
import re

from .regex_base import RegexCodeAnalyzer


class PascalAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "pascal"
    EXTENSIONS = (".pas", ".dpr", ".dpk")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("{", "}"), ("(*", "*)"))
    STRING_DELIMS = ("'",)

    _USES = re.compile(r"\buses\b([^;]+);", re.IGNORECASE | re.DOTALL)
    _CLASS = re.compile(
        r"\b([A-Za-z_]\w*)\s*=\s*(class|object|interface)\b"
        r"(?:\s*\(\s*([\w., ]+?)\s*\))?",
        re.IGNORECASE,
    )
    _RECORD = re.compile(
        r"\b([A-Za-z_]\w*)\s*=\s*(?:packed\s+)?record\b", re.IGNORECASE
    )
    _ENUM = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*\(([^)]*)\)\s*;", re.IGNORECASE)
    _METHOD = re.compile(
        r"^\s*(?:class\s+)?(procedure|function|constructor|destructor)\s+"
        r"(?:([A-Za-z_]\w*)\s*\.\s*)?"  # optional receiver
        r"([A-Za-z_]\w*)\s*"
        r"(?:\(([^)]*)\))?"
        r"(?:\s*:\s*([\w.]+))?",
        re.IGNORECASE,
    )
    _PROPERTY = re.compile(
        r"^\s*property\s+([A-Za-z_]\w*)\s*(?::\s*([\w.]+))?", re.IGNORECASE
    )
    _FIELD = re.compile(
        r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:\s*([\w.\[\]<> ]+?)\s*;",
        re.IGNORECASE,
    )
    _VAR = re.compile(
        r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:\s*([\w.\[\]<> ]+?)\s*"
        r"(?:=\s*[^;]+)?;",
        re.IGNORECASE,
    )
    _VISIBILITY = re.compile(
        r"^\s*(private|public|protected|published|strict\s+private|"
        r"strict\s+protected)\b",
        re.IGNORECASE,
    )

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for rx in (self._CLASS, self._RECORD, self._ENUM):
            for m in rx.finditer(text):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        # imports (uses clauses, may span lines / appear twice)
        seen = set()
        for m in self._USES.finditer(text):
            for u in m.group(1).split(","):
                u = u.strip().split(" in ")[0].strip()
                if u and u not in seen:
                    seen.add(u)
                    self._add_import(file_id, u, u)

        lines = text.splitlines()
        n = len(lines)

        # enums (single line)
        enums = {}
        for m in self._ENUM.finditer(text):
            name = m.group(1)
            attrs = []
            for v in m.group(2).split(","):
                v = v.strip().split("=")[0].strip()
                if re.match(r"^[A-Za-z_]\w*$", v):
                    attrs.append(self._add_arg(v, "enumvalue"))
            enums[name] = attrs

        # class / record type declarations with bodies ending at matching 'end'.
        types = {}  # name -> dict
        type_spans = []  # (start_line, end_line, type_name) inclusive-exclusive
        seen_fn = set()  # (owner_or_None, name) to emit each routine once
        i = 0
        while i < n:
            line = lines[i]
            cm = self._CLASS.search(line)
            rm = self._RECORD.search(line)
            decl = cm or rm
            if decl:
                name = decl.group(1)
                if name in enums:
                    i += 1
                    continue
                parents = []
                if cm and cm.group(3):
                    for p in cm.group(3).split(","):
                        p = p.strip()
                        if p in self._class_registry:
                            parents.append(self._class_registry[p])
                kind = cm.group(2).lower() if cm else "record"
                # forward decl (class;) on same line -> no body
                tail = line[decl.end() :]
                if re.match(r"\s*;", tail) and kind in ("class", "object", "interface"):
                    types.setdefault(
                        name,
                        {"kind": kind, "parents": parents, "methods": [], "attrs": []},
                    )
                    i += 1
                    continue
                methods, attrs = [], []
                depth_end = 1
                j = i + 1
                # scan body until the matching 'end'
                while j < n and depth_end > 0:
                    bl = lines[j]
                    if re.search(r"\brecord\b", bl, re.IGNORECASE) and not re.search(
                        r"=\s*(?:packed\s+)?record", bl, re.IGNORECASE
                    ):
                        depth_end += len(re.findall(r"\brecord\b", bl, re.IGNORECASE))
                    if re.match(r"^\s*end\b", bl, re.IGNORECASE):
                        depth_end -= 1
                        if depth_end == 0:
                            break
                    mm = self._METHOD.match(bl)
                    if mm:
                        key = (name, mm.group(3))
                        if key not in seen_fn:
                            seen_fn.add(key)
                            methods.append(self._make_method(file_id, mm, name))
                        j += 1
                        continue
                    pm = self._PROPERTY.match(bl)
                    if pm:
                        attrs.append(self._add_arg(pm.group(1), pm.group(2)))
                        j += 1
                        continue
                    if not self._VISIBILITY.match(bl):
                        fm = self._FIELD.match(bl)
                        if fm and fm.group(1).lower() not in (
                            "procedure",
                            "function",
                            "property",
                            "type",
                            "const",
                        ):
                            for fn in fm.group(1).split(","):
                                fn = fn.strip()
                                if fn:
                                    attrs.append(self._add_arg(fn, fm.group(2).strip()))
                    j += 1
                if name in types:
                    types[name]["methods"].extend(methods)
                    types[name]["attrs"].extend(attrs)
                    types[name]["parents"] = types[name]["parents"] or parents
                else:
                    types[name] = {
                        "kind": kind,
                        "parents": parents,
                        "methods": methods,
                        "attrs": attrs,
                    }
                type_spans.append((i, j + 1, name))
                i = j + 1
                continue
            i += 1

        def inside_type_body(lineno):
            return any(a <= lineno < b for a, b, _ in type_spans)

        # implementation-section routines + free functions (each emitted once).
        for idx, line in enumerate(lines):
            if inside_type_body(idx):
                continue
            mm = self._METHOD.match(line)
            if not mm:
                continue
            recv, name = mm.group(2), mm.group(3)
            if recv:
                key = (recv, name)
                if key in seen_fn:
                    continue
                seen_fn.add(key)
                fid = self._make_method(file_id, mm, recv)
                if recv in types:
                    types[recv]["methods"].append(fid)
                elif recv in self._class_registry:
                    types.setdefault(
                        recv,
                        {"kind": "class", "parents": [], "methods": [], "attrs": []},
                    )["methods"].append(fid)
            else:
                key = (None, name)
                if key in seen_fn:
                    continue
                seen_fn.add(key)
                arg_ids = self._params(mm.group(4) or "")
                out_ids = [self._add_output(mm.group(5))] if mm.group(5) else []
                self._add_function(file_id, name, arg_ids, out_ids)

        # unit-level var section variables
        in_var = False
        for line in lines:
            if re.match(r"^\s*var\b", line, re.IGNORECASE):
                in_var = True
                continue
            if re.match(
                r"^\s*(begin|const|type|implementation|procedure|function|"
                r"initialization|end)\b",
                line,
                re.IGNORECASE,
            ):
                in_var = False
            if in_var:
                vm = self._VAR.match(line)
                if vm:
                    for vn in vm.group(1).split(","):
                        vn = vn.strip()
                        if vn:
                            self._add_variable(file_id, vn, None)

        for name, t in enums.items():
            self._add_class(file_id, name, description="pascal enum", attr_ids=t)
        for name, t in types.items():
            self._add_class(
                file_id,
                name,
                description=f"pascal {t['kind']}",
                parent_ids=t["parents"],
                method_ids=t["methods"],
                attr_ids=t["attrs"],
            )

    def _make_method(self, file_id, mm, owner_name):
        name = mm.group(3)
        arg_ids = self._params(mm.group(4) or "")
        out_ids = [self._add_output(mm.group(5))] if mm.group(5) else []
        cid = self._class_registry.get(owner_name)
        return self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)

    def _params(self, params):
        arg_ids = []
        for part in params.split(";"):
            part = part.strip()
            if not part:
                continue
            part = re.sub(r"(?i)^\s*(var|const|out)\s+", "", part)
            if ":" in part:
                names, atype = part.split(":", 1)
                atype = atype.split("=")[0].strip()
            else:
                names, atype = part, None
            for nm in names.split(","):
                nm = nm.strip()
                if nm:
                    arg_ids.append(self._add_arg(nm, atype))
        return arg_ids
