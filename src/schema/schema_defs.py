# Additional schema-definition-language engines for SchemaAnalyzer.
#
# Each engine is a REAL, syntax-aware parser for one residual schema format and
# emits the same normalized rows as the SQL/IDL core via the analyzer's shared
# ``_emit_table`` / ``_emit_column`` / ``_emit_type`` / ``_emit_method`` helpers:
#
#   structure / message / shape / record / container -> schema_tables_table
#   field / member / leaf / property                 -> schema_columns_table
#   enum / typedef / scalar / grammar rule           -> schema_types_table
#   operation / rpc / path / service                 -> schema_methods_table
#
# Formats handled here (mixed into SchemaAnalyzer):
#   WebIDL / CORBA-COM IDL (.webidl .idl)  Smithy IDL (.smithy)
#   CDDL (.cddl)   DBML (.dbml)   YANG (.yang)   SNMP MIB / ASN.1 (.mib)
#   ROS message (.msg)  ROS service (.srv)  SHACL Turtle (.shacl)
#   EBNF grammar (.ebnf)  JSON-Schema doc (.jsonschema)
#   OpenAPI / Swagger (.openapi .swagger)  RAML (.raml)
#   Kubernetes CRD (.crd)  Kaitai Struct (.ksy)  Xcode String Catalog (.xcstrings)
import json
import re

try:  # PyYAML is preferred; a compact block-YAML fallback keeps us dependency-safe
    import yaml as _yaml
except Exception:  # pragma: no cover - exercised only where PyYAML is absent
    _yaml = None


def load_yaml_docs(text):
    """Return the list of YAML documents in *text* (JSON is a YAML subset).

    Uses PyYAML when available, otherwise a small block-style loader that covers
    the mapping/sequence/scalar structure these schema files actually use."""
    if _yaml is not None:
        try:
            return [d for d in _yaml.safe_load_all(text) if d is not None]
        except Exception:
            pass
    # JSON is valid YAML; try it before the block fallback.
    try:
        return [json.loads(text)]
    except Exception:
        pass
    docs, cur = [], []
    for line in text.splitlines():
        if line.strip() == "---":
            if cur:
                docs.append(_mini_yaml("\n".join(cur)))
                cur = []
        else:
            cur.append(line)
    if cur:
        docs.append(_mini_yaml("\n".join(cur)))
    return [d for d in docs if d is not None]


def _scalar(v):
    v = v.strip()
    if not v:
        return None
    if (v[0] == v[-1]) and v[0] in "\"'" and len(v) >= 2:
        return v[1:-1]
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if re.fullmatch(r"-?\d*\.\d+", v):
        return float(v)
    return v


def _mini_yaml(text):
    """Minimal block-YAML -> python (mappings, sequences, scalars, comments).

    A pragmatic fallback only; not a full YAML implementation."""
    lines = []
    for raw in text.splitlines():
        # strip full-line and trailing comments (naive but adequate here)
        if raw.strip().startswith("#"):
            continue
        lines.append(raw.rstrip())
    lines = [ln for ln in lines if ln.strip() != ""]
    pos = [0]

    def indent(s):
        return len(s) - len(s.lstrip(" "))

    def parse_block(min_indent):
        # decide mapping vs sequence by first line at this level
        if pos[0] >= len(lines):
            return None
        first = lines[pos[0]]
        cur_indent = indent(first)
        if cur_indent < min_indent:
            return None
        is_seq = first.lstrip().startswith("- ") or first.lstrip() == "-"
        container = [] if is_seq else {}
        while pos[0] < len(lines):
            ln = lines[pos[0]]
            ind = indent(ln)
            if ind < cur_indent:
                break
            if ind > cur_indent:  # shouldn't happen at this level
                pos[0] += 1
                continue
            body = ln.lstrip()
            if is_seq:
                if not (body.startswith("- ") or body == "-"):
                    break
                item = body[1:].lstrip()
                pos[0] += 1
                if item == "":
                    container.append(parse_block(cur_indent + 1))
                elif ":" in item and not item.startswith("{"):
                    # inline mapping start on the dash line
                    key, _, val = item.partition(":")
                    val = val.strip()
                    d = {}
                    if val:
                        d[key.strip()] = _flow_or_scalar(val)
                    else:
                        d[key.strip()] = parse_block(ind + 3)
                    # continuation lines of this mapping item
                    while (
                        pos[0] < len(lines)
                        and indent(lines[pos[0]]) > cur_indent
                        and not lines[pos[0]].lstrip().startswith("- ")
                    ):
                        k2, _, v2 = lines[pos[0]].lstrip().partition(":")
                        pos[0] += 1
                        v2 = v2.strip()
                        d[k2.strip()] = (
                            _flow_or_scalar(v2) if v2 else parse_block(ind + 3)
                        )
                    container.append(d)
                else:
                    container.append(_flow_or_scalar(item))
            else:
                if ":" not in body:
                    pos[0] += 1
                    continue
                key, _, val = body.partition(":")
                key = key.strip().strip("\"'")
                val = val.strip()
                pos[0] += 1
                if val:
                    container[key] = _flow_or_scalar(val)
                else:
                    child = parse_block(cur_indent + 1)
                    container[key] = child
        return container

    def _flow_or_scalar(v):
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            return [_scalar(x) for x in _split_commas(inner)] if inner else []
        if v.startswith("{") and v.endswith("}"):
            inner = v[1:-1].strip()
            d = {}
            for part in _split_commas(inner):
                if ":" in part:
                    k, _, vv = part.partition(":")
                    d[k.strip().strip("\"'")] = _scalar(vv)
            return d
        if v in ("|", ">", "|-", ">-", "|+", ">+"):
            return ""  # block scalar body is dropped in the fallback
        return _scalar(v)

    return parse_block(0)


def _split_commas(s):
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _local(uri):
    """Local name of a prefixed/absolute RDF or namespaced identifier."""
    uri = uri.strip().strip("<>")
    for sep in ("#", "/", ":"):
        if sep in uri:
            uri = uri.rsplit(sep, 1)[-1]
    return uri


class SchemaDefinitionEngines:
    """Mixin adding the residual schema-definition engines to SchemaAnalyzer.

    Relies on the host analyzer's ``_emit_table`` / ``_emit_column`` /
    ``_emit_type`` / ``_emit_method`` helpers and ``_strip_block_comments``."""

    # ---- shared comment stripping (// and /* */ and #) -------------------
    @staticmethod
    def _strip_slashes(text):
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"//[^\n]*", "", text)
        return text

    # =====================================================================
    # WebIDL / CORBA-COM IDL   (.webidl .idl)
    # =====================================================================
    _IDL_CONTAINER = re.compile(
        r"\b(interface|dictionary|struct|exception|valuetype|union)\s+"
        r"(\w+)\s*(?::\s*([\w:,\s]+?))?\s*\{",
        re.MULTILINE,
    )
    _IDL_ENUM = re.compile(r"\benum\s+(\w+)\s*\{([^}]*)\}")
    _IDL_TYPEDEF = re.compile(r"\btypedef\s+([\w:<>,\s\[\]]+?)\s+(\w+)\s*;")
    _IDL_MODULE = re.compile(r"\bmodule\s+(\w+)\s*\{")
    _IDL_ATTR = re.compile(
        r"(?:readonly\s+)?attribute\s+([\w:<>?,\s\[\]]+?)\s+(\w+)\s*;"
    )
    _IDL_CONST = re.compile(r"\bconst\s+([\w:]+)\s+(\w+)\s*=\s*([^;]+);")
    _IDL_METHOD = re.compile(
        r"(?:^|\n)\s*(?:static\s+)?([\w:<>?,\s\[\]]+?)\s+(\w+)\s*\(([^)]*)\)\s*;"
    )

    def _parse_idl_family(self, text, engine, file_id):
        t = self._strip_slashes(text)
        ns = None
        mm = self._IDL_MODULE.search(t)
        if mm:
            ns = mm.group(1)
        # enums and typedefs first (module-level types)
        for m in self._IDL_ENUM.finditer(t):
            vals = [v.strip().strip('"') for v in m.group(2).split(",") if v.strip()]
            self._emit_type(m.group(1), "enum", None, vals, None, file_id)
        for m in self._IDL_TYPEDEF.finditer(t):
            self._emit_type(
                m.group(2), "typedef", m.group(1).strip(), None, None, file_id
            )
        for m in self._IDL_CONTAINER.finditer(t):
            kind, name, bases = m.group(1), m.group(2), m.group(3)
            inner, _ = self._extract_braced(t, t.index("{", m.start()))
            if inner is None:
                inner = ""
            row = self._emit_table(name, engine, ns, kind, file_id)
            for am in self._IDL_ATTR.finditer(inner):
                self._emit_column(
                    row, am.group(2), am.group(1).strip(), file_id, keys="attribute"
                )
            for cm in self._IDL_CONST.finditer(inner):
                self._emit_column(
                    row,
                    cm.group(2),
                    cm.group(1),
                    file_id,
                    keys="const",
                    value=cm.group(3).strip(),
                )
            # plain struct fields  "Type name;"  (not attribute/const/method)
            for fm in re.finditer(r"(?:^|\n)\s*([\w:<>,\s\[\]]+?)\s+(\w+)\s*;", inner):
                seg = fm.group(0)
                if "attribute" in seg or "const" in seg:
                    continue
                if "(" in seg:
                    continue
                ty = fm.group(1).strip()
                if ty in ("readonly",):
                    continue
                self._emit_column(row, fm.group(2), ty, file_id)
            for mm2 in self._IDL_METHOD.finditer(inner):
                ret, mname, args = mm2.group(1).strip(), mm2.group(2), mm2.group(3)
                if ret in ("attribute", "const", "readonly"):
                    continue
                self._emit_method(
                    mname,
                    "operation",
                    ret,
                    engine,
                    args.strip() or None,
                    row["table_id"],
                    file_id,
                )

    # =====================================================================
    # Smithy IDL   (.smithy)
    # =====================================================================
    _SMITHY_NS = re.compile(r"^\s*namespace\s+([\w.]+)", re.MULTILINE)
    _SMITHY_SHAPE = re.compile(
        r"^\s*(structure|union|list|map|set|enum|intEnum|operation|service|"
        r"resource)\s+(\w+)\s*(?:with\s*\[[^\]]*\]\s*)?\{",
        re.MULTILINE,
    )
    _SMITHY_SIMPLE = re.compile(
        r"^\s*(string|integer|long|short|byte|float|double|boolean|blob|"
        r"timestamp|document|bigInteger|bigDecimal)\s+(\w+)\s*$",
        re.MULTILINE,
    )

    def _parse_smithy(self, text, engine, file_id):
        t = self._strip_slashes(text)
        t = re.sub(r"@\w+(?:\([^)]*\))?", "", t)  # drop traits
        ns_m = self._SMITHY_NS.search(t)
        ns = ns_m.group(1) if ns_m else None
        for m in self._SMITHY_SIMPLE.finditer(t):
            self._emit_type(m.group(2), "scalar", m.group(1), None, None, file_id)
        for m in self._SMITHY_SHAPE.finditer(t):
            kind, name = m.group(1), m.group(2)
            inner, _ = self._extract_braced(t, t.index("{", m.start()))
            inner = inner or ""
            if kind in ("enum", "intEnum"):
                vals = []
                for em in re.finditer(r"(\w+)\s*(?:=\s*([^,\n]+))?", inner):
                    if em.group(1):
                        vals.append(em.group(1))
                self._emit_type(name, "enum", None, vals, None, file_id)
                continue
            if kind in ("operation", "service", "resource"):
                # members like input:/output:/operations:[] -> record on method
                sig = ", ".join(
                    f"{k}={v.strip()}"
                    for k, v in re.findall(r"(\w+)\s*:\s*([^\n,]+)", inner)
                )
                self._emit_method(name, kind, None, engine, sig or None, None, file_id)
                continue
            row = self._emit_table(name, engine, ns, kind, file_id)
            for fm in re.finditer(r"(\w+)\s*:\s*([\w.$#]+)", inner):
                self._emit_column(row, fm.group(1), fm.group(2), file_id)

    # =====================================================================
    # CDDL   (.cddl)
    # =====================================================================
    def _parse_cddl(self, text, engine, file_id):
        t = re.sub(r";[^\n]*", "", text)  # ; line comments
        # rules: name = rhs   (rhs may span lines / braces)
        for m in re.finditer(r"^\s*([\w$@.-]+)\s*(?:=|/=|//=)\s*", t, re.MULTILINE):
            name = m.group(1)
            start = m.end()
            # capture up to the next rule head or EOF
            nxt = re.search(r"^\s*[\w$@.-]+\s*(?:=|/=|//=)\s*", t[start:], re.MULTILINE)
            body = t[start : start + nxt.start()] if nxt else t[start:]
            body = body.strip()
            if body.startswith("{"):
                inner, _ = self._extract_braced(body, 0)
                inner = inner or ""
                row = self._emit_table(name, engine, None, "map", file_id)
                for fm in re.finditer(
                    r"(?:\?\s*)?([\w\"$@.-]+)\s*:\s*([^,\n]+)", inner
                ):
                    self._emit_column(
                        row,
                        fm.group(1).strip('"'),
                        fm.group(2).strip().rstrip(","),
                        file_id,
                    )
            else:
                base = body.split("\n")[0][:120] or None
                self._emit_type(name, "rule", base, None, None, file_id)

    # =====================================================================
    # DBML   (.dbml)
    # =====================================================================
    _DBML_TABLE = re.compile(
        r"\bTable\s+([\w.\"]+)\s*(?:as\s+\w+\s*)?\{", re.IGNORECASE
    )
    _DBML_ENUM = re.compile(r"\bEnum\s+([\w.\"]+)\s*\{([^}]*)\}", re.IGNORECASE)
    _DBML_REF = re.compile(
        r"\bRef\s*\w*\s*:\s*([\w.\"]+)\s*([<>-])\s*([\w.\"]+)", re.IGNORECASE
    )

    def _parse_dbml(self, text, engine, file_id):
        t = re.sub(r"//[^\n]*", "", text)
        t = re.sub(r"/\*.*?\*/", "", t, flags=re.DOTALL)
        for m in self._DBML_ENUM.finditer(t):
            vals = [
                v.strip().strip('"')
                for v in re.split(r"[\n,]", m.group(2))
                if v.strip()
            ]
            self._emit_type(m.group(1).strip('"'), "enum", None, vals, None, file_id)
        for m in self._DBML_TABLE.finditer(t):
            name = m.group(1).strip('"')
            inner, _ = self._extract_braced(t, t.index("{", m.start()))
            inner = inner or ""
            row = self._emit_table(name, engine, None, "table", file_id)
            for line in inner.splitlines():
                line = line.strip()
                if not line or line.lower().startswith(("note:", "indexes")):
                    continue
                cm = re.match(r'([\w"]+)\s+([\w()<>,]+)\s*(\[[^\]]*\])?', line)
                if not cm:
                    continue
                settings = (cm.group(3) or "").lower()
                keys = None
                if "pk" in settings or "primary key" in settings:
                    keys = "primary"
                elif "unique" in settings:
                    keys = "unique"
                ref_t = ref_c = None
                rm = re.search(r"ref:\s*[<>-]\s*([\w.\"]+)", settings)
                if rm:
                    tgt = rm.group(1).strip('"').split(".")
                    ref_t = tgt[0]
                    ref_c = tgt[1] if len(tgt) > 1 else None
                self._emit_column(
                    row,
                    cm.group(1).strip('"'),
                    cm.group(2),
                    file_id,
                    keys=keys,
                    nullable="not null" not in settings,
                    ref_table=ref_t,
                    ref_col=ref_c,
                )
        for m in self._DBML_REF.finditer(t):
            left = m.group(1).strip('"').split(".")
            right = m.group(3).strip('"').split(".")
            self._emit_relation_key(left, right, engine, file_id)

    def _emit_relation_key(self, left, right, engine, file_id):
        tbl = (
            self._resolve_table_id(left[0])
            if hasattr(self, "_resolve_table_id")
            else None
        )
        self.schema_keys_table.append(
            {
                "key_id": self._next("key"),
                "key_name": None,
                "key_type": "foreign",
                "table_id": tbl,
                "column_ids": [],
                "referenced_table": right[0],
                "referenced_columns": right[1:] if len(right) > 1 else [],
                "on_delete": None,
                "on_update": None,
                "file_id": file_id,
            }
        )

    # =====================================================================
    # YANG   (.yang)
    # =====================================================================
    def _parse_yang(self, text, engine, file_id):
        t = self._strip_slashes(text)
        mm = re.search(r"\b(?:sub)?module\s+([\w.-]+)\s*\{", t)
        ns = mm.group(1) if mm else None
        for m in re.finditer(r"\btypedef\s+([\w.-]+)\s*\{", t):
            inner, _ = self._extract_braced(t, t.index("{", m.start()))
            base = re.search(r"\btype\s+([\w:.-]+)", inner or "")
            self._emit_type(
                m.group(1),
                "typedef",
                base.group(1) if base else None,
                None,
                None,
                file_id,
            )
        for m in re.finditer(
            r"(?<![\w-])(container|list|grouping)\s+([\w.-]+)\s*\{", t
        ):
            kind, name = m.group(1), m.group(2)
            inner, _ = self._extract_braced(t, t.index("{", m.start()))
            inner = inner or ""
            row = self._emit_table(name, engine, ns, kind, file_id)
            for lm in re.finditer(
                r"\b(leaf|leaf-list)\s+([\w.-]+)\s*\{([^{}]*)\}", inner
            ):
                ty = re.search(r"\btype\s+([\w:.-]+)", lm.group(3))
                self._emit_column(
                    row,
                    lm.group(2),
                    ty.group(1) if ty else None,
                    file_id,
                    keys="list" if lm.group(1) == "leaf-list" else None,
                )
        for m in re.finditer(r"\b(rpc|notification|action)\s+([\w.-]+)\s*[\{;]", t):
            self._emit_method(m.group(2), m.group(1), None, engine, None, None, file_id)

    # =====================================================================
    # SNMP MIB / ASN.1   (.mib)
    # =====================================================================
    def _parse_mib(self, text, engine, file_id):
        t = re.sub(r"--[^\n]*", "", text)  # ASN.1 -- line comments
        ns_m = re.search(r"^\s*([\w-]+)\s+DEFINITIONS\s*::=\s*BEGIN", t, re.MULTILINE)
        ns = ns_m.group(1) if ns_m else None
        # SEQUENCE types -> tables
        for m in re.finditer(r"\b([\w-]+)\s*::=\s*SEQUENCE\s*\{([^}]*)\}", t):
            row = self._emit_table(m.group(1), engine, ns, "sequence", file_id)
            for fm in re.finditer(r"([\w-]+)\s+([\w-]+(?:\s*\([^)]*\))?)", m.group(2)):
                self._emit_column(row, fm.group(1), fm.group(2).strip(), file_id)
        # OBJECT-TYPE definitions -> managed objects (types w/ syntax)
        for m in re.finditer(
            r"\b([\w-]+)\s+OBJECT-TYPE\b(.*?)::=\s*\{([^}]*)\}", t, re.DOTALL
        ):
            syn = re.search(r"SYNTAX\s+([\w-]+(?:\s*\([^)]*\))?)", m.group(2))
            self._emit_type(
                m.group(1),
                "object-type",
                syn.group(1).strip() if syn else None,
                None,
                None,
                file_id,
            )

    # =====================================================================
    # ROS message / service   (.msg / .srv)
    # =====================================================================
    @staticmethod
    def _ros_fields(block):
        out = []
        for raw in block.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"([\w/]+(?:\[\d*\])?)\s+([\w]+)\s*(?:=\s*(.+))?$", line)
            if m:
                out.append((m.group(1), m.group(2), m.group(3)))
        return out

    def _parse_ros_msg(self, text, engine, file_id, name=None):
        name = name or "Message"
        row = self._emit_table(name, engine, None, "message", file_id)
        for ty, fld, const in self._ros_fields(text):
            self._emit_column(
                row,
                fld,
                ty,
                file_id,
                keys="const" if const is not None else None,
                value=const,
            )
        return row

    def _parse_ros_srv(self, text, engine, file_id, name=None):
        name = name or "Service"
        parts = re.split(r"^\s*---\s*$", text, maxsplit=1, flags=re.MULTILINE)
        req = parts[0]
        resp = parts[1] if len(parts) > 1 else ""
        self._parse_ros_msg(req, engine, file_id, name=name + "Request")
        self._parse_ros_msg(resp, engine, file_id, name=name + "Response")

    # =====================================================================
    # SHACL (Turtle)   (.shacl)
    # =====================================================================
    def _parse_shacl(self, text, engine, file_id):
        t = re.sub(r"#[^\n]*", "", text)
        # each shape: <subject> ... a sh:NodeShape ... up to statement-terminating .
        for m in re.finditer(
            r"([:\w]+)\s+((?:[^.;]|;[^\n])*?a\s+sh:NodeShape[^.]*?)\.", t, re.DOTALL
        ):
            subj, body = m.group(1), m.group(2)
            tgt = re.search(r"sh:targetClass\s+([:\w]+)", body)
            name = _local(tgt.group(1)) if tgt else _local(subj)
            row = self._emit_table(name, engine, None, "node-shape", file_id)
            for pm in re.finditer(r"sh:path\s+([:\w]+)([^\]]*)", body):
                pname = _local(pm.group(1))
                seg = pm.group(2)
                dt = re.search(r"sh:(?:datatype|class)\s+([:\w]+)", seg)
                mincount = re.search(r"sh:minCount\s+(\d+)", seg)
                keys = "required" if (mincount and mincount.group(1) != "0") else None
                self._emit_column(
                    row,
                    pname,
                    _local(dt.group(1)) if dt else None,
                    file_id,
                    keys=keys,
                    nullable=not (mincount and mincount.group(1) != "0"),
                )

    # =====================================================================
    # EBNF grammar   (.ebnf)
    # =====================================================================
    def _parse_ebnf(self, text, engine, file_id):
        t = re.sub(r"\(\*.*?\*\)", "", text, flags=re.DOTALL)  # (* *) comments
        # split into productions terminated by ';' when present, else by lines
        chunks = re.split(r";\s*", t) if ";" in t else t.splitlines()
        for chunk in chunks:
            m = re.match(
                r"\s*[<]?([\w.\- ]+?)[>]?\s*(?:::=|=|:)\s*(.+)", chunk, re.DOTALL
            )
            if not m:
                continue
            name = m.group(1).strip()
            rhs = m.group(2)
            refs = []
            for r in re.findall(r"[<]?([A-Za-z][\w.\-]*)[>]?", rhs):
                if r and r not in refs and r != name:
                    refs.append(r)
            self._emit_type(
                name, "production", rhs.strip()[:120] or None, refs, None, file_id
            )

    # =====================================================================
    # JSON Schema document   (.jsonschema)
    # =====================================================================
    def _parse_jsonschema_doc(self, text, engine, file_id):
        try:
            doc = json.loads(text)
        except Exception:
            docs = load_yaml_docs(text)
            doc = docs[0] if docs else None
        if not isinstance(doc, dict):
            return
        title = doc.get("title") or doc.get("$id") or "Schema"
        self._emit_json_object(_local(str(title)), doc, engine, file_id, "schema")
        for section in ("definitions", "$defs"):
            defs = doc.get(section)
            if isinstance(defs, dict):
                for dn, dv in defs.items():
                    if isinstance(dv, dict):
                        self._emit_json_object(dn, dv, engine, file_id, "definition")

    def _emit_json_object(self, name, schema, engine, file_id, kind):
        if schema.get("enum"):
            self._emit_type(
                name, "enum", schema.get("type"), list(schema["enum"]), None, file_id
            )
        props = schema.get("properties")
        if not isinstance(props, dict):
            if schema.get("type") and not schema.get("enum"):
                self._emit_type(name, "scalar", schema.get("type"), None, None, file_id)
            return None
        required = set(schema.get("required") or [])
        row = self._emit_table(name, engine, None, kind, file_id)
        for pn, pv in props.items():
            if not isinstance(pv, dict):
                self._emit_column(row, pn, None, file_id)
                continue
            ptype = pv.get("type")
            if isinstance(ptype, list):
                ptype = "|".join(str(x) for x in ptype)
            fmt = pv.get("format")
            tstr = f"{ptype}:{fmt}" if fmt else ptype
            self._emit_column(
                row,
                pn,
                tstr,
                file_id,
                keys="required" if pn in required else None,
                nullable=pn not in required,
                default=_json_default(pv),
                value=(
                    "|".join(map(str, pv["enum"]))
                    if isinstance(pv.get("enum"), list)
                    else None
                ),
            )
        return row

    # =====================================================================
    # OpenAPI / Swagger   (.openapi / .swagger)
    # =====================================================================
    def _parse_openapi(self, text, engine, file_id):
        docs = load_yaml_docs(text)
        if not docs or not isinstance(docs[0], dict):
            return
        doc = docs[0]
        info = doc.get("info") or {}
        ns = info.get("title") if isinstance(info, dict) else None
        schemas = {}
        comps = doc.get("components")
        if isinstance(comps, dict) and isinstance(comps.get("schemas"), dict):
            schemas = comps["schemas"]
        elif isinstance(doc.get("definitions"), dict):  # Swagger 2.0
            schemas = doc["definitions"]
        for sn, sv in schemas.items():
            if isinstance(sv, dict):
                row = self._emit_json_object(sn, sv, engine, file_id, "schema")
                if row is not None:
                    row["namespace"] = ns
        paths = doc.get("paths")
        if isinstance(paths, dict):
            for route, ops in paths.items():
                if not isinstance(ops, dict):
                    continue
                for verb, op in ops.items():
                    if verb.lower() not in (
                        "get",
                        "post",
                        "put",
                        "delete",
                        "patch",
                        "head",
                        "options",
                    ):
                        continue
                    opid = (
                        op.get("operationId") if isinstance(op, dict) else None
                    ) or f"{verb.upper()} {route}"
                    self._emit_method(
                        opid,
                        "operation",
                        None,
                        engine,
                        f"{verb.upper()} {route}",
                        None,
                        file_id,
                    )

    # =====================================================================
    # RAML   (.raml)
    # =====================================================================
    def _parse_raml(self, text, engine, file_id):
        docs = load_yaml_docs(re.sub(r"^#%RAML[^\n]*\n", "", text))
        if not docs or not isinstance(docs[0], dict):
            return
        doc = docs[0]
        ns = doc.get("title")
        types = doc.get("types") or doc.get("schemas")
        if isinstance(types, dict):
            for tn, tv in types.items():
                if isinstance(tv, dict) and isinstance(tv.get("properties"), dict):
                    row = self._emit_table(tn, engine, ns, "type", file_id)
                    for pn, pv in tv["properties"].items():
                        pt = pv.get("type") if isinstance(pv, dict) else pv
                        self._emit_column(
                            row,
                            pn.rstrip("?"),
                            pt if isinstance(pt, str) else None,
                            file_id,
                            nullable=pn.endswith("?"),
                        )
                else:
                    self._emit_type(
                        tn,
                        "type",
                        (
                            tv.get("type")
                            if isinstance(tv, dict)
                            else (tv if isinstance(tv, str) else None)
                        ),
                        None,
                        None,
                        file_id,
                    )
        for key, val in doc.items():
            if key.startswith("/") and isinstance(val, dict):
                for verb in ("get", "post", "put", "delete", "patch"):
                    if verb in val:
                        self._emit_method(
                            f"{verb.upper()} {key}",
                            "operation",
                            None,
                            engine,
                            None,
                            None,
                            file_id,
                        )

    # =====================================================================
    # Kubernetes CRD   (.crd)
    # =====================================================================
    def _parse_crd(self, text, engine, file_id):
        for doc in load_yaml_docs(text):
            if not isinstance(doc, dict):
                continue
            if doc.get("kind") != "CustomResourceDefinition":
                continue
            spec = doc.get("spec") or {}
            names = spec.get("names") or {}
            kind = names.get("kind") or doc.get("metadata", {}).get("name", "CRD")
            group = spec.get("group")
            schema = None
            versions = spec.get("versions")
            if isinstance(versions, list) and versions:
                v0 = versions[0]
                schema = (
                    ((v0.get("schema") or {}).get("openAPIV3Schema"))
                    if isinstance(v0, dict)
                    else None
                )
            if schema is None:  # v1beta1
                schema = (spec.get("validation") or {}).get("openAPIV3Schema")
            row = self._emit_table(kind, engine, group, "custom-resource", file_id)
            props = (
                (schema or {}).get("properties") if isinstance(schema, dict) else None
            )
            if isinstance(props, dict):
                for pn, pv in props.items():
                    pt = pv.get("type") if isinstance(pv, dict) else None
                    self._emit_column(row, pn, pt, file_id)

    # =====================================================================
    # Kaitai Struct   (.ksy)
    # =====================================================================
    def _parse_ksy(self, text, engine, file_id):
        docs = load_yaml_docs(text)
        if not docs or not isinstance(docs[0], dict):
            return
        doc = docs[0]
        meta = doc.get("meta") or {}
        root = meta.get("id", "kaitai") if isinstance(meta, dict) else "kaitai"
        self._emit_ksy_type(root, doc, engine, file_id)
        types = doc.get("types")
        if isinstance(types, dict):
            for tn, tv in types.items():
                if isinstance(tv, dict):
                    self._emit_ksy_type(tn, tv, engine, file_id)
        enums = doc.get("enums")
        if isinstance(enums, dict):
            for en, ev in enums.items():
                vals = list(ev.values()) if isinstance(ev, dict) else []
                self._emit_type(en, "enum", None, [str(x) for x in vals], None, file_id)

    def _emit_ksy_type(self, name, node, engine, file_id):
        seq = node.get("seq")
        insts = node.get("instances")
        if not (isinstance(seq, list) or isinstance(insts, dict)):
            return
        row = self._emit_table(name, engine, None, "kaitai-type", file_id)
        if isinstance(seq, list):
            for fld in seq:
                if isinstance(fld, dict):
                    self._emit_column(
                        row, str(fld.get("id", "?")), _ksy_type(fld), file_id
                    )
        if isinstance(insts, dict):
            for iname, iv in insts.items():
                self._emit_column(
                    row,
                    iname,
                    _ksy_type(iv) if isinstance(iv, dict) else None,
                    file_id,
                    keys="instance",
                )

    # =====================================================================
    # Xcode String Catalog   (.xcstrings)
    # =====================================================================
    def _parse_xcstrings(self, text, engine, file_id):
        try:
            doc = json.loads(text)
        except Exception:
            return
        if not isinstance(doc, dict):
            return
        src = doc.get("sourceLanguage")
        strings = doc.get("strings")
        if not isinstance(strings, dict):
            return
        row = self._emit_table("StringCatalog", engine, src, "string-catalog", file_id)
        for key, entry in strings.items():
            comment = entry.get("comment") if isinstance(entry, dict) else None
            locs = (
                entry.get("localizations") if isinstance(entry, dict) else None
            ) or {}
            self._emit_column(
                row,
                key or "(base)",
                "localized-string",
                file_id,
                value=comment,
                default=(",".join(sorted(locs)) if locs else None),
            )


def _json_default(schema):
    d = schema.get("default")
    return None if d is None else str(d)


def _ksy_type(fld):
    ty = fld.get("type")
    if isinstance(ty, dict):
        ty = ty.get("switch-on", "switch")
    sz = fld.get("size")
    if ty is None and sz is not None:
        return f"bytes[{sz}]"
    if fld.get("repeat"):
        return f"{ty}[]"
    return ty
