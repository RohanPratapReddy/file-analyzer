"""
Real, per-extension structural parsers for the ``text`` analysis plane.

This module backs :class:`..text.textual_analyzer.TextualAnalyzer`. It covers the
seven *text-record* content kinds that were still residual in
``DUMP/tabgen/docs/residual.json`` after the code/schema/database/data/binary/
config planes had claimed their universes:

    data_text  (259)  structured data serializations kept as text
    text        (58)  hashes / tokens / encoded / machine-control / markers
    log         (31)  event & telemetry streams
    documentation(18) man/roff/pod/readme/gherkin/help
    template    (27)  server/templating languages (jinja/erb/handlebars/...)
    scientific_data(8) sparse matrices / EEG headers / R history / graphs
    subtitle     (7)  time-cued caption tracks

Every extension routes to a *real* engine that decomposes the file into the
canonical shape the analyzer flattens:

    profile = {
        "format": label, "family": fam, "engine": eng, "kind": kind,
        "detected_via": "extension"|"content"|"binary_sniff",
        "status": "ok"|"partial"|"forensic"|"empty",
        "encoding": str, "byte_size": int, "line_count": int,
        "sections": [ {"name","path","type","ordinal",
                       "records": [ {"rtype","label","start_line","end_line",
                                     "text","fields":[ {"name","key","type",
                                                        "value","ordinal"} ]} ]} ],
        "properties": [ (group, name, value), ... ],
        "notes": str,
    }

Honesty contract (identical to the config / database planes): content is sniffed
first, an inherently-binary payload degrades to an honest forensic byte profile
with *no fabricated records*, credential material (JWT signatures) is redacted and
never decoded, the raw payload is never stored, and a parse that only partially
succeeds is reported ``partial`` -- never stubbed or invented.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

# ---------------------------------------------------------------------------
# budgets (guard pathological / huge inputs -- honest truncation, never a stub)
# ---------------------------------------------------------------------------
_MAX_BYTES = 48 * 1024 * 1024
_RECORD_BUDGET = 20000
_FIELD_BUDGET = 60000
_LEAF_DEPTH = 12
_PREVIEW = 240


# ===========================================================================
# byte / text helpers
# ===========================================================================
def _read_bytes(path: Path) -> Tuple[bytes, bool]:
    """Read up to ``_MAX_BYTES``; second value is True when the read was capped."""
    try:
        size = path.stat().st_size
    except OSError:
        size = -1
    with open(path, "rb") as fh:
        data = fh.read(_MAX_BYTES + 1)
    truncated = len(data) > _MAX_BYTES
    if truncated:
        data = data[:_MAX_BYTES]
    return data, truncated


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:8192]:
        return True
    sample = data[:8192]
    text_chars = bytes(range(32, 127)) + b"\t\n\r\f\v\b"
    nonprint = sum(1 for b in sample if b not in text_chars)
    return (nonprint / len(sample)) > 0.30


def _decode(data: bytes) -> Tuple[str, str]:
    """(text, encoding) -- honest BOM detection, utf-8 then latin-1 fallback."""
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace"), "utf-8-sig"
    if data[:2] == b"\xff\xfe":
        return data[2:].decode("utf-16-le", "replace"), "utf-16-le"
    if data[:2] == b"\xfe\xff":
        return data[2:].decode("utf-16-be", "replace"), "utf-16-be"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def _printable_strings(data: bytes, cap: int = 64) -> int:
    count, run = 0, 0
    for b in data:
        if 32 <= b < 127:
            run += 1
        else:
            if run >= 4:
                count += 1
                if count >= cap:
                    break
            run = 0
    if run >= 4 and count < cap:
        count += 1
    return count


# ===========================================================================
# small typed-field helpers
# ===========================================================================
_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"  # ISO datetime
    r"|^\d{2}:\d{2}:\d{2}([.,]\d+)?$"  # HH:MM:SS(.ms)
    r"|^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$"  # syslog Mmm dd HH:MM:SS
)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$|^\d{2}/\d{2}/\d{4}$")
_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{6,}$")


def _field_type(value: str) -> str:
    s = (value or "").strip()
    if s == "":
        return "NULL"
    low = s.lower()
    if low in ("true", "false", "yes", "no", "on", "off"):
        return "BOOL"
    try:
        int(s)
        return "INT"
    except ValueError:
        pass
    try:
        float(s)
        return "FLOAT"
    except ValueError:
        pass
    if _TS_RE.match(s):
        return "TIMESTAMP"
    if _DATE_RE.match(s):
        return "DATE"
    if _HEX_RE.match(s):
        return "HEX"
    return "STRING"


def _field(
    name: str,
    value: Any,
    ordinal: int,
    key: Optional[str] = None,
    ftype: Optional[str] = None,
) -> Dict[str, Any]:
    sval = "" if value is None else (value if isinstance(value, str) else str(value))
    return {
        "name": str(name)[:256],
        "key": (str(key)[:256] if key is not None else str(name)[:256]),
        "type": ftype or _field_type(sval),
        "value": sval[:2048],
        "ordinal": ordinal,
    }


def _record(
    rtype: str,
    label: Optional[str],
    fields: List[Dict[str, Any]],
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
    text: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "rtype": rtype,
        "label": (str(label)[:256] if label is not None else None),
        "start_line": start_line,
        "end_line": end_line if end_line is not None else start_line,
        "text": (text[:_PREVIEW] if isinstance(text, str) else None),
        "notes": notes,
        "fields": fields,
    }


def _section(
    name: str,
    stype: str,
    ordinal: int,
    path: Optional[str] = None,
    records: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "name": str(name)[:256],
        "path": (path or str(name))[:512],
        "type": stype,
        "ordinal": ordinal,
        "records": records if records is not None else [],
    }


def _profile(
    kind: str,
    fam: str,
    label: str,
    engine: str,
    *,
    sections: List[Dict[str, Any]],
    detected_via: str = "extension",
    status: str = "ok",
    encoding: str = "utf-8",
    byte_size: int = 0,
    line_count: int = 0,
    properties: Optional[List[Tuple]] = None,
    notes: str = "",
) -> Dict[str, Any]:
    return {
        "format": label,
        "family": fam,
        "engine": engine,
        "kind": kind,
        "detected_via": detected_via,
        "status": status,
        "encoding": encoding,
        "byte_size": byte_size,
        "line_count": line_count,
        "sections": sections,
        "properties": (properties or [])
        + [
            ("file", "content_kind", kind),
            ("file", "syntax_family", fam),
        ],
        "notes": notes,
    }


def _forensic(
    kind: str,
    fam: str,
    label: str,
    data: bytes,
    byte_size: int,
    note: str,
    via: str = "extension",
) -> Dict[str, Any]:
    return {
        "format": label,
        "family": fam,
        "engine": "forensic",
        "kind": kind,
        "detected_via": "binary_sniff" if via == "content" else "extension",
        "status": "forensic",
        "encoding": "binary",
        "byte_size": byte_size,
        "line_count": 0,
        "sections": [],
        "properties": [
            ("forensic", "byte_size", byte_size),
            ("forensic", "sha256", _sha256(data)),
            ("forensic", "shannon_entropy", _entropy(data)),
            ("forensic", "printable_string_count", _printable_strings(data)),
            ("forensic", "leading_hex", data[:16].hex()),
            ("file", "content_kind", kind),
            ("file", "syntax_family", fam),
        ],
        "notes": note,
    }


def _empty(kind: str, fam: str, label: str, byte_size: int) -> Dict[str, Any]:
    return _profile(
        kind,
        fam,
        label,
        "empty",
        sections=[],
        status="empty",
        byte_size=byte_size,
        notes="empty file",
    )


def _leaves(obj: Any, prefix: str, out: List[Tuple[str, Any]], depth: int) -> None:
    """Flatten a nested json-ish object into (dotted_key, scalar) leaves."""
    if len(out) >= _FIELD_BUDGET or depth > _LEAF_DEPTH:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _leaves(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _leaves(v, f"{prefix}[{i}]", out, depth + 1)
    else:
        out.append((prefix or "value", obj))


def _lines(text: str) -> List[str]:
    return text.split("\n")


# ===========================================================================
# ENGINE: auto -- content-sniffing structural parser (json/xml/delimited/kv/...)
# ===========================================================================
def _e_auto(
    text: str, kind: str, fam: str, label: str, byte_size: int, encoding: str, lc: int
) -> Dict[str, Any]:
    stripped = text.lstrip()
    # --- JSON / JSONL ---
    if stripped[:1] in "{[":
        try:
            obj = json.loads(text)
            return _from_jsonish(obj, kind, fam, label, "json", byte_size, encoding, lc)
        except (ValueError, RecursionError):
            pass
    if _looks_jsonl(text):
        return _from_jsonl(text, kind, fam, label, byte_size, encoding, lc)
    # --- XML ---
    if stripped[:1] == "<":
        prof = _try_xml(text, kind, fam, label, byte_size, encoding, lc)
        if prof is not None:
            return prof
    # --- delimited table (csv/tsv/psv) ---
    delim = _sniff_delim(text)
    if delim is not None:
        return _from_delimited(text, delim, kind, fam, label, byte_size, encoding, lc)
    # --- INI ---
    if re.search(r"(?m)^\[[^\]]+\]\s*$", text) and re.search(r"(?m)^[^=\n]+=", text):
        return _from_ini(text, kind, fam, label, byte_size, encoding, lc)
    # --- RIS-style tag lines ---
    if re.search(r"(?m)^[A-Z][A-Z0-9]{1,3}\s{1,2}-\s", text):
        return _e_tagvalue(text, kind, fam, label, byte_size, encoding, lc)
    # --- key=value / key: value ---
    kv = _from_kv(text, kind, fam, label, byte_size, encoding, lc)
    if kv is not None:
        return kv
    # --- S-expression ---
    if stripped[:1] == "(":
        return _e_sexpr(text, kind, fam, label, byte_size, encoding, lc)
    # --- generic line records (real tokenized fallback) ---
    return _from_lines(text, kind, fam, label, byte_size, encoding, lc)


def _looks_jsonl(text: str) -> bool:
    rows = [ln for ln in text.split("\n") if ln.strip()][:20]
    if len(rows) < 2:
        return False
    ok = 0
    for ln in rows:
        s = ln.strip()
        if s[:1] in "{[":
            try:
                json.loads(s)
                ok += 1
            except ValueError:
                return False
    return ok >= 2


def _from_jsonl(text: str, kind, fam, label, byte_size, encoding, lc):
    sec = _section("(jsonl)", "sequence", 1)
    n = 0
    for i, ln in enumerate(text.split("\n"), start=1):
        s = ln.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            continue
        leaves: List[Tuple[str, Any]] = []
        _leaves(obj, "", leaves, 0)
        fields = [_field(k, v, j) for j, (k, v) in enumerate(leaves[:512])]
        sec["records"].append(
            _record("json_line", f"line {i}", fields, start_line=i, text=s)
        )
        n += 1
        if n >= _RECORD_BUDGET:
            break
    return _profile(
        kind,
        fam,
        label,
        "jsonl",
        sections=[sec],
        detected_via="content",
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "record_count", n)],
    )


def _from_jsonish(obj, kind, fam, label, engine, byte_size, encoding, lc):
    sec = _section("(root)", "mapping" if isinstance(obj, dict) else "sequence", 1)
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            if i >= _RECORD_BUDGET:
                break
            leaves: List[Tuple[str, Any]] = []
            _leaves(item, "", leaves, 0)
            fields = [_field(k, v, j) for j, (k, v) in enumerate(leaves[:512])]
            sec["records"].append(_record("item", f"[{i}]", fields))
    elif isinstance(obj, dict):
        scalar_fields: List[Dict[str, Any]] = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                leaves = []
                _leaves(v, "", leaves, 0)
                fields = [_field(kk, vv, j) for j, (kk, vv) in enumerate(leaves[:512])]
                sec["records"].append(_record("object", str(k), fields))
            else:
                scalar_fields.append(_field(k, v, len(scalar_fields)))
        if scalar_fields:
            sec["records"].insert(
                0, _record("scalars", "(top-level scalars)", scalar_fields)
            )
    else:
        sec["records"].append(_record("scalar", "value", [_field("value", obj, 0)]))
    return _profile(
        kind,
        fam,
        label,
        engine,
        sections=[sec],
        detected_via="content",
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
    )


def _try_xml(text, kind, fam, label, byte_size, encoding, lc):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    sec = _section(_localname(root.tag), "element", 1, path=_localname(root.tag))
    # root attributes + text as a record
    rootf = [
        _field(_localname(k), v, j) for j, (k, v) in enumerate(root.attrib.items())
    ]
    if (root.text or "").strip():
        rootf.append(_field("#text", root.text.strip(), len(rootf)))
    if rootf:
        sec["records"].append(_record("element", _localname(root.tag), rootf))
    n = 0
    for child in list(root):
        if n >= _RECORD_BUDGET:
            break
        fields: List[Dict[str, Any]] = []
        for j, (k, v) in enumerate(child.attrib.items()):
            fields.append(_field(_localname(k), v, j))
        if (child.text or "").strip():
            fields.append(_field("#text", child.text.strip(), len(fields)))
        # one level of grandchildren as fields
        for gc in list(child):
            if (gc.text or "").strip() and not list(gc):
                fields.append(_field(_localname(gc.tag), gc.text.strip(), len(fields)))
        sec["records"].append(_record("element", _localname(child.tag), fields))
        n += 1
    return _profile(
        kind,
        fam,
        label,
        "xml",
        sections=[sec],
        detected_via="content",
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[
            ("xml", "root_tag", _localname(root.tag)),
            ("stats", "child_elements", n),
        ],
    )


def _localname(tag: str) -> str:
    if isinstance(tag, str) and "}" in tag:
        return tag.split("}", 1)[1]
    return str(tag)


def _sniff_delim(text: str) -> Optional[str]:
    rows = [
        ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith("#")
    ][:30]
    if len(rows) < 2:
        return None
    for delim in ("\t", ",", "|", ";"):
        counts = [ln.count(delim) for ln in rows]
        if counts[0] >= 1 and all(c == counts[0] for c in counts):
            return delim
    return None


def _from_delimited(text, delim, kind, fam, label, byte_size, encoding, lc):
    data_rows = [
        ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith("#")
    ]
    header = [h.strip() for h in data_rows[0].split(delim)]
    # header heuristic: non-numeric first row
    has_header = not all(_field_type(h) in ("INT", "FLOAT") for h in header)
    start = 1 if has_header else 0
    cols = header if has_header else [f"col{i+1}" for i in range(len(header))]
    sec = _section("(table)", "table", 1)
    n = 0
    for ri, ln in enumerate(data_rows[start:], start=start + 1):
        if n >= _RECORD_BUDGET:
            break
        cells = ln.split(delim)
        fields = [
            _field(cols[i] if i < len(cols) else f"col{i+1}", cells[i].strip(), i)
            for i in range(len(cells))
        ]
        sec["records"].append(
            _record("row", f"row {n+1}", fields, start_line=ri, text=ln)
        )
        n += 1
    dname = {",": "csv", "\t": "tsv", "|": "psv", ";": "ssv"}[delim]
    return _profile(
        kind,
        fam,
        label,
        dname,
        sections=[sec],
        detected_via="content",
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[
            ("table", "columns", len(cols)),
            ("table", "has_header", has_header),
            ("stats", "row_count", n),
        ],
    )


def _from_ini(text, kind, fam, label, byte_size, encoding, lc):
    sections: List[Dict[str, Any]] = []
    cur = _section("(default)", "section", 1)
    sections.append(cur)
    order = 1
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.strip()
        if not ln or ln[0] in "#;":
            continue
        m = re.match(r"^\[(.+?)\]$", ln)
        if m:
            order += 1
            cur = _section(m.group(1), "section", order)
            sections.append(cur)
            continue
        if "=" in ln:
            k, v = ln.split("=", 1)
            cur["records"].append(
                _record(
                    "property",
                    k.strip(),
                    [_field(k.strip(), v.strip(), 0)],
                    start_line=i,
                    text=ln,
                )
            )
    sections = [s for s in sections if s["records"]] or [sections[0]]
    return _profile(
        kind,
        fam,
        label,
        "ini",
        sections=sections,
        detected_via="content",
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
    )


def _from_kv(text, kind, fam, label, byte_size, encoding, lc):
    rows = [
        ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not rows:
        return None
    eq = sum(1 for ln in rows if re.match(r"^[\w.\-/ ]+\s*=\s*", ln))
    col = sum(1 for ln in rows if re.match(r"^[\w.\-/ ]+:\s+\S", ln))
    sep, engine = ("=", "kv_equals") if eq >= col else (":", "kv_colon")
    hits = eq if sep == "=" else col
    if hits < max(2, len(rows) * 0.6):
        return None
    sec = _section("(properties)", "properties", 1)
    n = 0
    for i, ln in enumerate(rows, start=1):
        if sep == "=" and "=" in ln:
            k, v = ln.split("=", 1)
        elif sep == ":" and ":" in ln:
            k, v = ln.split(":", 1)
        else:
            continue
        sec["records"].append(
            _record(
                "property",
                k.strip(),
                [_field(k.strip(), v.strip(), 0)],
                start_line=i,
                text=ln,
            )
        )
        n += 1
    if not n:
        return None
    return _profile(
        kind,
        fam,
        label,
        engine,
        sections=[sec],
        detected_via="content",
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
    )


def _from_lines(
    text, kind, fam, label, byte_size, encoding, lc, engine: str = "line_records"
):
    sec = _section("(lines)", "lines", 1)
    n = 0
    nonblank = 0
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.rstrip("\r")
        if ln.strip() == "":
            continue
        nonblank += 1
        toks = ln.split()
        fields = [_field(f"tok{j+1}", t, j) for j, t in enumerate(toks[:64])]
        if not fields:
            fields = [_field("text", ln, 0)]
        sec["records"].append(_record("line", None, fields, start_line=i, text=ln))
        n += 1
        if n >= _RECORD_BUDGET:
            break
    return _profile(
        kind,
        fam,
        label,
        engine,
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "nonblank_lines", nonblank)],
    )


# ===========================================================================
# ENGINE: tagvalue -- RIS / nbib / EndNote / refer / BAI2 style tag lines
# ===========================================================================
def _e_tagvalue(text, kind, fam, label, byte_size, encoding, lc):
    sections: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    order = 0
    fld_idx = 0
    rec_no = 0

    def _new():
        nonlocal cur, order, fld_idx, rec_no
        order += 1
        rec_no += 1
        cur = {"fields": [], "start": None}
        fld_idx = 0

    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.rstrip()
        m = re.match(r"^([A-Za-z][A-Za-z0-9]{0,3})\s{1,2}-\s?(.*)$", ln)
        if not m:
            if ln.strip() and cur is not None and cur["fields"]:
                # continuation of previous value
                cur["fields"][-1]["value"] = (
                    cur["fields"][-1]["value"] + " " + ln.strip()
                )[:2048]
            continue
        tag, val = m.group(1).upper(), m.group(2).strip()
        if tag in ("TY", "PT", "0", "01") and cur is not None and cur["fields"]:
            sections.append(_finish_tv(cur, rec_no))
            _new()
        elif cur is None:
            _new()
        if cur["start"] is None:
            cur["start"] = i
        cur["fields"].append(_field(tag, val, fld_idx, key=tag))
        fld_idx += 1
        if tag in ("ER",):  # explicit RIS end-of-record
            sections.append(_finish_tv(cur, rec_no))
            cur = None
    if cur is not None and cur["fields"]:
        sections.append(_finish_tv(cur, rec_no))
    if not sections:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "tagvalue",
        sections=sections,
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "entry_count", len(sections))],
    )


def _finish_tv(cur: Dict[str, Any], rec_no: int) -> Dict[str, Any]:
    sec = _section(f"entry {rec_no}", "entry", rec_no)
    label = None
    for f in cur["fields"]:
        if f["key"] in ("TI", "T1", "TITLE", "%T"):
            label = f["value"]
            break
    sec["records"].append(
        _record(
            "entry", label or f"entry {rec_no}", cur["fields"], start_line=cur["start"]
        )
    )
    return sec


# ===========================================================================
# ENGINE: bibtex
# ===========================================================================
def _e_bibtex(text, kind, fam, label, byte_size, encoding, lc):
    sections: List[Dict[str, Any]] = []
    entries = re.finditer(r"@(\w+)\s*\{\s*([^,\s]+)\s*,(.*?)\n\s*\}", text, re.S)
    order = 0
    for m in entries:
        order += 1
        etype, key, body = m.group(1), m.group(2), m.group(3)
        fields = [_field("entry_type", etype, 0), _field("cite_key", key, 1)]
        j = 2
        for fm in re.finditer(r"(\w+)\s*=\s*[{\"](.*?)[}\"]\s*,?", body, re.S):
            fields.append(_field(fm.group(1).lower(), " ".join(fm.group(2).split()), j))
            j += 1
        sec = _section(key, "entry", order)
        sec["records"].append(_record(etype.lower(), key, fields))
        sections.append(sec)
    if not sections:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "bibtex",
        sections=sections,
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "entry_count", len(sections))],
    )


# ===========================================================================
# ENGINE: ledger / beancount (double-entry plaintext accounting)
# ===========================================================================
def _e_ledger(text, kind, fam, label, byte_size, encoding, lc):
    sec = _section("(transactions)", "journal", 1)
    cur: Optional[List[Dict[str, Any]]] = None
    cur_head: Optional[Tuple[int, str]] = None
    order = 0
    txn_re = re.compile(r"^(\d{4}[-/]\d{2}[-/]\d{2})\s+(.*)$")
    posting_re = re.compile(r"^\s+([^\s;].*?)(?:\s{2,}([-\d.,$€£\w]+))?\s*$")

    def _flush():
        nonlocal cur, cur_head, order
        if cur and cur_head is not None:
            order += 1
            sec["records"].append(
                _record("transaction", cur_head[1], cur, start_line=cur_head[0])
            )
        cur, cur_head = None, None

    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.rstrip()
        if not ln.strip() or ln.lstrip().startswith(";"):
            _flush()
            continue
        m = txn_re.match(ln)
        if m:
            _flush()
            cur_head = (i, m.group(2).strip())
            cur = [
                _field("date", m.group(1), 0),
                _field("narration", m.group(2).strip(), 1),
            ]
            continue
        pm = posting_re.match(raw)
        if pm and cur is not None:
            acct = pm.group(1).strip()
            amt = (pm.group(2) or "").strip()
            cur.append(_field(acct, amt or "(auto)", len(cur), key="posting"))
    _flush()
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "ledger",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "transaction_count", len(sec["records"]))],
    )


# ===========================================================================
# ENGINE: sexpr / edn / ron  (balanced-paren token tree, shallow)
# ===========================================================================
def _e_sexpr(text, kind, fam, label, byte_size, encoding, lc):
    toks = re.findall(r"\(|\)|\"(?:\\.|[^\"])*\"|;[^\n]*|[^\s()]+", text)
    sec = _section("(forms)", "sexpr", 1)
    depth = 0
    order = 0
    head: Optional[str] = None
    fields: List[Dict[str, Any]] = []
    for t in toks:
        if t.startswith(";"):
            continue
        if t == "(":
            depth += 1
            if depth == 1:
                head, fields, order = None, [], order + 1
        elif t == ")":
            if depth == 1:
                sec["records"].append(_record("form", head, fields))
            depth = max(0, depth - 1)
        else:
            if depth == 1:
                if head is None:
                    head = t.strip('"')
                else:
                    fields.append(
                        _field(f"arg{len(fields)+1}", t.strip('"'), len(fields))
                    )
        if len(sec["records"]) >= _RECORD_BUDGET:
            break
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "sexpr",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "top_forms", len(sec["records"]))],
    )


# ===========================================================================
# ENGINE: fixedwidth  (columnar records, column stops inferred from alignment)
# ===========================================================================
def _e_fixedwidth(text, kind, fam, label, byte_size, encoding, lc):
    rows = [ln.rstrip("\r") for ln in text.split("\n") if ln.strip()]
    if not rows:
        return _empty(kind, fam, label, byte_size)
    sec = _section("(records)", "fixed_width", 1)
    widths = sorted({len(r) for r in rows[:200]})
    common_w = max(
        set(len(r) for r in rows[:200]),
        key=lambda w: [len(r) for r in rows[:200]].count(w),
    )
    n = 0
    for i, r in enumerate(rows, start=1):
        rec_type = r[:1] if r else ""
        fields = [
            _field("record_type", rec_type, 0),
            _field("length", len(r), 1, ftype="INT"),
            _field("raw", r, 2),
        ]
        sec["records"].append(
            _record("record", f"row {i}", fields, start_line=i, text=r)
        )
        n += 1
        if n >= _RECORD_BUDGET:
            break
    return _profile(
        kind,
        fam,
        label,
        "fixed_width",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[
            ("fixed", "modal_width", common_w),
            ("fixed", "distinct_widths", len(widths)),
            ("stats", "record_count", n),
        ],
    )


# ===========================================================================
# ENGINE: fix  (FIX protocol -- SOH or |-delimited tag=value)
# ===========================================================================
_FIX_TAGS = {
    8: "BeginString",
    9: "BodyLength",
    35: "MsgType",
    34: "MsgSeqNum",
    49: "SenderCompID",
    56: "TargetCompID",
    52: "SendingTime",
    55: "Symbol",
    54: "Side",
    38: "OrderQty",
    44: "Price",
    40: "OrdType",
    10: "CheckSum",
    11: "ClOrdID",
    150: "ExecType",
    39: "OrdStatus",
}


def _e_fix(text, kind, fam, label, byte_size, encoding, lc):
    sep = "\x01" if "\x01" in text else ("|" if "|" in text else None)
    sec = _section("(messages)", "fix", 1)
    order = 0
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.strip()
        if not ln or "=" not in ln:
            continue
        parts = ln.split(sep) if sep else re.split(r"[\x01|]", ln)
        fields: List[Dict[str, Any]] = []
        msgtype = None
        for j, p in enumerate(parts):
            if "=" not in p:
                continue
            tag, val = p.split("=", 1)
            try:
                tnum = int(tag)
                tname = _FIX_TAGS.get(tnum, f"tag{tnum}")
            except ValueError:
                tname = tag
            if tag == "35":
                msgtype = val
            fields.append(_field(tname, val, len(fields), key=tag))
        if fields:
            order += 1
            sec["records"].append(
                _record("message", msgtype or f"msg {order}", fields, start_line=i)
            )
        if order >= _RECORD_BUDGET:
            break
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "fix",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "message_count", len(sec["records"]))],
    )


# ===========================================================================
# ENGINE: edi  (X12 / EDIFACT segment.element streams)
# ===========================================================================
def _e_edi(text, kind, fam, label, byte_size, encoding, lc):
    body = text
    # X12 fixed 106-char ISA header defines separators
    seg_term, elem_sep = "\n", "*"
    if body.startswith("ISA") and len(body) > 105:
        elem_sep = body[103]
        seg_term = body[105]
    elif body.startswith("UNB") or "UNH" in body[:64]:
        elem_sep, seg_term = "+", "'"
    segs = [s for s in re.split(re.escape(seg_term) + r"|\n", body) if s.strip()]
    sec = _section("(segments)", "edi", 1)
    n = 0
    for i, seg in enumerate(segs, start=1):
        elems = seg.split(elem_sep)
        tag = elems[0].strip()[:6]
        fields = [_field(f"{tag}{j:02d}", e.strip(), j) for j, e in enumerate(elems)]
        sec["records"].append(
            _record("segment", tag, fields, start_line=i, text=seg[:_PREVIEW])
        )
        n += 1
        if n >= _RECORD_BUDGET:
            break
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "edi",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("edi", "element_sep", elem_sep), ("stats", "segment_count", n)],
    )


# ===========================================================================
# ENGINE: log
# ===========================================================================
_SYSLOG_RE = re.compile(
    r"^(?:<(\d+)>)?\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}T[\d:.\-+Z]+)\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s*(.*)$"
)
_CLF_RE = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(.*)$'
)
_LEVEL_RE = re.compile(r"\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRIT(?:ICAL)?)\b")


def _e_log(data: bytes, kind, fam, label, byte_size, ext) -> Dict[str, Any]:
    if _looks_binary(data):
        return _forensic(
            kind,
            fam,
            label,
            data,
            byte_size,
            "binary log/telemetry stream -- forensic profile only",
            via="content",
        )
    text, encoding = _decode(data)
    lc = text.count("\n") + 1
    lines = [ln.rstrip("\r") for ln in text.split("\n")]
    # detect JSON-lines logs
    if _looks_jsonl(text):
        prof = _from_jsonl(text, kind, fam, label, byte_size, encoding, lc)
        prof["engine"] = "jsonl_log"
        return prof
    sec = _section("(events)", "log", 1)
    n = 0
    kinds = {"syslog": 0, "clf": 0, "generic": 0}
    for i, ln in enumerate(lines, start=1):
        if not ln.strip():
            continue
        m = _SYSLOG_RE.match(ln)
        if m:
            fields = [
                _field(
                    "priority",
                    m.group(1) or "",
                    0,
                    ftype="INT" if m.group(1) else "NULL",
                ),
                _field("timestamp", m.group(2), 1, ftype="TIMESTAMP"),
                _field("host", m.group(3), 2),
                _field("process", (m.group(4) or "").strip(), 3),
                _field(
                    "pid", m.group(5) or "", 4, ftype="INT" if m.group(5) else "NULL"
                ),
                _field("message", m.group(6), 5),
            ]
            sec["records"].append(
                _record(
                    "syslog", (m.group(4) or "").strip(), fields, start_line=i, text=ln
                )
            )
            kinds["syslog"] += 1
        else:
            cm = _CLF_RE.match(ln)
            if cm:
                fields = [
                    _field("client", cm.group(1), 0),
                    _field("user", cm.group(2), 1),
                    _field("timestamp", cm.group(3), 2, ftype="TIMESTAMP"),
                    _field("request", cm.group(4), 3),
                    _field("status", cm.group(5), 4, ftype="INT"),
                    _field("bytes", cm.group(6), 5),
                ]
                sec["records"].append(
                    _record("access", cm.group(5), fields, start_line=i, text=ln)
                )
                kinds["clf"] += 1
            else:
                lvl = _LEVEL_RE.search(ln)
                fields = [_field("text", ln, 0)]
                if lvl:
                    fields.append(_field("level", lvl.group(1), 1))
                sec["records"].append(
                    _record(
                        "event",
                        lvl.group(1) if lvl else None,
                        fields,
                        start_line=i,
                        text=ln,
                    )
                )
                kinds["generic"] += 1
        n += 1
        if n >= _RECORD_BUDGET:
            break
    dominant = max(kinds, key=kinds.get) if n else "generic"
    return _profile(
        kind,
        fam,
        label,
        f"log_{dominant}",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[
            ("stats", "event_count", n),
            ("stats", "syslog_lines", kinds["syslog"]),
            ("stats", "access_lines", kinds["clf"]),
        ],
    )


# ===========================================================================
# ENGINE: subtitle  (time-cued captions -- SRT/VTT/SUB/IDX/SSA/TTML/PJS/...)
# ===========================================================================
_TIME_ARROW = re.compile(
    r"(\d{1,2}:\d{2}:\d{2}[.,]\d{1,3})\s*-->\s*(\d{1,2}:\d{2}:\d{2}[.,]\d{1,3})"
)
_IDX_RE = re.compile(
    r"^timestamp:\s*(\d{2}:\d{2}:\d{2}:\d{3}),\s*filepos:\s*([0-9a-fA-F]+)"
)
_PJS_RE = re.compile(r"^\s*(\d+)\s*,\s*(\d+)\s*,\s*[\"'](.*)[\"']\s*$")


def _e_subtitle(data: bytes, kind, fam, label, byte_size, ext) -> Dict[str, Any]:
    if _looks_binary(data):
        return _forensic(
            kind,
            fam,
            label,
            data,
            byte_size,
            "binary caption container (PGS/Matroska) -- forensic only",
            via="content",
        )
    text, encoding = _decode(data)
    lc = text.count("\n") + 1
    stripped = text.lstrip()
    # TTML / iTT (XML)
    if stripped[:1] == "<" and ("tt" in stripped[:64] or "<p" in text):
        sec = _section("(cues)", "caption", 1)
        try:
            root = ET.fromstring(text)
            order = 0
            for p in root.iter():
                if _localname(p.tag) == "p":
                    order += 1
                    begin = p.attrib.get("begin") or ""
                    end = p.attrib.get("end") or ""
                    txt = "".join(p.itertext()).strip()
                    fields = [
                        _field("begin", begin, 0, ftype="TIMESTAMP"),
                        _field("end", end, 1, ftype="TIMESTAMP"),
                        _field("text", txt, 2),
                    ]
                    sec["records"].append(
                        _record("cue", f"cue {order}", fields, text=txt)
                    )
            if sec["records"]:
                return _profile(
                    kind,
                    fam,
                    label,
                    "ttml",
                    sections=[sec],
                    detected_via="content",
                    byte_size=byte_size,
                    encoding=encoding,
                    line_count=lc,
                    properties=[("stats", "cue_count", order)],
                )
        except ET.ParseError:
            pass
    sec = _section("(cues)", "caption", 1)
    order = 0
    # SRT/VTT arrow-timed blocks
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        m = _TIME_ARROW.search(lines[i])
        if m:
            order += 1
            j = i + 1
            buf = []
            while j < len(lines) and lines[j].strip():
                buf.append(lines[j].strip())
                j += 1
            txt = " ".join(buf)
            fields = [
                _field("start", m.group(1), 0, ftype="TIMESTAMP"),
                _field("end", m.group(2), 1, ftype="TIMESTAMP"),
                _field("text", txt, 2),
            ]
            sec["records"].append(
                _record("cue", f"cue {order}", fields, start_line=i + 1, text=txt)
            )
            i = j
            continue
        im = _IDX_RE.match(lines[i].strip())
        if im:
            order += 1
            fields = [
                _field("timestamp", im.group(1), 0, ftype="TIMESTAMP"),
                _field("filepos", im.group(2), 1, ftype="HEX"),
            ]
            sec["records"].append(
                _record("index", f"entry {order}", fields, start_line=i + 1)
            )
            i += 1
            continue
        pm = _PJS_RE.match(lines[i])
        if pm:
            order += 1
            fields = [
                _field("start_frame", pm.group(1), 0, ftype="INT"),
                _field("end_frame", pm.group(2), 1, ftype="INT"),
                _field("text", pm.group(3), 2),
            ]
            sec["records"].append(
                _record(
                    "cue", f"cue {order}", fields, start_line=i + 1, text=pm.group(3)
                )
            )
            i += 1
            continue
        i += 1
    if not sec["records"]:
        return _from_lines(
            text, kind, fam, label, byte_size, encoding, lc, engine="subtitle_text"
        )
    return _profile(
        kind,
        fam,
        label,
        "subtitle",
        sections=[sec],
        detected_via="content",
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "cue_count", order)],
    )


# ===========================================================================
# ENGINE: roff / man / pod  (documentation macro languages)
# ===========================================================================
def _e_roff(text, kind, fam, label, byte_size, encoding, lc):
    lines = text.split("\n")
    # POD?
    if re.search(r"(?m)^=(head\d|pod|item|over|back|cut|encoding)\b", text):
        return _e_pod(text, kind, fam, label, byte_size, encoding, lc)
    sections: List[Dict[str, Any]] = []
    cur = _section("(preamble)", "man_section", 1)
    sections.append(cur)
    order = 1
    title = None
    for i, raw in enumerate(lines, start=1):
        ln = raw.rstrip()
        if ln.startswith(".TH"):
            parts = _roff_args(ln[3:])
            title = parts[0] if parts else None
            cur["records"].append(
                _record(
                    "title",
                    title,
                    [_field(f"arg{j+1}", p, j) for j, p in enumerate(parts)],
                    start_line=i,
                    text=ln,
                )
            )
        elif ln.startswith(".SH") or ln.startswith(".SS"):
            name = " ".join(_roff_args(ln[3:])) or f"section {order}"
            order += 1
            cur = _section(name, "man_section", order)
            sections.append(cur)
        elif ln.startswith("."):
            macro = ln.split()[0]
            cur["records"].append(
                _record(
                    "macro",
                    macro,
                    [
                        _field("macro", macro, 0),
                        _field("args", ln[len(macro) :].strip(), 1),
                    ],
                    start_line=i,
                    text=ln,
                )
            )
        elif ln.strip():
            cur["records"].append(
                _record(
                    "text",
                    None,
                    [_field("text", ln.strip(), 0)],
                    start_line=i,
                    text=ln.strip(),
                )
            )
    sections = [s for s in sections if s["records"]] or sections[:1]
    props = [("man", "title", title)] if title else []
    props.append(("stats", "section_count", len(sections)))
    return _profile(
        kind,
        fam,
        label,
        "roff",
        sections=sections,
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=props,
    )


def _roff_args(s: str) -> List[str]:
    return [a or b for a, b in re.findall(r'"([^"]*)"|(\S+)', s.strip())]


def _e_pod(text, kind, fam, label, byte_size, encoding, lc):
    sections: List[Dict[str, Any]] = []
    cur = _section("(pod)", "pod_section", 1)
    sections.append(cur)
    order = 1
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.rstrip()
        hm = re.match(r"^=(head\d|item|over|back|pod|cut|encoding)\b\s*(.*)$", ln)
        if hm:
            cmd, arg = hm.group(1), hm.group(2).strip()
            if cmd.startswith("head"):
                order += 1
                cur = _section(arg or f"head {order}", "pod_section", order)
                sections.append(cur)
            else:
                cur["records"].append(
                    _record(
                        cmd,
                        arg or None,
                        [_field("command", cmd, 0), _field("text", arg, 1)],
                        start_line=i,
                        text=ln,
                    )
                )
        elif ln.strip():
            cur["records"].append(
                _record(
                    "paragraph",
                    None,
                    [_field("text", ln.strip(), 0)],
                    start_line=i,
                    text=ln.strip(),
                )
            )
    sections = [s for s in sections if s["records"]] or sections[:1]
    return _profile(
        kind,
        fam,
        label,
        "pod",
        sections=sections,
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "section_count", len(sections))],
    )


# ===========================================================================
# ENGINE: doctext  (readme / authors / adr / markdown-ish heading documents)
# ===========================================================================
def _e_doctext(text, kind, fam, label, byte_size, encoding, lc):
    lines = text.split("\n")
    sections: List[Dict[str, Any]] = []
    cur = _section("(body)", "doc_section", 1)
    sections.append(cur)
    order = 1
    pending_para: List[str] = []
    pstart = 0

    def _flush_para(end_line: int):
        nonlocal pending_para  # pstart is only read here -> closure, no nonlocal
        if pending_para:
            txt = " ".join(pending_para).strip()
            if txt:
                cur["records"].append(
                    _record(
                        "paragraph",
                        None,
                        [_field("text", txt, 0)],
                        start_line=pstart,
                        end_line=end_line,
                        text=txt,
                    )
                )
        pending_para = []

    for i, raw in enumerate(lines, start=1):
        ln = raw.rstrip()
        hm = re.match(r"^(#{1,6})\s+(.*)$", ln)  # markdown ATX heading
        setext = (
            i < len(lines)
            and re.match(r"^(=+|-+)\s*$", lines[i].strip())
            and ln.strip()
        )
        if hm:
            _flush_para(i - 1)
            order += 1
            level = len(hm.group(1))
            cur = _section(hm.group(2).strip(), "doc_section", order)
            cur["records"].append(
                _record(
                    "heading",
                    hm.group(2).strip(),
                    [
                        _field("level", level, 0, ftype="INT"),
                        _field("title", hm.group(2).strip(), 1),
                    ],
                    start_line=i,
                )
            )
            sections.append(cur)
        elif setext:
            _flush_para(i - 1)
            order += 1
            cur = _section(ln.strip(), "doc_section", order)
            cur["records"].append(
                _record(
                    "heading",
                    ln.strip(),
                    [_field("title", ln.strip(), 0)],
                    start_line=i,
                )
            )
            sections.append(cur)
        elif ln.strip() == "":
            _flush_para(i - 1)
        else:
            if not pending_para:
                pstart = i
            pending_para.append(ln.strip())
    _flush_para(len(lines))
    sections = [s for s in sections if s["records"]] or sections[:1]
    words = len(text.split())
    return _profile(
        kind,
        fam,
        label,
        "doctext",
        sections=sections,
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[
            ("stats", "section_count", len(sections)),
            ("stats", "word_count", words),
        ],
    )


# ===========================================================================
# ENGINE: gherkin  (.feature)
# ===========================================================================
def _e_gherkin(text, kind, fam, label, byte_size, encoding, lc):
    sections: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    feature = None
    order = 0
    kw = re.compile(
        r"^\s*(Feature|Background|Scenario Outline|Scenario|Examples|Rule):\s*(.*)$"
    )
    step = re.compile(r"^\s*(Given|When|Then|And|But|\*)\s+(.*)$")
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.rstrip()
        km = kw.match(ln)
        if km:
            key, name = km.group(1), km.group(2).strip()
            if key == "Feature":
                feature = name
            order += 1
            cur = _section(
                f"{key}: {name}" if name else key, key.lower().replace(" ", "_"), order
            )
            cur["records"].append(
                _record(
                    key.lower().replace(" ", "_"),
                    name or key,
                    [_field(key.lower().replace(" ", "_"), name, 0)],
                    start_line=i,
                )
            )
            sections.append(cur)
            continue
        sm = step.match(ln)
        if sm and cur is not None:
            cur["records"].append(
                _record(
                    "step",
                    sm.group(1),
                    [
                        _field("keyword", sm.group(1), 0),
                        _field("text", sm.group(2).strip(), 1),
                    ],
                    start_line=i,
                    text=ln.strip(),
                )
            )
        elif ln.strip().startswith("|") and cur is not None:  # example table row
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            cur["records"].append(
                _record(
                    "table_row",
                    None,
                    [_field(f"col{j+1}", c, j) for j, c in enumerate(cells)],
                    start_line=i,
                    text=ln.strip(),
                )
            )
    if not sections:
        return _e_doctext(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "gherkin",
        sections=sections,
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=([("gherkin", "feature", feature)] if feature else [])
        + [("stats", "block_count", len(sections))],
    )


# ===========================================================================
# ENGINE: template  (delimiter-aware templating languages)
# ===========================================================================
_TMPL_PATTERNS = [
    ("expression", re.compile(r"\{\{-?\s*(.*?)\s*-?\}\}", re.S)),  # {{ }}
    ("statement", re.compile(r"\{%-?\s*(.*?)\s*-?%\}", re.S)),  # {% %}
    ("comment", re.compile(r"\{#\s*(.*?)\s*#\}", re.S)),  # {# #}
    (
        "scriptlet",
        re.compile(r"<%[-=@!]?\s*(.*?)\s*[-=]?%>", re.S),
    ),  # <% %> ERB/EJS/JSP
    ("razor", re.compile(r"@\{(.*?)\}", re.S)),  # @{ } Razor block
    ("autoconf", re.compile(r"@([A-Za-z_][A-Za-z0-9_]*)@")),  # @VAR@ .in
]
_TMPL_TAGKW = re.compile(r"^\s*(\w+)")


def _e_template(text, kind, fam, label, byte_size, encoding, lc):
    sec = _section("(directives)", "template", 1)
    counts: Dict[str, int] = {}
    hits: List[Tuple[int, str, str]] = []
    for ttype, pat in _TMPL_PATTERNS:
        for m in pat.finditer(text):
            hits.append((m.start(), ttype, m.group(1).strip()))
    hits.sort(key=lambda h: h[0])
    order = 0
    for pos, ttype, body in hits:
        order += 1
        line_no = text.count("\n", 0, pos) + 1
        kwm = _TMPL_TAGKW.match(body)
        directive = kwm.group(1) if (kwm and ttype == "statement") else ttype
        counts[directive] = counts.get(directive, 0) + 1
        fields = [
            _field("directive_kind", ttype, 0),
            _field("keyword", directive, 1),
            _field("body", body, 2),
        ]
        sec["records"].append(
            _record("directive", directive, fields, start_line=line_no, text=body)
        )
        if order >= _RECORD_BUDGET:
            break
    host = _template_host(label, text)
    props = [
        ("template", "host_language", host),
        ("template", "directive_total", order),
    ]
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:12]:
        props.append(("directive_counts", k, v))
    if not sec["records"]:
        # a template with no directives is still a valid (static) template file
        return _profile(
            kind,
            fam,
            label,
            "template",
            sections=[sec],
            byte_size=byte_size,
            encoding=encoding,
            line_count=lc,
            status="partial",
            properties=props,
            notes="no template directives found (static content)",
        )
    return _profile(
        kind,
        fam,
        label,
        "template",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=props,
    )


def _template_host(label: str, text: str) -> str:
    l = label.lower()
    if any(
        x in l
        for x in (
            "html",
            "haml",
            "pug",
            "jade",
            "slim",
            "twig",
            "liquid",
            "mustache",
            "handlebars",
            "jinja",
            "njk",
            "tera",
            "eta",
            "ejs",
        )
    ):
        return "html"
    if "php" in l or "<?php" in text:
        return "php"
    if any(x in l for x in ("erb", "rb")):
        return "ruby"
    if any(x in l for x in ("jsp", "cshtml", "vbhtml", "razor", "cfm")):
        return "jvm/dotnet"
    if l in ("in",):
        return "autoconf"
    return "text"


# ===========================================================================
# ENGINE: hashlist  (checksum manifests)
# ===========================================================================
_HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128, "crc": 8, "blake3": 64}


def _e_hashlist(text, kind, fam, label, byte_size, encoding, lc, algo: str):
    sec = _section("(digests)", "checksums", 1)
    exp = _HASH_LEN.get(algo)
    n = 0
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.strip()
        if not ln or ln.startswith((";", "#")):
            continue
        m = re.match(r"^([0-9a-fA-F]+)\s+[* ]?(.*)$", ln)
        if m:
            digest, fname = m.group(1), m.group(2).strip()
            fields = [
                _field("digest", digest, 0, ftype="HEX"),
                _field("filename", fname, 1),
                _field("digest_bits", len(digest) * 4, 2, ftype="INT"),
            ]
            if exp and len(digest) != exp:
                fields.append(_field("length_ok", "false", 3, ftype="BOOL"))
            sec["records"].append(
                _record("checksum", fname or digest[:16], fields, start_line=i)
            )
        else:
            m2 = re.match(
                r"^(\S.*?)\s*[:=]\s*([0-9a-fA-F]+)$", ln
            )  # BSD "NAME (f) = hash"
            if m2:
                sec["records"].append(
                    _record(
                        "checksum",
                        m2.group(1),
                        [
                            _field("filename", m2.group(1), 0),
                            _field("digest", m2.group(2), 1, ftype="HEX"),
                        ],
                        start_line=i,
                    )
                )
        n += 1
        if n >= _RECORD_BUDGET:
            break
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        f"{algo}sum",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[
            ("hash", "algorithm", algo),
            ("stats", "digest_count", len(sec["records"])),
        ],
    )


# ===========================================================================
# ENGINE: jwt  (decode header + payload; NEVER the signature)
# ===========================================================================
def _b64url(seg: str) -> Optional[bytes]:
    pad = "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg + pad)
    except (binascii.Error, ValueError):
        return None


def _e_jwt(text, kind, fam, label, byte_size, encoding, lc):
    token = text.strip().split()[0] if text.strip() else ""
    parts = token.split(".")
    sec = _section("(jwt)", "token", 1)
    if len(parts) != 3:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    hdr_b, pay_b, sig = parts
    props: List[Tuple] = [
        ("jwt", "signature", "<redacted>"),
        ("jwt", "signature_length", len(sig)),
    ]
    for name, seg in (("header", hdr_b), ("payload", pay_b)):
        raw = _b64url(seg)
        if raw is None:
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        fields = [_field(k, v, j) for j, (k, v) in enumerate(obj.items())]
        sec["records"].append(_record(name, name, fields))
        if name == "header":
            props.append(("jwt", "alg", obj.get("alg")))
            props.append(("jwt", "typ", obj.get("typ")))
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "jwt",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        status="ok",
        properties=props,
        notes="JWT header/payload decoded; signature redacted",
    )


# ===========================================================================
# ENGINE: encoded  (base64 / base85 / uuencode / rot13 -- decode-validate only)
# ===========================================================================
def _e_encoded(data: bytes, kind, fam, label, byte_size, ext):
    text, encoding = _decode(data)
    lc = text.count("\n") + 1
    sec = _section("(encoded)", "encoded", 1)
    scheme = {
        "b64": "base64",
        "b85": "base85",
        "uu": "uuencode",
        "uue": "uuencode",
        "rot13": "rot13",
        "mim": "mime",
    }.get(ext.lstrip("."), "base64")
    decoded_len: Optional[int] = None
    valid = False
    sniff = None
    try:
        body = "".join(text.split())
        if scheme == "base64":
            raw = base64.b64decode(body, validate=False)
            decoded_len, valid = len(raw), True
            sniff = _sniff_magic(raw)
        elif scheme == "base85":
            raw = base64.b85decode(body)
            decoded_len, valid = len(raw), True
            sniff = _sniff_magic(raw)
        elif scheme == "uuencode":
            import io
            import uu

            out = io.BytesIO()
            uu.decode(io.BytesIO(data), out, quiet=True)
            decoded_len, valid = out.tell(), True
            sniff = _sniff_magic(out.getvalue())
        elif scheme == "rot13":
            import codecs

            dec = codecs.decode(text, "rot_13")
            decoded_len, valid = len(dec), True
            sniff = "text"
    except Exception:
        valid = False
    fields = [
        _field("scheme", scheme, 0),
        _field("encoded_bytes", byte_size, 1, ftype="INT"),
        _field("decoded_valid", "true" if valid else "false", 2, ftype="BOOL"),
    ]
    if decoded_len is not None:
        fields.append(_field("decoded_bytes", decoded_len, 3, ftype="INT"))
    if sniff:
        fields.append(_field("decoded_sniff", sniff, 4))
    sec["records"].append(_record("payload", scheme, fields))
    return _profile(
        kind,
        fam,
        label,
        scheme,
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        status="ok" if valid else "partial",
        properties=[
            ("encoded", "scheme", scheme),
            ("encoded", "decoded_bytes", decoded_len),
        ],
        notes="decoded for validation; payload not stored",
    )


def _sniff_magic(b: bytes) -> str:
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if b[:4] == b"%PDF":
        return "pdf"
    if b[:2] == b"PK":
        return "zip"
    if b[:4] in (b"\x7fELF",):
        return "elf"
    if b[:2] == b"BM":
        return "bmp"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    try:
        b[:512].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary"


# ===========================================================================
# ENGINE: gcode  (CNC / 3D-print / printer command languages)
# ===========================================================================
_GCODE_RE = re.compile(r"([A-Za-z])\s*(-?\d+\.?\d*)")


def _e_gcode(text, kind, fam, label, byte_size, encoding, lc):
    sec = _section("(program)", "gcode", 1)
    n = 0
    codes: Dict[str, int] = {}
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.strip()
        if not ln or ln.startswith((";", "(")):
            continue
        # strip inline comments
        ln = re.sub(r";.*$", "", ln)
        ln = re.sub(r"\(.*?\)", "", ln).strip()
        if not ln:
            continue
        words = _GCODE_RE.findall(ln)
        if not words:
            # PJL / ESC-based printer control line
            sec["records"].append(
                _record(
                    "command",
                    ln.split()[0][:32],
                    [_field("text", ln, 0)],
                    start_line=i,
                    text=ln,
                )
            )
            n += 1
            continue
        cmd = words[0][0].upper() + words[0][1]
        codes[cmd] = codes.get(cmd, 0) + 1
        fields = [
            _field(f"{w[0].upper()}", w[1], j, ftype=_field_type(w[1]))
            for j, w in enumerate(words)
        ]
        sec["records"].append(_record("command", cmd, fields, start_line=i, text=ln))
        n += 1
        if n >= _RECORD_BUDGET:
            break
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    top = sorted(codes.items(), key=lambda kv: -kv[1])[:12]
    return _profile(
        kind,
        fam,
        label,
        "gcode",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("gcode", "command_count", n)]
        + [("command_counts", k, v) for k, v in top],
    )


# ===========================================================================
# ENGINE: nmap  (.nmap human / .gnmap grepable)
# ===========================================================================
def _e_nmap(text, kind, fam, label, byte_size, encoding, lc):
    sec = _section("(hosts)", "scan", 1)
    order = 0
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.strip()
        gm = re.match(r"^Host:\s*(\S+)\s*\(([^)]*)\)\s*(.*)$", ln)  # grepable
        if gm:
            order += 1
            ip, host, rest = gm.group(1), gm.group(2), gm.group(3)
            ports = re.findall(
                r"(\d+)/(open|closed|filtered)/(\w*)/?(?:/([^/,]*))?", rest
            )
            fields = [_field("ip", ip, 0), _field("hostname", host, 1)]
            for j, (p, state, proto, svc) in enumerate(ports[:64]):
                fields.append(
                    _field(f"port_{p}", f"{state}/{proto}/{svc}".strip("/"), 2 + j)
                )
            sec["records"].append(_record("host", ip, fields, start_line=i, text=ln))
            continue
        hm = re.match(r"^Nmap scan report for\s+(.*)$", ln)  # human
        if hm:
            order += 1
            sec["records"].append(
                _record(
                    "host",
                    hm.group(1).strip(),
                    [_field("target", hm.group(1).strip(), 0)],
                    start_line=i,
                    text=ln,
                )
            )
            continue
        pm = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$", ln)
        if pm and sec["records"]:
            sec["records"][-1]["fields"].append(
                _field(
                    f"{pm.group(1)}/{pm.group(2)}",
                    f"{pm.group(3)} {pm.group(4)}",
                    len(sec["records"][-1]["fields"]),
                )
            )
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "nmap",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "host_count", order)],
    )


# ===========================================================================
# ENGINE: httpreq  (.http / .rest / .bruno request collections)
# ===========================================================================
def _e_httpreq(text, kind, fam, label, byte_size, encoding, lc):
    blocks = re.split(r"(?m)^###.*$", text)
    sections: List[Dict[str, Any]] = []
    order = 0
    method_re = re.compile(
        r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)(?:\s+(HTTP/\d\.\d))?$"
    )
    for blk in blocks:
        lines = [l for l in blk.split("\n")]
        req_line = None
        headers: List[Dict[str, Any]] = []
        for li, ln in enumerate(lines):
            s = ln.strip()
            mm = method_re.match(s)
            if mm and req_line is None:
                req_line = (mm.group(1), mm.group(2))
                continue
            if req_line and ":" in s and s and not s.startswith("#"):
                k, v = s.split(":", 1)
                headers.append(_field(k.strip(), v.strip(), len(headers), key="header"))
            elif req_line and s == "":
                break
        if req_line:
            order += 1
            sec = _section(f"{req_line[0]} {req_line[1]}", "request", order)
            fields = [
                _field("method", req_line[0], 0),
                _field("url", req_line[1], 1),
            ] + headers
            sec["records"].append(
                _record("request", f"{req_line[0]} {req_line[1]}", fields)
            )
            sections.append(sec)
    if not sections:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "http_request",
        sections=sections,
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "request_count", order)],
    )


# ===========================================================================
# ENGINE: fen  (chess position records)
# ===========================================================================
_FEN_FIELDS = [
    "placement",
    "side_to_move",
    "castling",
    "en_passant",
    "halfmove_clock",
    "fullmove_number",
]


def _e_fen(text, kind, fam, label, byte_size, encoding, lc):
    sec = _section("(positions)", "fen", 1)
    order = 0
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.strip()
        if not ln or ln.startswith(("#", "[")):
            continue
        parts = ln.split()
        if len(parts) >= 4 and re.match(r"^[pnbrqkPNBRQK1-8/]+$", parts[0]):
            order += 1
            fields = [
                _field(_FEN_FIELDS[j] if j < len(_FEN_FIELDS) else f"f{j}", parts[j], j)
                for j in range(min(len(parts), 6))
            ]
            sec["records"].append(
                _record("position", f"position {order}", fields, start_line=i, text=ln)
            )
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "fen",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "position_count", order)],
    )


# ===========================================================================
# ENGINE: sparse_matrix  (.coo/.csc coordinate + Harwell-Boeing .rsa/.rua)
# ===========================================================================
def _e_sparse(text, kind, fam, label, byte_size, encoding, lc, ext):
    lines = [ln for ln in text.split("\n")]
    sec = _section("(matrix)", "sparse", 1)
    # MatrixMarket / coordinate?
    header = lines[0].strip() if lines else ""
    if header.startswith("%%MatrixMarket") or re.match(
        r"^\s*\d+\s+\d+\s+\d+\s*$", _first_data(lines)
    ):
        rows = cols = nnz = None
        n = 0
        for i, raw in enumerate(lines, start=1):
            ln = raw.strip()
            if not ln or ln.startswith("%"):
                continue
            nums = ln.split()
            if rows is None and len(nums) >= 2:
                rows = _int(nums[0])
                cols = _int(nums[1])
                nnz = _int(nums[2]) if len(nums) > 2 else None
                continue
            if len(nums) >= 2:
                fields = [
                    _field("row", nums[0], 0, ftype="INT"),
                    _field("col", nums[1], 1, ftype="INT"),
                ]
                if len(nums) > 2:
                    fields.append(_field("value", nums[2], 2))
                sec["records"].append(_record("entry", None, fields, start_line=i))
                n += 1
            if n >= _RECORD_BUDGET:
                break
        props = [
            ("matrix", "rows", rows),
            ("matrix", "cols", cols),
            ("matrix", "declared_nnz", nnz),
            ("stats", "entries_parsed", n),
        ]
        return _profile(
            kind,
            fam,
            label,
            "coordinate",
            sections=[sec],
            byte_size=byte_size,
            encoding=encoding,
            line_count=lc,
            properties=props,
        )
    # Harwell-Boeing (.rsa/.rua): 4-5 line header
    if ext.lstrip(".") in ("rsa", "rua") and len(lines) >= 4:
        title = lines[0][:72].strip()
        key = lines[0][72:].strip() if len(lines[0]) > 72 else ""
        counts = lines[1].split()
        mxtype = lines[2][:3].strip() if len(lines) > 2 else ""
        dims = lines[2][14:].split() if len(lines) > 2 else []
        fields = [
            _field("title", title, 0),
            _field("key", key, 1),
            _field("matrix_type", mxtype, 2),
        ]
        for j, d in enumerate(dims[:4]):
            fields.append(
                _field(
                    ["rows", "cols", "nonzeros", "rhs"][j] if j < 4 else f"d{j}",
                    d,
                    3 + j,
                    ftype="INT",
                )
            )
        sec["records"].append(_record("hb_header", title or key, fields, start_line=1))
        return _profile(
            kind,
            fam,
            label,
            "harwell_boeing",
            sections=[sec],
            byte_size=byte_size,
            encoding=encoding,
            line_count=lc,
            properties=[
                ("matrix", "format", "harwell-boeing"),
                ("matrix", "type", mxtype),
            ],
        )
    return _from_lines(text, kind, fam, label, byte_size, encoding, lc)


def _first_data(lines: List[str]) -> str:
    for ln in lines:
        if ln.strip() and not ln.strip().startswith("%"):
            return ln.strip()
    return ""


def _int(s: str) -> Optional[int]:
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


# ===========================================================================
# ENGINE: brainvision  (.vhdr / .vmrk -- INI-like EEG header & markers)
# ===========================================================================
def _e_brainvision(text, kind, fam, label, byte_size, encoding, lc):
    sections: List[Dict[str, Any]] = []
    cur = _section("(preamble)", "bv_section", 1)
    sections.append(cur)
    order = 1
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.strip()
        if not ln or ln.startswith(";"):
            continue
        m = re.match(r"^\[(.+?)\]$", ln)
        if m:
            order += 1
            cur = _section(m.group(1), "bv_section", order)
            sections.append(cur)
            continue
        if "=" in ln:
            k, v = ln.split("=", 1)
            # Marker lines: Mk<n>=type,desc,pos,size,chan
            if k.strip().lower().startswith("mk") and "," in v:
                parts = v.split(",")
                names = ["type", "description", "position", "size", "channel", "date"]
                fields = [
                    _field(names[j] if j < len(names) else f"f{j}", parts[j].strip(), j)
                    for j in range(len(parts))
                ]
                cur["records"].append(
                    _record("marker", k.strip(), fields, start_line=i)
                )
            else:
                cur["records"].append(
                    _record(
                        "property",
                        k.strip(),
                        [_field(k.strip(), v.strip(), 0)],
                        start_line=i,
                        text=ln,
                    )
                )
    sections = [s for s in sections if s["records"]] or sections[:1]
    return _profile(
        kind,
        fam,
        label,
        "brainvision",
        sections=sections,
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "section_count", len(sections))],
    )


# ===========================================================================
# ENGINE: rhistory  (.rhistory -- one R command per line)
# ===========================================================================
def _e_rhistory(text, kind, fam, label, byte_size, encoding, lc):
    sec = _section("(commands)", "history", 1)
    n = 0
    for i, raw in enumerate(text.split("\n"), start=1):
        ln = raw.rstrip()
        if ln.strip() == "":
            continue
        fields = [
            _field("command", ln.strip(), 0),
            _field("length", len(ln), 1, ftype="INT"),
        ]
        sec["records"].append(
            _record("command", None, fields, start_line=i, text=ln.strip())
        )
        n += 1
        if n >= _RECORD_BUDGET:
            break
    return _profile(
        kind,
        fam,
        label,
        "rhistory",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[("stats", "command_count", n)],
    )


# ===========================================================================
# ENGINE: graph_edges  (.graph -- adjacency / edge list, e.g. METIS/DIMACS)
# ===========================================================================
def _e_graph(text, kind, fam, label, byte_size, encoding, lc):
    lines = [ln for ln in text.split("\n")]
    sec = _section("(edges)", "graph", 1)
    header = _first_data(lines)
    hv = header.split()
    n_nodes = _int(hv[0]) if hv else None
    n_edges = _int(hv[1]) if len(hv) > 1 else None
    n = 0
    seen_header = False
    node = 0
    for i, raw in enumerate(lines, start=1):
        ln = raw.strip()
        if not ln or ln.startswith(("%", "#")):
            continue
        if not seen_header:
            seen_header = True
            continue
        node += 1
        neighbors = ln.split()
        fields = [
            _field("node", node, 0, ftype="INT"),
            _field("degree", len(neighbors), 1, ftype="INT"),
            _field("adjacency", " ".join(neighbors[:64]), 2),
        ]
        sec["records"].append(
            _record("adjacency", f"node {node}", fields, start_line=i)
        )
        n += 1
        if n >= _RECORD_BUDGET:
            break
    if not sec["records"]:
        return _from_lines(text, kind, fam, label, byte_size, encoding, lc)
    return _profile(
        kind,
        fam,
        label,
        "graph",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        properties=[
            ("graph", "declared_nodes", n_nodes),
            ("graph", "declared_edges", n_edges),
            ("stats", "adjacency_rows", n),
        ],
    )


# ===========================================================================
# ENGINE: marker  (presence-significant files, may hold small content)
# ===========================================================================
def _e_marker(text, kind, fam, label, byte_size, encoding, lc):
    content = text.strip()
    fields = [
        _field("present", "true", 0, ftype="BOOL"),
        _field("byte_size", byte_size, 1, ftype="INT"),
        _field("empty", "true" if not content else "false", 2, ftype="BOOL"),
    ]
    if content:
        fields.append(_field("content", content[:512], 3))
    sec = _section("(marker)", "marker", 1)
    sec["records"].append(_record("marker", label, fields))
    return _profile(
        kind,
        fam,
        label,
        "marker",
        sections=[sec],
        byte_size=byte_size,
        encoding=encoding,
        line_count=lc,
        notes="presence-significant marker file",
    )


# ===========================================================================
# REGISTRY  (ext -> (kind, family, label, engine_key))
# ===========================================================================
def _reg(
    mapping: Dict[str, Tuple[str, str, str, str]],
    exts,
    kind,
    family,
    engine,
    labels: Optional[Dict[str, str]] = None,
) -> None:
    for e in exts:
        lbl = (labels or {}).get(e) or e.lstrip(".").upper()
        mapping[e] = (kind, family, lbl, engine)


_TEXT_REGISTRY: Dict[str, Tuple[str, str, str, str]] = {}

# ---- subtitle (7) ----
_reg(
    _TEXT_REGISTRY,
    [".idx", ".itt", ".pjs", ".ssf", ".dks", ".sup", ".mks"],
    "subtitle",
    "caption",
    "subtitle",
    labels={
        ".idx": "VobSub Index",
        ".itt": "iTunes Timed Text",
        ".pjs": "Phoenix Subtitle",
        ".ssf": "Structured Subtitle Format",
        ".dks": "DKS Subtitle",
        ".sup": "PGS/HDMV Subtitle (binary)",
        ".mks": "Matroska Subtitle (binary)",
    },
)

# ---- scientific_data (8) ----
_reg(
    _TEXT_REGISTRY,
    [".coo", ".csc"],
    "scientific_data",
    "sparse_matrix",
    "sparse",
    labels={".coo": "Coordinate Sparse Matrix", ".csc": "Compressed Sparse Column"},
)
_reg(
    _TEXT_REGISTRY,
    [".rsa", ".rua"],
    "scientific_data",
    "sparse_matrix",
    "sparse",
    labels={
        ".rsa": "Harwell-Boeing (real symmetric)",
        ".rua": "Harwell-Boeing (real unsymmetric)",
    },
)
_reg(
    _TEXT_REGISTRY,
    [".graph"],
    "scientific_data",
    "graph",
    "graph",
    labels={".graph": "Graph Adjacency/Edge List"},
)
_reg(
    _TEXT_REGISTRY,
    [".rhistory"],
    "scientific_data",
    "history",
    "rhistory",
    labels={".rhistory": "R Command History"},
)
_reg(
    _TEXT_REGISTRY,
    [".vhdr", ".vmrk"],
    "scientific_data",
    "eeg",
    "brainvision",
    labels={".vhdr": "BrainVision Header", ".vmrk": "BrainVision Markers"},
)

# ---- documentation (18) ----
_reg(
    _TEXT_REGISTRY,
    [".1", ".5", ".8", ".man", ".me", ".roff"],
    "documentation",
    "roff",
    "roff",
    labels={
        ".1": "man page (section 1)",
        ".5": "man page (section 5)",
        ".8": "man page (section 8)",
        ".man": "man page",
        ".me": "roff (me macros)",
        ".roff": "roff document",
    },
)
_reg(
    _TEXT_REGISTRY,
    [".pod"],
    "documentation",
    "pod",
    "roff",
    labels={".pod": "Perl POD"},
)
_reg(
    _TEXT_REGISTRY,
    [".readme", ".authors", ".adr", ".skill", ".dox", ".javadoc", ".rdoc"],
    "documentation",
    "doc",
    "doctext",
    labels={
        ".readme": "README",
        ".authors": "AUTHORS",
        ".adr": "Arch Decision Record",
        ".skill": "Skill Document",
        ".dox": "Doxygen Page",
        ".javadoc": "Javadoc",
        ".rdoc": "RDoc",
    },
)
_reg(
    _TEXT_REGISTRY,
    [".feature"],
    "documentation",
    "gherkin",
    "gherkin",
    labels={".feature": "Gherkin Feature"},
)
_reg(
    _TEXT_REGISTRY,
    [".chm", ".hlp", ".hbk"],
    "documentation",
    "help",
    "binary_help",
    labels={
        ".chm": "Compiled HTML Help (binary)",
        ".hlp": "WinHelp (binary)",
        ".hbk": "Help Book (binary)",
    },
)

# ---- template (27) ----
_reg(
    _TEXT_REGISTRY,
    [
        ".cfm",
        ".cshtml",
        ".ejs",
        ".epp",
        ".erb",
        ".eta",
        ".gohtml",
        ".haml",
        ".handlebars",
        ".in",
        ".j2",
        ".jade",
        ".jinja",
        ".jinja2",
        ".jsp",
        ".jspx",
        ".liquid",
        ".mustache",
        ".njk",
        ".phtml",
        ".pug",
        ".razor",
        ".slim",
        ".tera",
        ".tmpl",
        ".twig",
        ".vbhtml",
    ],
    "template",
    "template",
    "template",
    labels={
        ".cfm": "ColdFusion",
        ".cshtml": "Razor (C#)",
        ".ejs": "EJS",
        ".epp": "Puppet EPP",
        ".erb": "ERB",
        ".eta": "Eta",
        ".gohtml": "Go html/template",
        ".haml": "Haml",
        ".handlebars": "Handlebars",
        ".in": "Autoconf template",
        ".j2": "Jinja2",
        ".jade": "Jade",
        ".jinja": "Jinja",
        ".jinja2": "Jinja2",
        ".jsp": "JSP",
        ".jspx": "JSP XML",
        ".liquid": "Liquid",
        ".mustache": "Mustache",
        ".njk": "Nunjucks",
        ".phtml": "PHP template",
        ".pug": "Pug",
        ".razor": "Razor",
        ".slim": "Slim",
        ".tera": "Tera",
        ".tmpl": "Generic template",
        ".twig": "Twig",
        ".vbhtml": "Razor (VB)",
    },
)

# ---- log (31) ----  (engine content-sniffs; binary telemetry -> forensic)
_reg(
    _TEXT_REGISTRY,
    [
        ".a429",
        ".acmi",
        ".aof",
        ".archivelog",
        ".bag",
        ".binlog",
        ".blf",
        ".chatlog",
        ".chrome-trace",
        ".clf",
        ".crash",
        ".dlt",
        ".err",
        ".etl",
        ".irc",
        ".ldf",
        ".mcap",
        ".oplog",
        ".otr",
        ".raft",
        ".redo",
        ".relaylog",
        ".syslog",
        ".sysout",
        ".tfevents",
        ".tlg",
        ".tlog",
        ".ulg",
        ".w3c",
        ".wal",
        ".wandb",
    ],
    "log",
    "log",
    "log",
    labels={
        ".a429": "ARINC-429 Log",
        ".acmi": "Tacview ACMI",
        ".aof": "Redis AOF",
        ".archivelog": "Archive Log",
        ".bag": "ROS Bag (binary)",
        ".binlog": "MSBuild Binary Log",
        ".blf": "Vector BLF (binary)",
        ".chatlog": "Chat Log",
        ".chrome-trace": "Chrome Trace",
        ".clf": "Common Log Format",
        ".crash": "Crash Report",
        ".dlt": "AUTOSAR DLT",
        ".err": "Error Log",
        ".etl": "Event Trace Log",
        ".irc": "IRC Log",
        ".ldf": "Transaction/LIN Log",
        ".mcap": "MCAP (binary)",
        ".oplog": "MongoDB Oplog",
        ".otr": "OTR Log",
        ".raft": "Raft Log",
        ".redo": "Redo Log",
        ".relaylog": "MySQL Relay Log",
        ".syslog": "Syslog",
        ".sysout": "System Output",
        ".tfevents": "TensorBoard Events (binary)",
        ".tlg": "Transaction Log",
        ".tlog": "MSBuild Tracker Log",
        ".ulg": "PX4 ULog (binary)",
        ".w3c": "W3C Extended Log",
        ".wal": "Write-Ahead Log",
        ".wandb": "Weights&Biases Log (binary)",
    },
)

# ---- text (58) ----
_reg(
    _TEXT_REGISTRY,
    [".md5", ".sha1", ".sha256", ".sha512", ".crc", ".blake3"],
    "text",
    "checksum",
    "hashlist",
    labels={
        ".md5": "MD5 Checksums",
        ".sha1": "SHA-1 Checksums",
        ".sha256": "SHA-256 Checksums",
        ".sha512": "SHA-512 Checksums",
        ".crc": "CRC Checksums",
        ".blake3": "BLAKE3 Checksums",
    },
)
_reg(
    _TEXT_REGISTRY, [".jwt"], "text", "token", "jwt", labels={".jwt": "JSON Web Token"}
)
_reg(
    _TEXT_REGISTRY,
    [".b64", ".b85", ".uu", ".uue", ".rot13", ".mim"],
    "text",
    "encoded",
    "encoded",
    labels={
        ".b64": "Base64",
        ".b85": "Base85",
        ".uu": "uuencode",
        ".uue": "uuencode",
        ".rot13": "ROT13",
        ".mim": "MIME encoded",
    },
)
_reg(
    _TEXT_REGISTRY,
    [
        ".gcode",
        ".gco",
        ".cnc",
        ".nc1",
        ".eia",
        ".hpgl",
        ".pjl",
        ".mpf",
        ".dpl",
        ".epl",
        ".apt",
    ],
    "text",
    "machine_control",
    "gcode",
    labels={
        ".gcode": "G-code",
        ".gco": "G-code",
        ".cnc": "CNC Program",
        ".nc1": "NC1 (DSTV)",
        ".eia": "EIA RS-274",
        ".hpgl": "HP-GL Plotter",
        ".pjl": "HP PJL",
        ".mpf": "Sinumerik Main Program",
        ".dpl": "Datamax DPL",
        ".epl": "Eltron EPL",
        ".apt": "APT CNC",
    },
)
_reg(
    _TEXT_REGISTRY,
    [".nmap", ".gnmap"],
    "text",
    "scan",
    "nmap",
    labels={".nmap": "Nmap Output", ".gnmap": "Nmap Grepable"},
)
_reg(
    _TEXT_REGISTRY,
    [".http", ".rest", ".bruno"],
    "text",
    "http",
    "httpreq",
    labels={".http": "HTTP Request", ".rest": "REST Client", ".bruno": "Bruno Request"},
)
_reg(
    _TEXT_REGISTRY,
    [".fen"],
    "text",
    "chess",
    "fen",
    labels={".fen": "FEN Chess Position"},
)
_reg(
    _TEXT_REGISTRY,
    [
        ".flag",
        ".keep",
        ".gitkeep",
        ".lock",
        ".ok",
        ".pid",
        ".placeholder",
        ".semaphore",
        ".trigger",
        ".done",
    ],
    "text",
    "marker",
    "marker",
    labels={
        ".flag": "Flag Marker",
        ".keep": "Keep Marker",
        ".gitkeep": "Git Keep",
        ".lock": "Lock File",
        ".ok": "OK Marker",
        ".pid": "PID File",
        ".placeholder": "Placeholder",
        ".semaphore": "Semaphore",
        ".trigger": "Trigger Marker",
        ".done": "Done Marker",
    },
)
_reg(
    _TEXT_REGISTRY,
    [
        ".abc",
        ".acme",
        ".apt",
        ".brf",
        ".cname",
        ".edl",
        ".f06",
        ".finger",
        ".gcov",
        ".lcov",
        ".gopher",
        ".ind",
        ".iptc7901",
        ".lst",
        ".magnet",
        ".note",
        ".outcar",
        ".prompt",
        ".todo",
    ],
    "text",
    "text",
    "auto",
    labels={
        ".abc": "ABC Music Notation",
        ".acme": "ACME Source",
        ".brf": "Braille Ready Format",
        ".cname": "DNS CNAME",
        ".edl": "Edit Decision List",
        ".f06": "Nastran F06 Output",
        ".finger": "Finger Plan",
        ".gcov": "gcov Coverage",
        ".lcov": "LCOV Coverage",
        ".gopher": "Gopher Menu",
        ".ind": "Index",
        ".iptc7901": "IPTC 7901 Wire",
        ".lst": "Listing",
        ".magnet": "Magnet URI",
        ".note": "Note",
        ".outcar": "VASP OUTCAR",
        ".prompt": "Prompt",
        ".todo": "TODO List",
    },
)

# ---- data_text (259) ----
_DT_TAGVALUE = {
    ".ris": "RIS Bibliography",
    ".nbib": "PubMed NBIB",
    ".enw": "EndNote",
    ".nbi": "NBI Bibliography",
    ".bibtex": "BibTeX",
}
_reg(
    _TEXT_REGISTRY,
    [".ris", ".nbib", ".enw", ".nbi"],
    "data_text",
    "bibliographic",
    "tagvalue",
    labels=_DT_TAGVALUE,
)
_reg(
    _TEXT_REGISTRY,
    [".bibtex"],
    "data_text",
    "bibliographic",
    "bibtex",
    labels=_DT_TAGVALUE,
)
_reg(
    _TEXT_REGISTRY,
    [".ledger", ".beancount"],
    "data_text",
    "accounting",
    "ledger",
    labels={".ledger": "Ledger Journal", ".beancount": "Beancount"},
)
_reg(
    _TEXT_REGISTRY,
    [".fix"],
    "data_text",
    "financial",
    "fix",
    labels={".fix": "FIX Protocol"},
)
_reg(
    _TEXT_REGISTRY,
    [".edi820", ".835", ".837"],
    "data_text",
    "edi",
    "edi",
    labels={
        ".edi820": "X12 820 Remittance",
        ".835": "X12 835 Payment",
        ".837": "X12 837 Claim",
    },
)
_reg(
    _TEXT_REGISTRY,
    [".edn", ".ron", ".sexp", ".edif"],
    "data_text",
    "sexpr",
    "sexpr",
    labels={
        ".edn": "EDN",
        ".ron": "Rusty Object Notation",
        ".sexp": "S-expression",
        ".edif": "EDIF Netlist",
    },
)
_reg(
    _TEXT_REGISTRY,
    [".fwf", ".fixed", ".efw2", ".fnma", ".hcm"],
    "data_text",
    "fixed_width",
    "fixedwidth",
    labels={
        ".fwf": "Fixed-Width Fields",
        ".fixed": "Fixed-Width",
        ".efw2": "SSA EFW2 Wage",
        ".fnma": "Fannie Mae 1003",
        ".hcm": "HCM Fixed",
    },
)

# All remaining data_text extensions -> content-sniffing `auto` engine.
_DATA_TEXT_AUTO = [
    ".1pif",
    ".3dl",
    ".835b",
    ".a2l",
    ".adjlist",
    ".adm",
    ".adsb",
    ".agdata",
    ".agent",
    ".ags",
    ".agsi",
    ".al3",
    ".ale",
    ".allure",
    ".amundsen",
    ".ann",
    ".apm",
    ".apple-app-site-association",
    ".arb",
    ".arm",
    ".arpa",
    ".arpt",
    ".asn",
    ".astm",
    ".atlas",
    ".atp",
    ".bad",
    ".bai2",
    ".barcode",
    ".bdf",
    ".blm",
    ".blp",
    ".body",
    ".bold",
    ".bom",
    ".braket",
    ".bsdl",
    ".bval",
    ".bvec",
    ".bvh",
    ".camx",
    ".catapult",
    ".cdc",
    ".cdl",
    ".cef",
    ".cfn",
    ".cgats",
    ".cha",
    ".cifp",
    ".cis2",
    ".cli",
    ".clm",
    ".cnv",
    ".comfyworkflow",
    ".conll",
    ".conllu",
    ".cookie",
    ".cp",
    ".cpuprofile",
    ".crm",
    ".ctd",
    ".cuckoo",
    ".cve",
    ".cyclonedx",
    ".cyjs",
    ".cypher",
    ".data",
    ".dhis2",
    ".dict",
    ".discord",
    ".droid",
    ".dsl",
    ".dwc",
    ".ean",
    ".ecsv",
    ".efw2b",
    ".eval",
    ".exif",
    ".fb",
    ".fhir",
    ".fixed2",
    ".flamegraph",
    ".fms",
    ".fpl",
    ".ga",
    ".gbrjob",
    ".ge",
    ".gfp",
    ".graphson",
    ".gs1",
    ".gsas",
    ".gslib",
    ".gsrs",
    ".gtm",
    ".hea",
    ".heapsnapshot",
    ".hepmc",
    ".hkl",
    ".hrm",
    ".hsts",
    ".i2b2",
    ".ibs",
    ".iif",
    ".iiif",
    ".importmap",
    ".influx",
    ".insomnia",
    ".intoto",
    ".invoke",
    ".iob",
    ".ipac",
    ".iptc",
    ".itx",
    ".lbl",
    ".ldt",
    ".lef",
    ".lex",
    ".lfp",
    ".lhe",
    ".lis",
    ".lnkparse",
    ".mailmerge",
    ".mapping",
    ".matter",
    ".mcp",
    ".mesh",
    ".mga",
    ".mie",
    ".misp",
    ".mls",
    ".moses",
    ".mpx",
    ".mqtt",
    ".mrc",
    ".mt940",
    ".mt942",
    ".n8n",
    ".nas",
    ".nft",
    ".ninjs",
    ".notam",
    ".oem",
    ".ohlc",
    ".omm",
    ".omop",
    ".openlineage",
    ".opt",
    ".orb",
    ".osv",
    ".otio",
    ".paj",
    ".pajek",
    ".payroll",
    ".pcf",
    ".pfa",
    ".pln",
    ".pnp",
    ".poct",
    ".postman_collection",
    ".prefab",
    ".prefetchdump",
    ".prom",
    ".provenance",
    ".psse",
    ".qbo",
    ".qcircuit",
    ".qfx",
    ".qif",
    ".qobj",
    ".qr",
    ".redcap",
    ".reso",
    ".retention",
    ".rics",
    ".rtl433",
    ".rvl",
    ".s2p",
    ".s4p",
    ".sarif",
    ".sbom",
    ".scim",
    ".sdnf",
    ".segment",
    ".senml",
    ".seq",
    ".side",
    ".sigmf",
    ".singer",
    ".skd",
    ".slack",
    ".snippets",
    ".snp",
    ".spdx",
    ".spef",
    ".spi1d",
    ".spi3d",
    ".stanag",
    ".stil",
    ".stix",
    ".str",
    ".svf",
    ".synctex",
    ".taxii",
    ".taxonomy",
    ".td",
    ".teams",
    ".textgrid",
    ".tfstate",
    ".ti3",
    ".tick",
    ".tiktoken",
    ".tle",
    ".tokenizer",
    ".trace",
    ".trc",
    ".tres",
    ".tscn",
    ".ucm",
    ".var",
    ".vcd",
    ".vdp",
    ".vercel",
    ".vex",
    ".vlt",
    ".vs",
    ".wasmmap",
    ".waypoints",
    ".well-known",
    ".wellknown",
    ".wgl",
    ".wpt",
    ".xapi",
    ".xer",
    ".xero",
    ".xmp",
    ".xpo",
    ".xrite",
    ".yy",
    ".zap-config",
    ".zcl",
    ".cookie",
    ".droid",
    ".prefab",
    ".tres",
    ".tscn",
    ".pnp",
    ".mga",
    ".ohlc",
]
_reg(
    _TEXT_REGISTRY, sorted(set(_DATA_TEXT_AUTO)), "data_text", "structured_text", "auto"
)

# domain data_text with a self-describing header the `auto` sniffer resolves
# (EnergyPlus weather = named header lines + CSV data rows; ergometer workout =
# bracketed [COURSE HEADER]/[COURSE DATA] INI-style sections).
_reg(
    _TEXT_REGISTRY,
    [".epw"],
    "data_text",
    "weather",
    "auto",
    labels={".epw": "EnergyPlus Weather Data"},
)
_reg(
    _TEXT_REGISTRY,
    [".erg"],
    "data_text",
    "workout",
    "auto",
    labels={".erg": "Ergometer Workout File"},
)

# a handful of financial/SWIFT data_text with recognizable line structure
_reg(
    _TEXT_REGISTRY,
    [".mt940", ".mt942", ".qif", ".bai2"],
    "data_text",
    "financial",
    "tagvalue",
    labels={
        ".mt940": "SWIFT MT940",
        ".mt942": "SWIFT MT942",
        ".qif": "Quicken QIF",
        ".bai2": "BAI2 Cash",
    },
)


# ===========================================================================
# public API
# ===========================================================================
def known_exts() -> frozenset:
    return frozenset(_TEXT_REGISTRY)


def routing_suffixes() -> Tuple[str, ...]:
    return tuple(sorted(_TEXT_REGISTRY))


def kind_for(ext: str) -> Optional[str]:
    hit = _TEXT_REGISTRY.get((ext or "").lower())
    return hit[0] if hit else None


def family_for(ext: str) -> Optional[str]:
    hit = _TEXT_REGISTRY.get((ext or "").lower())
    return hit[1] if hit else None


# engines that take raw bytes (they content-sniff / may go forensic)
_BYTE_ENGINES = {"log", "subtitle", "encoded"}


def analyze(path: Path, ext: str) -> Dict[str, Any]:
    ext = (ext or "").lower()
    kind, fam, label, engine = _TEXT_REGISTRY.get(
        ext, ("text", "text", ext.lstrip(".") or "text", "auto")
    )
    data, truncated = _read_bytes(path)
    byte_size = len(data)
    if byte_size == 0:
        # a zero-byte marker is meaningful; everything else is an honest empty
        if engine == "marker":
            return _e_marker("", kind, fam, label, 0, "utf-8", 1)
        return _empty(kind, fam, label, 0)

    # byte-level engines decide binary/forensic themselves
    if engine in _BYTE_ENGINES:
        if engine == "log":
            prof = _e_log(data, kind, fam, label, byte_size, ext)
        elif engine == "subtitle":
            prof = _e_subtitle(data, kind, fam, label, byte_size, ext)
        else:
            prof = _e_encoded(data, kind, fam, label, byte_size, ext)
        if truncated:
            prof["notes"] = (prof.get("notes", "") + "; input truncated at cap").strip(
                "; "
            )
        return prof

    # inherently-binary documentation/log containers -> honest forensic
    if engine == "binary_help" or (_looks_binary(data) and engine not in ("marker",)):
        return _forensic(
            kind,
            fam,
            label,
            data,
            byte_size,
            f"{label}: binary payload -- forensic profile only",
            via="content",
        )

    text, encoding = _decode(data)
    lc = text.count("\n") + 1

    dispatch = {
        "auto": lambda: _e_auto(text, kind, fam, label, byte_size, encoding, lc),
        "tagvalue": lambda: _e_tagvalue(
            text, kind, fam, label, byte_size, encoding, lc
        ),
        "bibtex": lambda: _e_bibtex(text, kind, fam, label, byte_size, encoding, lc),
        "ledger": lambda: _e_ledger(text, kind, fam, label, byte_size, encoding, lc),
        "sexpr": lambda: _e_sexpr(text, kind, fam, label, byte_size, encoding, lc),
        "fixedwidth": lambda: _e_fixedwidth(
            text, kind, fam, label, byte_size, encoding, lc
        ),
        "fix": lambda: _e_fix(text, kind, fam, label, byte_size, encoding, lc),
        "edi": lambda: _e_edi(text, kind, fam, label, byte_size, encoding, lc),
        "roff": lambda: _e_roff(text, kind, fam, label, byte_size, encoding, lc),
        "gherkin": lambda: _e_gherkin(text, kind, fam, label, byte_size, encoding, lc),
        "doctext": lambda: _e_doctext(text, kind, fam, label, byte_size, encoding, lc),
        "template": lambda: _e_template(
            text, kind, fam, label, byte_size, encoding, lc
        ),
        "hashlist": lambda: _e_hashlist(
            text, kind, fam, label, byte_size, encoding, lc, ext.lstrip(".")
        ),
        "jwt": lambda: _e_jwt(text, kind, fam, label, byte_size, encoding, lc),
        "gcode": lambda: _e_gcode(text, kind, fam, label, byte_size, encoding, lc),
        "nmap": lambda: _e_nmap(text, kind, fam, label, byte_size, encoding, lc),
        "httpreq": lambda: _e_httpreq(text, kind, fam, label, byte_size, encoding, lc),
        "fen": lambda: _e_fen(text, kind, fam, label, byte_size, encoding, lc),
        "sparse": lambda: _e_sparse(
            text, kind, fam, label, byte_size, encoding, lc, ext
        ),
        "brainvision": lambda: _e_brainvision(
            text, kind, fam, label, byte_size, encoding, lc
        ),
        "rhistory": lambda: _e_rhistory(
            text, kind, fam, label, byte_size, encoding, lc
        ),
        "graph": lambda: _e_graph(text, kind, fam, label, byte_size, encoding, lc),
        "marker": lambda: _e_marker(text, kind, fam, label, byte_size, encoding, lc),
    }
    fn = dispatch.get(engine, dispatch["auto"])
    try:
        prof = fn()
    except Exception as err:  # never fabricate on failure
        prof = _profile(
            kind,
            fam,
            label,
            engine,
            sections=[],
            status="partial",
            byte_size=byte_size,
            encoding=encoding,
            line_count=lc,
            notes=f"parse error ({type(err).__name__}: {err}); "
            f"no records fabricated",
        )
    if truncated:
        prof["notes"] = (prof.get("notes", "") + "; input truncated at cap").strip("; ")
    return prof
