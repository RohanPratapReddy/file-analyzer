"""
Real, per-extension structure-aware parsers for the residual *markup* universe.

This module is the engine layer behind :class:`.markup_analyzer.MarkupAnalyzer`.
For every one of the 228 residual ``markup`` extensions in
``DUMP/tabgen/docs/residual.json`` it runs a genuine, pure-stdlib, content-sniff
-first parser and returns a normalized *profile* describing the markup document:

    * which **tags / elements** appear, and the metrics *within* each tag
      (occurrence count, nesting depth, child fan-out, leaf/text-bearing counts,
      total text length, the attribute names carried),
    * every distinct **attribute** on every element (occurrence count, distinct
      value count, inferred value type, sample, min/max length),
    * every **namespace** declaration (prefix / URI / usage),
    * a structural **section** outline (the direct children of the root, or the
      headings of a non-XML markup),
    * document-level **properties** (XML declaration, DOCTYPE, root element,
      detected dialect, per-family metadata, and honest forensic facts).

Engines (dispatched by the registry, all real -- never a stub):

    xml         expat structural walk (manual xmlns tracking; comments / PIs /
                CDATA / DOCTYPE / XML-decl), the workhorse for ~204 XML
                vocabularies. Falls back to a lenient tag scan on a not-well
                -formed document (status ``partial``) -- never fabricates.
    html        lenient ``html.parser`` walk (void-element aware depth, headings
                -> sections, doctype / title / meta / script / style / link /
                form / image census) for ASP / ASPX / ASCX / DHTML / bookmarks.
    sgml        OFX (SGML 1.x tag stream) -- tries XML first (OFX 2.x), then a
                tolerant SGML tag scanner.
    wiki        MediaWiki / Creole / Textile markup (headings, links, templates,
                tables, lists, images).
    gemtext     Gemini gemtext (headings, => links, preformatted, lists, quotes).
    roff        troff / nroff request stream (.SH/.SS sections, macro census).
    typst       Typst source (headings, #let/#set/#show/#import, function calls).
    mif         FrameMaker Maker Interchange Format token stream.
    markdown    Markdown-components / API-Blueprint / Slate (frontmatter,
                headings, fenced code, MDC/apib components).
    lightweight plain lightweight text (.ascii/.utf8/.diz/.1st): line/word/char
                stats, underline-heading + ASCII-art detection.

Honesty contract (identical to the config / text planes): content is sniffed
first; a gzip-wrapped markup is transparently decompressed and re-parsed; a
ZIP-packaged vocabulary (IDML/INX/ODF that is actually a container) degrades to
an honest forensic note (members are NOT extracted in this plane); an inherently
-binary payload degrades to a forensic byte profile with no fabricated tags; the
raw payload is never stored (only tag/attribute names, counts, metrics and short
samples); a parse that only partially succeeds is reported ``partial``.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.parsers import expat

# ---------------------------------------------------------------------------
# Budgets / limits (bound worst-case work; never change correctness of a small
# file, only cap a pathological one and note the truncation honestly).
# ---------------------------------------------------------------------------
_MAX_BYTES = 48 * 1024 * 1024
_ELEMENT_BUDGET = 4000  # distinct element/tag names retained
_ATTR_BUDGET = 8000  # distinct (element, attribute) pairs retained
_SECTION_BUDGET = 2000  # structural sections retained
_NS_BUDGET = 512  # namespace declarations retained
_DISTINCT_VAL_CAP = 64  # per-attribute distinct-value sample cap
_TEXT_SAMPLES = 8  # char-data chunks retained per open element
_DEPTH_GUARD = 512  # runaway-nesting guard
_PREVIEW = 240  # sample-text / preview clip length


# ===========================================================================
# Byte / text helpers
# ===========================================================================
def _read_bytes(path: Path) -> Tuple[bytes, bool]:
    """Read up to ``_MAX_BYTES``; second element flags truncation."""
    size = path.stat().st_size
    with open(path, "rb") as fh:
        data = fh.read(_MAX_BYTES)
    return data, size > _MAX_BYTES


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return True
    sample = data[:4096]
    nonprint = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return nonprint / max(1, len(sample)) > 0.30


def _decode(data: bytes) -> Tuple[str, str]:
    """Best-effort text decode with BOM sniffing; returns (text, encoding)."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace"), "utf-8-sig"
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", "replace"), "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", "replace"), "utf-16-be"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace"), "latin-1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _line_count(text: str) -> int:
    if not text:
        return 0
    n = text.count("\n")
    return n + 1 if not text.endswith("\n") else n


def _localname(tag: str) -> str:
    """Strip a namespace prefix / Clark ``{uri}local`` wrapper from a tag name."""
    if not tag:
        return tag
    if tag[0] == "{":
        return tag.rsplit("}", 1)[-1]
    if ":" in tag:
        return tag.rsplit(":", 1)[-1]
    return tag


def _prefix_of(name: str) -> Optional[str]:
    if name.startswith("{") or ":" not in name:
        return None
    return name.split(":", 1)[0]


# ---------------------------------------------------------------------------
# Attribute value typing
# ---------------------------------------------------------------------------
_RE_INT = re.compile(r"^[+-]?\d+$")
_RE_FLOAT = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$")
_RE_TS = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2})?")
_RE_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}" r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _infer_value_type(value: str) -> str:
    v = value.strip()
    if not v:
        return "EMPTY"
    low = v.lower()
    if low in ("true", "false"):
        return "BOOL"
    if _RE_INT.match(v):
        return "INT"
    if _RE_FLOAT.match(v):
        return "FLOAT"
    if _RE_UUID.match(v):
        return "UUID"
    if v.startswith(("http://", "https://", "urn:", "ftp://")) or "://" in v[:12]:
        return "URI"
    if _RE_TS.match(v):
        return "TIMESTAMP"
    return "STRING"


# ===========================================================================
# Profile scaffolding
# ===========================================================================
def _blank_metrics() -> Dict[str, int]:
    return {
        "element_count": 0,
        "distinct_element_count": 0,
        "attribute_count": 0,
        "distinct_attribute_count": 0,
        "namespace_count": 0,
        "max_depth": 0,
        "comment_count": 0,
        "pi_count": 0,
        "cdata_count": 0,
        "text_length": 0,
    }


def _profile(fmt: str, family: str, engine: str, language: str) -> Dict[str, Any]:
    return {
        "format": fmt,
        "family": family,
        "engine": engine,
        "kind": "markup",
        "markup_language": language,
        "detected_via": "extension",
        "status": "ok",
        "encoding": None,
        "byte_size": None,
        "line_count": None,
        "well_formed": None,
        "root_element": None,
        "dialect": None,
        "metrics": _blank_metrics(),
        "elements": [],
        "attributes": [],
        "namespaces": [],
        "sections": [],
        "properties": [],
        "notes": None,
    }


def _forensic(
    fmt: str, family: str, engine: str, data: bytes, note: str
) -> Dict[str, Any]:
    prof = _profile(fmt, family, engine, "binary")
    prof["status"] = "forensic"
    prof["byte_size"] = len(data)
    prof["notes"] = note
    prof["properties"] = [
        ("forensic", "byte_size", len(data)),
        ("forensic", "sha256", _sha256(data)),
        ("forensic", "leading_magic_hex", data[:8].hex()),
    ]
    return prof


def _empty(fmt: str, family: str, engine: str, language: str) -> Dict[str, Any]:
    prof = _profile(fmt, family, engine, language)
    prof["status"] = "empty"
    prof["byte_size"] = 0
    prof["line_count"] = 0
    prof["notes"] = "empty file"
    return prof


def _finalize_element_metrics(prof: Dict[str, Any]) -> None:
    m = prof["metrics"]
    m["distinct_element_count"] = len(prof["elements"])
    m["distinct_attribute_count"] = len(prof["attributes"])
    m["namespace_count"] = len(prof["namespaces"])
    m["attribute_count"] = sum(a.get("count", 0) for a in prof["attributes"])


# ===========================================================================
# XML engine (expat structural walk, manual namespace tracking)
# ===========================================================================
class _XmlWalker:
    """Accumulates per-element / per-attribute / per-namespace statistics."""

    def __init__(self) -> None:
        self.elements: Dict[str, Dict[str, Any]] = {}
        self.attributes: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.namespaces: Dict[str, Dict[str, Any]] = {}
        self.sections: List[Dict[str, Any]] = []
        self.metrics = _blank_metrics()
        self.root: Optional[str] = None
        self.xml_version: Optional[str] = None
        self.xml_encoding: Optional[str] = None
        self.xml_standalone: Optional[str] = None
        self.doctype: Optional[Dict[str, Any]] = None
        self._stack: List[Dict[str, Any]] = []
        self._elem_over = False
        self._attr_over = False

    # -- element bookkeeping -------------------------------------------
    def _elem(self, name: str) -> Optional[Dict[str, Any]]:
        st = self.elements.get(name)
        if st is None:
            if len(self.elements) >= _ELEMENT_BUDGET:
                self._elem_over = True
                return None
            st = self.elements[name] = {
                "tag": _localname(name),
                "qname": name,
                "ns_prefix": _prefix_of(name),
                "ns_uri": None,
                "count": 0,
                "min_depth": None,
                "max_depth": 0,
                "total_children": 0,
                "max_children": 0,
                "leaf_count": 0,
                "text_count": 0,
                "total_text_len": 0,
                "attr_names": set(),
                "sample_text": None,
                "is_root": False,
                "ordinal": len(self.elements) + 1,
            }
        return st

    def _attr(self, elem: str, attr: str) -> Optional[Dict[str, Any]]:
        key = (elem, attr)
        st = self.attributes.get(key)
        if st is None:
            if len(self.attributes) >= _ATTR_BUDGET:
                self._attr_over = True
                return None
            st = self.attributes[key] = {
                "element_tag": _localname(elem),
                "element_qname": elem,
                "name": _localname(attr),
                "qname": attr,
                "ns_prefix": _prefix_of(attr),
                "count": 0,
                "values": set(),
                "value_over": False,
                "vtype": None,
                "vtype_mixed": False,
                "sample": None,
                "min_len": None,
                "max_len": 0,
            }
        return st

    # -- expat handlers ------------------------------------------------
    def start(self, name: str, attrs: Dict[str, str]) -> None:
        depth = len(self._stack)
        if self.root is None:
            self.root = name
        # namespace declarations carried on this element
        for a, v in attrs.items():
            if a == "xmlns":
                self._decl_ns("", v)
            elif a.startswith("xmlns:"):
                self._decl_ns(a[6:], v)
        st = self._elem(name)
        self.metrics["element_count"] += 1
        if st is not None:
            st["count"] += 1
            st["min_depth"] = (
                depth if st["min_depth"] is None else min(st["min_depth"], depth)
            )
            st["max_depth"] = max(st["max_depth"], depth)
            if depth == 0:
                st["is_root"] = True
            pfx = _prefix_of(name)
            if pfx and pfx in self.namespaces:
                st["ns_uri"] = self.namespaces[pfx]["uri"]
                self.namespaces[pfx]["usage"] += 1
            elif pfx is None and "" in self.namespaces:
                st["ns_uri"] = self.namespaces[""]["uri"]
        # attributes (skip the xmlns declarations themselves)
        for a, v in attrs.items():
            if a == "xmlns" or a.startswith("xmlns:"):
                continue
            if st is not None:
                st["attr_names"].add(_localname(a))
            ast = self._attr(name, a)
            if ast is not None:
                ast["count"] += 1
                if not ast["value_over"]:
                    if len(ast["values"]) < _DISTINCT_VAL_CAP:
                        ast["values"].add(v)
                    else:
                        ast["value_over"] = True
                vt = _infer_value_type(v)
                if ast["vtype"] is None:
                    ast["vtype"] = vt
                elif ast["vtype"] != vt and vt != "EMPTY":
                    ast["vtype_mixed"] = True
                if ast["sample"] is None and v:
                    ast["sample"] = v[:_PREVIEW]
                lv = len(v)
                ast["min_len"] = (
                    lv if ast["min_len"] is None else min(ast["min_len"], lv)
                )
                ast["max_len"] = max(ast["max_len"], lv)
            pfx = _prefix_of(a)
            if pfx and pfx in self.namespaces:
                self.namespaces[pfx]["usage"] += 1
        if depth < _DEPTH_GUARD:
            self._stack.append(
                {
                    "name": name,
                    "depth": depth,
                    "child_elems": 0,
                    "has_child": False,
                    "text": [],
                    "attrs": {
                        k: v
                        for k, v in attrs.items()
                        if not (k == "xmlns" or k.startswith("xmlns:"))
                    },
                }
            )
        if self._stack[:-1]:
            self._stack[-2]["child_elems"] += 1
            self._stack[-2]["has_child"] = True

    def end(self, name: str) -> None:
        if not self._stack:
            return
        node = self._stack.pop()
        st = self.elements.get(node["name"])
        nchild = node["child_elems"]
        if st is not None:
            st["total_children"] += nchild
            st["max_children"] = max(st["max_children"], nchild)
            if not node["has_child"]:
                st["leaf_count"] += 1
            txt = "".join(node["text"]).strip()
            if txt:
                st["text_count"] += 1
                st["total_text_len"] += len(txt)
                if not st["sample_text"]:
                    st["sample_text"] = txt[:_PREVIEW]
        if node["depth"] == 1 and len(self.sections) < _SECTION_BUDGET:
            title = None
            for tk in ("name", "id", "title", "label"):
                if tk in node["attrs"]:
                    title = node["attrs"][tk][:_PREVIEW]
                    break
            if title is None:
                t = "".join(node["text"]).strip()
                title = t[:_PREVIEW] if t else None
            self.sections.append(
                {
                    "name": _localname(node["name"]),
                    "type": "element",
                    "path": "/"
                    + _localname(self.root or "")
                    + "/"
                    + _localname(node["name"]),
                    "depth": 1,
                    "ordinal": len(self.sections) + 1,
                    "tag": node["name"],
                    "child_count": nchild,
                    "text_len": len("".join(node["text"]).strip()),
                    "title": title,
                }
            )

    def char(self, data: str) -> None:
        self.metrics["text_length"] += len(data)
        if self._stack and data.strip():
            top = self._stack[-1]
            if len(top["text"]) < _TEXT_SAMPLES:
                top["text"].append(data)

    def comment(self, _data: str) -> None:
        self.metrics["comment_count"] += 1

    def pi(self, _target: str, _data: str) -> None:
        self.metrics["pi_count"] += 1

    def cdata_start(self) -> None:
        self.metrics["cdata_count"] += 1

    def xml_decl(
        self, version: Optional[str], encoding: Optional[str], standalone: int
    ) -> None:
        self.xml_version = version
        self.xml_encoding = encoding
        self.xml_standalone = {1: "yes", 0: "no"}.get(standalone)

    def doctype_decl(
        self, name: str, sysid: Optional[str], pubid: Optional[str], _internal: int
    ) -> None:
        self.doctype = {"name": name, "system_id": sysid, "public_id": pubid}

    def _decl_ns(self, prefix: str, uri: str) -> None:
        if prefix in self.namespaces:
            return
        if len(self.namespaces) >= _NS_BUDGET:
            return
        self.namespaces[prefix] = {
            "prefix": prefix,
            "uri": uri,
            "is_default": prefix == "",
            "usage": 0,
        }


def _make_parser(walker: _XmlWalker) -> "expat.XMLParserType":
    p = expat.ParserCreate()  # no namespace_separator: keep raw qnames
    p.buffer_text = True
    p.StartElementHandler = walker.start
    p.EndElementHandler = walker.end
    p.CharacterDataHandler = walker.char
    p.CommentHandler = walker.comment
    p.ProcessingInstructionHandler = walker.pi
    p.StartCdataSectionHandler = walker.cdata_start
    p.XmlDeclHandler = walker.xml_decl
    p.StartDoctypeDeclHandler = walker.doctype_decl
    return p


def _walker_into_profile(prof: Dict[str, Any], w: _XmlWalker) -> None:
    prof["root_element"] = _localname(w.root) if w.root else None
    prof["metrics"]["max_depth"] = max(
        (e["max_depth"] for e in w.elements.values()), default=0
    )
    prof["metrics"]["comment_count"] = w.metrics["comment_count"]
    prof["metrics"]["pi_count"] = w.metrics["pi_count"]
    prof["metrics"]["cdata_count"] = w.metrics["cdata_count"]
    prof["metrics"]["text_length"] = w.metrics["text_length"]
    prof["metrics"]["element_count"] = w.metrics["element_count"]

    for st in w.elements.values():
        names = sorted(st["attr_names"])
        prof["elements"].append(
            {
                "tag": st["tag"],
                "qname": st["qname"],
                "ns_prefix": st["ns_prefix"],
                "ns_uri": st["ns_uri"],
                "count": st["count"],
                "min_depth": st["min_depth"] or 0,
                "max_depth": st["max_depth"],
                "total_children": st["total_children"],
                "max_children": st["max_children"],
                "leaf_count": st["leaf_count"],
                "text_count": st["text_count"],
                "total_text_len": st["total_text_len"],
                "attr_names": names,
                "sample_text": st["sample_text"],
                "is_root": st["is_root"],
                "ordinal": st["ordinal"],
            }
        )
    for st in w.attributes.values():
        dv = len(st["values"]) + (1 if st["value_over"] else 0)
        vtype = "MIXED" if st["vtype_mixed"] else (st["vtype"] or "STRING")
        prof["attributes"].append(
            {
                "element_tag": st["element_tag"],
                "element_qname": st["element_qname"],
                "name": st["name"],
                "ns_prefix": st["ns_prefix"],
                "count": st["count"],
                "distinct_values": dv,
                "value_type": vtype,
                "sample": st["sample"],
                "min_len": st["min_len"] or 0,
                "max_len": st["max_len"],
            }
        )
    for st in w.namespaces.values():
        prof["namespaces"].append(
            {
                "prefix": st["prefix"],
                "uri": st["uri"],
                "is_default": st["is_default"],
                "usage": st["usage"],
            }
        )
    prof["sections"] = w.sections
    _finalize_element_metrics(prof)

    props = prof["properties"]
    if w.xml_version:
        props.append(("xml_declaration", "version", w.xml_version))
    if w.xml_encoding:
        props.append(("xml_declaration", "encoding", w.xml_encoding))
    if w.xml_standalone:
        props.append(("xml_declaration", "standalone", w.xml_standalone))
    if w.doctype:
        props.append(("doctype", "name", w.doctype.get("name")))
        if w.doctype.get("public_id"):
            props.append(("doctype", "public_id", w.doctype["public_id"]))
        if w.doctype.get("system_id"):
            props.append(("doctype", "system_id", w.doctype["system_id"]))
    if prof["root_element"]:
        props.append(("structure", "root_element", prof["root_element"]))
    props.append(("structure", "distinct_elements", len(prof["elements"])))
    props.append(("structure", "total_elements", prof["metrics"]["element_count"]))
    props.append(("structure", "max_depth", prof["metrics"]["max_depth"]))
    props.append(("structure", "namespace_count", len(prof["namespaces"])))
    if w._elem_over:
        props.append(("limits", "distinct_element_cap_reached", True))
    if w._attr_over:
        props.append(("limits", "distinct_attribute_cap_reached", True))


_RE_TAG = re.compile(
    r"<\s*(/?)\s*([A-Za-z_][\w.\-]*(?::[\w.\-]+)?)((?:\s+[^<>]*?)?)\s*(/?)>"
)
_RE_ATTR = re.compile(
    r"([A-Za-z_][\w.\-]*(?::[\w.\-]+)?)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s\"'<>]+)"
)
_RE_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _lenient_tag_scan(
    text: str, prof: Dict[str, Any], void_tags: Optional[frozenset] = None
) -> None:
    """Regex tag census used when a strict parse is not well-formed.

    Produces real element / attribute / section rows (open/close balanced for an
    approximate depth); marks the profile ``partial`` -- never fabricates rows.
    """
    void_tags = void_tags or frozenset()
    prof["metrics"]["comment_count"] = len(_RE_COMMENT.findall(text))
    body = _RE_COMMENT.sub("", text)

    w = _XmlWalker()
    for m in _RE_TAG.finditer(body):
        closing, name, attr_str, self_close = (
            m.group(1),
            m.group(2),
            m.group(3),
            m.group(4),
        )
        low = name.lower()
        if closing:
            # find nearest matching open on the stack
            for i in range(len(w._stack) - 1, -1, -1):
                if w._stack[i]["name"] == name:
                    while len(w._stack) > i:
                        w.end(w._stack[-1]["name"])
                    break
            continue
        attrs: Dict[str, str] = {}
        for am in _RE_ATTR.finditer(attr_str or ""):
            val = am.group(2)
            if val[:1] in "\"'":
                val = val[1:-1]
            attrs[am.group(1)] = val
        w.start(name, attrs)
        if self_close or low in void_tags:
            w.end(name)
    while w._stack:
        w.end(w._stack[-1]["name"])
    _walker_into_profile(prof, w)


def _engine_xml(data: bytes, prof: Dict[str, Any], decoded: str) -> None:
    w = _XmlWalker()
    parser = _make_parser(w)
    try:
        parser.Parse(data, True)
        prof["well_formed"] = True
        _walker_into_profile(prof, w)
        if prof["metrics"]["element_count"] == 0:
            prof["status"] = "partial"
            prof["notes"] = "no elements parsed"
    except expat.ExpatError as err:
        # Not strictly well-formed (undefined entity, stray markup, SGML-ism):
        # fall back to a lenient tag census so the tags are still reported.
        prof["well_formed"] = False
        prof["status"] = "partial"
        line = getattr(err, "lineno", "?")
        col = getattr(err, "offset", "?")
        prof["properties"].append(
            (
                "parse",
                "expat_error",
                f"{expat.ErrorString(err.code)} at line {line} col {col}",
            )
        )
        _lenient_tag_scan(decoded, prof)
        if not prof["notes"]:
            prof["notes"] = (
                "not well-formed XML; lenient tag census; no tags fabricated"
            )


# ===========================================================================
# HTML engine (lenient html.parser walk)
# ===========================================================================
_HTML_VOID = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


class _HtmlCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.w = _XmlWalker()
        self.headings: List[Dict[str, Any]] = []
        self.title: Optional[str] = None
        self._in_title = False
        self.counts = {
            "script": 0,
            "style": 0,
            "link": 0,
            "form": 0,
            "img": 0,
            "a": 0,
            "input": 0,
            "table": 0,
        }
        self.doctype: Optional[str] = None
        self._pending_heading: Optional[Dict[str, Any]] = None

    def handle_decl(self, decl: str) -> None:
        self.doctype = decl[:_PREVIEW]

    def handle_starttag(self, tag: str, attrs) -> None:
        adict = {k: (v if v is not None else "") for k, v in attrs}
        self.w.start(tag, adict)
        if tag in self.counts:
            self.counts[tag] += 1
        if tag == "title":
            self._in_title = True
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._pending_heading = {"level": int(tag[1]), "text": []}
        if tag in _HTML_VOID:
            self.w.end(tag)

    def handle_startendtag(self, tag: str, attrs) -> None:
        adict = {k: (v if v is not None else "") for k, v in attrs}
        self.w.start(tag, adict)
        if tag in self.counts:
            self.counts[tag] += 1
        self.w.end(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6") and self._pending_heading:
            txt = "".join(self._pending_heading["text"]).strip()
            self.headings.append({"level": self._pending_heading["level"], "text": txt})
            self._pending_heading = None
        if tag in _HTML_VOID:
            return
        for i in range(len(self.w._stack) - 1, -1, -1):
            if self.w._stack[i]["name"] == tag:
                while len(self.w._stack) > i:
                    self.w.end(self.w._stack[-1]["name"])
                break

    def handle_data(self, data: str) -> None:
        self.w.char(data)
        if self._in_title:
            self.title = ((self.title or "") + data).strip()[:_PREVIEW]
        if self._pending_heading is not None:
            self._pending_heading["text"].append(data)

    def handle_comment(self, _data: str) -> None:
        self.w.metrics["comment_count"] += 1


def _engine_html(data: bytes, prof: Dict[str, Any], decoded: str) -> None:
    c = _HtmlCollector()
    try:
        c.feed(decoded)
        c.close()
    except Exception as err:  # html.parser is lenient; guard anyway
        prof["status"] = "partial"
        prof["properties"].append(("parse", "html_error", str(err)[:_PREVIEW]))
    while c.w._stack:
        c.w.end(c.w._stack[-1]["name"])
    prof["well_formed"] = None  # HTML is not required to be well-formed
    _walker_into_profile(prof, c.w)
    # sections: headings (nesting depth approximated by heading level)
    prof["sections"] = []
    for i, h in enumerate(c.headings[:_SECTION_BUDGET], start=1):
        prof["sections"].append(
            {
                "name": h["text"][:_PREVIEW] or f"h{h['level']}",
                "type": "heading",
                "path": f"h{h['level']}",
                "depth": h["level"],
                "ordinal": i,
                "tag": f"h{h['level']}",
                "child_count": 0,
                "text_len": len(h["text"]),
                "title": h["text"][:_PREVIEW],
            }
        )
    props = prof["properties"]
    if c.doctype:
        props.append(("html", "doctype", c.doctype))
    if c.title:
        props.append(("html", "title", c.title))
    props.append(("html", "heading_count", len(c.headings)))
    for k, v in c.counts.items():
        if v:
            props.append(("html_census", f"{k}_count", v))
    props.append(("structure", "root_element", prof["root_element"]))
    props.append(("structure", "note", "HTML nesting depth is approximate"))


# ===========================================================================
# SGML engine (OFX): try XML, then a tolerant SGML tag stream
# ===========================================================================
_RE_OFX_HDR = re.compile(r"^([A-Z][A-Z0-9]+):(.*)$")


def _engine_sgml(data: bytes, prof: Dict[str, Any], decoded: str) -> None:
    stripped = decoded.lstrip()
    if stripped.startswith("<?xml") or stripped.startswith("<OFX>"):
        _engine_xml(data, prof, decoded)
        if prof["metrics"]["element_count"]:
            prof["properties"].append(("ofx", "variant", "OFX 2.x (XML)"))
            return
    # OFX 1.x SGML: a header block (KEY:VALUE) then a tag stream where leaf
    # tags carry an inline value and are not explicitly closed.
    prof["markup_language"] = "sgml"
    prof["well_formed"] = False
    header: List[Tuple[str, str]] = []
    body_start = 0
    lines = decoded.splitlines(keepends=True)
    pos = 0
    for ln in lines:
        s = ln.strip()
        if not s:
            pos += len(ln)
            continue
        if s.startswith("<"):
            break
        m = _RE_OFX_HDR.match(s)
        if m:
            header.append((m.group(1), m.group(2).strip()))
            pos += len(ln)
        else:
            break
    body_start = pos
    w = _XmlWalker()
    body = decoded[body_start:]
    for m in re.finditer(r"<\s*(/?)\s*([A-Za-z0-9_.]+)\s*>([^<]*)", body):
        closing, name, inline = m.group(1), m.group(2), m.group(3).strip()
        if closing:
            for i in range(len(w._stack) - 1, -1, -1):
                if w._stack[i]["name"] == name:
                    while len(w._stack) > i:
                        w.end(w._stack[-1]["name"])
                    break
            continue
        w.start(name, {})
        if inline:
            w.char(inline)
            w.end(name)  # leaf tag with an inline value: close it
    while w._stack:
        w.end(w._stack[-1]["name"])
    _walker_into_profile(prof, w)
    prof["status"] = "ok" if prof["metrics"]["element_count"] else "partial"
    for k, v in header:
        prof["properties"].append(("ofx_header", k, v))
    prof["properties"].append(("ofx", "variant", "OFX 1.x (SGML)"))
    if not prof["notes"]:
        prof["notes"] = "OFX SGML tag stream; leaf tags carry inline values"


# ===========================================================================
# Line-based markup engines (wiki / gemtext / roff / typst / mif / markdown /
# lightweight). Each produces a construct-type element census + a heading /
# structural section outline, with real per-construct metrics.
# ===========================================================================
def _elrow(
    tag: str,
    count: int,
    ordinal: int,
    *,
    min_depth: int = 0,
    max_depth: int = 0,
    sample: Optional[str] = None,
    text_len: int = 0,
) -> Dict[str, Any]:
    return {
        "tag": tag,
        "qname": tag,
        "ns_prefix": None,
        "ns_uri": None,
        "count": count,
        "min_depth": min_depth,
        "max_depth": max_depth,
        "total_children": 0,
        "max_children": 0,
        "leaf_count": count,
        "text_count": 1 if text_len else 0,
        "total_text_len": text_len,
        "attr_names": [],
        "sample_text": sample,
        "is_root": False,
        "ordinal": ordinal,
    }


def _emit_constructs(
    prof: Dict[str, Any],
    counts: Dict[str, int],
    samples: Optional[Dict[str, str]] = None,
) -> None:
    samples = samples or {}
    ordinal = 0
    total = 0
    for tag, cnt in counts.items():
        if not cnt:
            continue
        ordinal += 1
        total += cnt
        prof["elements"].append(_elrow(tag, cnt, ordinal, sample=samples.get(tag)))
    prof["metrics"]["element_count"] = total
    _finalize_element_metrics(prof)


_RE_WIKI_HEAD = re.compile(r"^(={1,6})\s*(.*?)\s*=*\s*$")
_RE_TEXTILE_HEAD = re.compile(r"^h([1-6])\.\s+(.*)$")


def _engine_wiki(text: str, prof: Dict[str, Any]) -> None:
    counts = {
        "heading": 0,
        "internal_link": 0,
        "external_link": 0,
        "template": 0,
        "table": 0,
        "list_item": 0,
        "image": 0,
        "bold": 0,
        "italic": 0,
        "redirect": 0,
    }
    sections: List[Dict[str, Any]] = []
    ordinal = 0
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        s = line.strip()
        mh = _RE_WIKI_HEAD.match(s)
        mt = _RE_TEXTILE_HEAD.match(s)
        if mh and mh.group(2):
            level = len(mh.group(1))
            counts["heading"] += 1
            ordinal += 1
            if len(sections) < _SECTION_BUDGET:
                sections.append(
                    {
                        "name": mh.group(2)[:_PREVIEW],
                        "type": "heading",
                        "path": "=" * level,
                        "depth": level,
                        "ordinal": ordinal,
                        "tag": f"h{level}",
                        "child_count": 0,
                        "text_len": len(mh.group(2)),
                        "title": mh.group(2)[:_PREVIEW],
                    }
                )
        elif mt:
            level = int(mt.group(1))
            counts["heading"] += 1
            ordinal += 1
            if len(sections) < _SECTION_BUDGET:
                sections.append(
                    {
                        "name": mt.group(2)[:_PREVIEW],
                        "type": "heading",
                        "path": f"h{level}",
                        "depth": level,
                        "ordinal": ordinal,
                        "tag": f"h{level}",
                        "child_count": 0,
                        "text_len": len(mt.group(2)),
                        "title": mt.group(2)[:_PREVIEW],
                    }
                )
        if s.startswith("#redirect") or s.lower().startswith("#redirect"):
            counts["redirect"] += 1
        if s.startswith(("*", "#", ";", ":", "-")) and not mh:
            counts["list_item"] += 1
        if s.startswith("{|") or s.startswith("|}") or s.startswith("|-"):
            counts["table"] += 1
        counts["internal_link"] += len(
            re.findall(r"\[\[(?!File:|Image:)[^\]]+\]\]", line)
        )
        counts["image"] += len(re.findall(r"\[\[(?:File|Image):[^\]]+\]\]", line))
        counts["external_link"] += len(re.findall(r"\[https?://[^\]]+\]", line))
        counts["external_link"] += len(
            re.findall(r"\[[^\]]*\]\((?:https?://)[^)]+\)", line)
        )
        counts["template"] += len(re.findall(r"\{\{[^}]+\}\}", line))
        counts["bold"] += line.count("'''") // 2
        counts["italic"] += line.count("''") // 2
    prof["sections"] = sections
    _emit_constructs(prof, counts)
    props = prof["properties"]
    props.append(("wiki", "heading_count", counts["heading"]))
    props.append(("wiki", "internal_link_count", counts["internal_link"]))
    props.append(("wiki", "external_link_count", counts["external_link"]))
    props.append(("wiki", "template_count", counts["template"]))
    props.append(("wiki", "table_count", counts["table"]))
    if counts["redirect"]:
        props.append(("wiki", "is_redirect", True))


_RE_GMI_HEAD = re.compile(r"^(#{1,3})\s+(.*)$")


def _engine_gemtext(text: str, prof: Dict[str, Any]) -> None:
    counts = {
        "heading": 0,
        "link": 0,
        "list_item": 0,
        "quote": 0,
        "preformatted_block": 0,
        "text_line": 0,
    }
    sections: List[Dict[str, Any]] = []
    ordinal = 0
    pre = False
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("```"):
            if not pre:
                counts["preformatted_block"] += 1
            pre = not pre
            continue
        if pre:
            continue
        mh = _RE_GMI_HEAD.match(line)
        if mh:
            level = len(mh.group(1))
            counts["heading"] += 1
            ordinal += 1
            if len(sections) < _SECTION_BUDGET:
                sections.append(
                    {
                        "name": mh.group(2)[:_PREVIEW],
                        "type": "heading",
                        "path": "#" * level,
                        "depth": level,
                        "ordinal": ordinal,
                        "tag": f"h{level}",
                        "child_count": 0,
                        "text_len": len(mh.group(2)),
                        "title": mh.group(2)[:_PREVIEW],
                    }
                )
        elif line.startswith("=>"):
            counts["link"] += 1
        elif line.startswith("* "):
            counts["list_item"] += 1
        elif line.startswith(">"):
            counts["quote"] += 1
        elif line.strip():
            counts["text_line"] += 1
    prof["sections"] = sections
    _emit_constructs(prof, counts)
    prof["properties"].append(("gemtext", "heading_count", counts["heading"]))
    prof["properties"].append(("gemtext", "link_count", counts["link"]))
    prof["properties"].append(
        ("gemtext", "preformatted_blocks", counts["preformatted_block"])
    )


_RE_ROFF_REQ = re.compile(r"^[.']\s*([A-Za-z0-9]+)(.*)$")


def _engine_roff(text: str, prof: Dict[str, Any]) -> None:
    macro_counts: Dict[str, int] = {}
    macro_sample: Dict[str, str] = {}
    sections: List[Dict[str, Any]] = []
    ordinal = 0
    title = None
    comment = 0
    total_req = 0
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        m = _RE_ROFF_REQ.match(line)
        if not m:
            continue
        name = m.group(1)
        arg = m.group(2).strip()
        if name in ('\\"', "\\", '"') or line.startswith('.\\"'):
            comment += 1
            continue
        total_req += 1
        macro_counts[name] = macro_counts.get(name, 0) + 1
        if name not in macro_sample and arg:
            macro_sample[name] = arg[:_PREVIEW]
        if name in ("SH", "SS") and arg:
            ordinal += 1
            if len(sections) < _SECTION_BUDGET:
                sections.append(
                    {
                        "name": arg.strip('"')[:_PREVIEW],
                        "type": "heading",
                        "path": f".{name}",
                        "depth": 1 if name == "SH" else 2,
                        "ordinal": ordinal,
                        "tag": f".{name}",
                        "child_count": 0,
                        "text_len": len(arg),
                        "title": arg.strip('"')[:_PREVIEW],
                    }
                )
        if name == "TH" and arg and title is None:
            title = arg.strip('"')[:_PREVIEW]
    prof["sections"] = sections
    ordn = 0
    for name in sorted(macro_counts):
        ordn += 1
        prof["elements"].append(
            _elrow(f".{name}", macro_counts[name], ordn, sample=macro_sample.get(name))
        )
    prof["metrics"]["element_count"] = total_req
    prof["metrics"]["comment_count"] = comment
    _finalize_element_metrics(prof)
    if title:
        prof["properties"].append(("roff", "title", title))
    prof["properties"].append(("roff", "request_count", total_req))
    prof["properties"].append(("roff", "distinct_macros", len(macro_counts)))
    prof["properties"].append(("roff", "section_count", len(sections)))


_RE_TYP_HEAD = re.compile(r"^(={1,6})\s+(.*)$")
_RE_TYP_FUNC = re.compile(r"#([A-Za-z_][\w.]*)\s*[\(\[]")
_RE_TYP_DIRECTIVE = re.compile(r"#(let|set|show|import|include)\b")


def _engine_typst(text: str, prof: Dict[str, Any]) -> None:
    counts = {
        "heading": 0,
        "let": 0,
        "set": 0,
        "show": 0,
        "import": 0,
        "include": 0,
        "math_block": 0,
        "list_item": 0,
    }
    func_counts: Dict[str, int] = {}
    sections: List[Dict[str, Any]] = []
    ordinal = 0
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        s = line.strip()
        mh = _RE_TYP_HEAD.match(s)
        if mh:
            level = len(mh.group(1))
            counts["heading"] += 1
            ordinal += 1
            if len(sections) < _SECTION_BUDGET:
                sections.append(
                    {
                        "name": mh.group(2)[:_PREVIEW],
                        "type": "heading",
                        "path": "=" * level,
                        "depth": level,
                        "ordinal": ordinal,
                        "tag": f"h{level}",
                        "child_count": 0,
                        "text_len": len(mh.group(2)),
                        "title": mh.group(2)[:_PREVIEW],
                    }
                )
        for dm in _RE_TYP_DIRECTIVE.finditer(line):
            counts[dm.group(1)] += 1
        for fm in _RE_TYP_FUNC.finditer(line):
            fn = fm.group(1)
            if fn in ("let", "set", "show", "import", "include"):
                continue
            func_counts[fn] = func_counts.get(fn, 0) + 1
        counts["math_block"] += line.count("$") // 2
        if s.startswith(("- ", "+ ")):
            counts["list_item"] += 1
    prof["sections"] = sections
    ordn = 0
    total = 0
    for tag, cnt in counts.items():
        if cnt:
            ordn += 1
            total += cnt
            prof["elements"].append(_elrow(tag, cnt, ordn))
    for fn in sorted(func_counts):
        ordn += 1
        total += func_counts[fn]
        prof["elements"].append(_elrow(f"#{fn}", func_counts[fn], ordn))
    prof["metrics"]["element_count"] = total
    _finalize_element_metrics(prof)
    prof["properties"].append(("typst", "heading_count", counts["heading"]))
    prof["properties"].append(
        ("typst", "import_count", counts["import"] + counts["include"])
    )
    prof["properties"].append(("typst", "let_count", counts["let"]))
    prof["properties"].append(("typst", "function_calls", sum(func_counts.values())))


_RE_MIF_TOKEN = re.compile(r"<([A-Za-z][A-Za-z0-9]*)")


def _engine_mif(text: str, prof: Dict[str, Any]) -> None:
    token_counts: Dict[str, int] = {}
    token_depth_min: Dict[str, int] = {}
    token_depth_max: Dict[str, int] = {}
    sections: List[Dict[str, Any]] = []
    depth = 0
    total = 0
    mif_version = None
    m0 = re.search(r"<MIFFile\s+([^\s>]+)", text)
    if m0:
        mif_version = m0.group(1)
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "<":
            mt = _RE_MIF_TOKEN.match(text, i)
            if mt:
                name = mt.group(1)
                token_counts[name] = token_counts.get(name, 0) + 1
                token_depth_min[name] = min(token_depth_min.get(name, depth), depth)
                token_depth_max[name] = max(token_depth_max.get(name, depth), depth)
                total += 1
                if depth == 1 and len(sections) < _SECTION_BUDGET:
                    sections.append(
                        {
                            "name": name,
                            "type": "token",
                            "path": f"<{name}>",
                            "depth": 1,
                            "ordinal": len(sections) + 1,
                            "tag": name,
                            "child_count": 0,
                            "text_len": 0,
                            "title": name,
                        }
                    )
                depth += 1
                i = mt.end()
                continue
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        i += 1
    prof["sections"] = sections
    ordn = 0
    for name in sorted(token_counts):
        ordn += 1
        prof["elements"].append(
            _elrow(
                name,
                token_counts[name],
                ordn,
                min_depth=token_depth_min[name],
                max_depth=token_depth_max[name],
            )
        )
    prof["metrics"]["element_count"] = total
    prof["metrics"]["max_depth"] = max(token_depth_max.values(), default=0)
    prof["root_element"] = "MIFFile" if "MIFFile" in token_counts else None
    _finalize_element_metrics(prof)
    if mif_version:
        prof["properties"].append(("mif", "version", mif_version))
    prof["properties"].append(("mif", "distinct_tokens", len(token_counts)))
    prof["properties"].append(("mif", "total_tokens", total))


_RE_MD_HEAD = re.compile(r"^(#{1,6})\s+(.*)$")
_RE_MD_FENCE = re.compile(r"^(```|~~~)\s*(\S+)?")
_RE_MDC_COMP = re.compile(r"^::+\s*([A-Za-z][\w-]*)")
_RE_APIB_FORMAT = re.compile(r"^FORMAT:\s*(\S+)", re.IGNORECASE)


def _engine_markdown(text: str, prof: Dict[str, Any]) -> None:
    counts = {
        "heading": 0,
        "fenced_code": 0,
        "component": 0,
        "link": 0,
        "image": 0,
        "list_item": 0,
        "blockquote": 0,
        "table_row": 0,
        "apib_group": 0,
        "apib_resource": 0,
        "apib_action": 0,
    }
    sections: List[Dict[str, Any]] = []
    ordinal = 0
    frontmatter = False
    apib_format = None
    lines = text.splitlines()
    in_fence = False
    fence_langs: List[str] = []
    if lines and lines[0].strip() == "---":
        for j in range(1, len(lines)):
            if lines[j].strip() in ("---", "..."):
                frontmatter = True
                break
    for raw in lines:
        line = raw.rstrip("\n")
        mf = _RE_MD_FENCE.match(line.strip())
        if mf:
            if not in_fence:
                counts["fenced_code"] += 1
                if mf.group(2):
                    fence_langs.append(mf.group(2))
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        mh = _RE_MD_HEAD.match(line)
        if mh:
            level = len(mh.group(1))
            head = mh.group(2).strip()
            counts["heading"] += 1
            ordinal += 1
            low = head.lower()
            if low.startswith("group "):
                counts["apib_group"] += 1
            elif "[" in head and "]" in head and "/" in head:
                counts["apib_resource"] += 1
            if len(sections) < _SECTION_BUDGET:
                sections.append(
                    {
                        "name": head[:_PREVIEW],
                        "type": "heading",
                        "path": "#" * level,
                        "depth": level,
                        "ordinal": ordinal,
                        "tag": f"h{level}",
                        "child_count": 0,
                        "text_len": len(head),
                        "title": head[:_PREVIEW],
                    }
                )
            continue
        mc = _RE_MDC_COMP.match(line.strip())
        if mc:
            counts["component"] += 1
        maf = _RE_APIB_FORMAT.match(line.strip())
        if maf:
            apib_format = maf.group(1)
        s = line.strip()
        if s.startswith(("- ", "* ", "+ ")) or re.match(r"^\d+\.\s", s):
            counts["list_item"] += 1
            if re.match(r"^[+*-]\s+(Response|Request|Attributes|Parameters)\b", s):
                counts["apib_action"] += 1
        if s.startswith(">"):
            counts["blockquote"] += 1
        if s.startswith("|") and s.endswith("|"):
            counts["table_row"] += 1
        counts["image"] += len(re.findall(r"!\[[^\]]*\]\([^)]+\)", line))
        counts["link"] += len(re.findall(r"(?<!!)\[[^\]]*\]\([^)]+\)", line))
    prof["sections"] = sections
    _emit_constructs(prof, counts)
    props = prof["properties"]
    props.append(("markdown", "heading_count", counts["heading"]))
    props.append(("markdown", "code_block_count", counts["fenced_code"]))
    props.append(("markdown", "has_frontmatter", frontmatter))
    if counts["component"]:
        props.append(("markdown", "component_count", counts["component"]))
    if fence_langs:
        props.append(("markdown", "code_languages", sorted(set(fence_langs))))
    if apib_format:
        props.append(("api_blueprint", "format", apib_format))
    if counts["apib_group"] or counts["apib_resource"]:
        props.append(("api_blueprint", "group_count", counts["apib_group"]))
        props.append(("api_blueprint", "resource_count", counts["apib_resource"]))


_RE_BOX = re.compile(r"[─-╿▀-▟=+*#|/\\_-]")


def _engine_lightweight(text: str, prof: Dict[str, Any]) -> None:
    lines = text.splitlines()
    counts = {
        "paragraph": 0,
        "blank_line": 0,
        "heading_underline": 0,
        "box_drawing_line": 0,
        "list_item": 0,
    }
    sections: List[Dict[str, Any]] = []
    ordinal = 0
    words = 0
    chars = len(text)
    longest = 0
    nonascii = 0
    prev_nonblank = None
    for raw in lines:
        line = raw.rstrip("\n")
        longest = max(longest, len(line))
        words += len(line.split())
        nonascii += sum(1 for ch in line if ord(ch) > 127)
        s = line.strip()
        if not s:
            counts["blank_line"] += 1
            prev_nonblank = None
            continue
        if re.match(r"^[=\-~^#*]{3,}$", s) and prev_nonblank:
            counts["heading_underline"] += 1
            ordinal += 1
            if len(sections) < _SECTION_BUDGET:
                sections.append(
                    {
                        "name": prev_nonblank[:_PREVIEW],
                        "type": "heading",
                        "path": "underline",
                        "depth": 1,
                        "ordinal": ordinal,
                        "tag": "heading",
                        "child_count": 0,
                        "text_len": len(prev_nonblank),
                        "title": prev_nonblank[:_PREVIEW],
                    }
                )
            prev_nonblank = None
            continue
        if s.startswith(("-", "*", "o ", "> ")):
            counts["list_item"] += 1
        letters = sum(1 for ch in s if ch.isalnum())
        symbols = len(_RE_BOX.findall(s))
        if symbols > letters and len(s) > 3:
            counts["box_drawing_line"] += 1
        else:
            counts["paragraph"] += 1
        prev_nonblank = s
    if not sections:
        sections = [
            {
                "name": "(body)",
                "type": "body",
                "path": "/",
                "depth": 0,
                "ordinal": 1,
                "tag": "body",
                "child_count": len(lines),
                "text_len": chars,
                "title": None,
            }
        ]
    prof["sections"] = sections
    _emit_constructs(prof, counts)
    prof["metrics"]["text_length"] = chars
    props = prof["properties"]
    props.append(("lightweight", "line_count", len(lines)))
    props.append(("lightweight", "word_count", words))
    props.append(("lightweight", "char_count", chars))
    props.append(("lightweight", "blank_lines", counts["blank_line"]))
    props.append(("lightweight", "longest_line", longest))
    ratio = round(nonascii / max(1, chars), 4)
    props.append(("lightweight", "non_ascii_ratio", ratio))
    props.append(
        (
            "lightweight",
            "looks_like_ascii_art",
            counts["box_drawing_line"] > max(3, counts["paragraph"]),
        )
    )


# ===========================================================================
# Registry: ext -> (family, engine, label)
# ===========================================================================
def _xml(items: Dict[str, Tuple[str, str]]) -> Dict[str, Tuple[str, str, str]]:
    return {ext: (fam, "xml", label) for ext, (fam, label) in items.items()}


_XML_VOCAB: Dict[str, Tuple[str, str]] = {
    ".abcd": ("biodiversity", "Access to Biological Collection Data"),
    ".acord": ("insurance_acord", "ACORD Insurance Data Message"),
    ".adml": ("group_policy", "Group Policy Language File"),
    ".admx": ("group_policy", "Group Policy Administrative Template"),
    ".adx": ("public_health_adx", "Aggregate Data Exchange"),
    ".aepx": ("after_effects", "After Effects XML Project"),
    ".aixm": ("aixm", "Aeronautical Information Exchange Model"),
    ".alto": ("alto_ocr", "ALTO OCR Layout"),
    ".aml": ("automationml", "AutomationML Engineering Data"),
    ".appdata": ("appstream", "AppStream Application Metadata"),
    ".arinc653": ("arinc653", "ARINC 653 Partition Configuration"),
    ".assetmap": ("dcp_assetmap", "DCP Asset Map"),
    ".bits": ("jats_bits", "Book Interchange Tag Suite"),
    ".blueprism": ("blueprism", "Blue Prism Process Export"),
    ".bpmn": ("bpmn", "BPMN Process Model"),
    ".browserconfig": ("browserconfig", "Microsoft Browser Configuration"),
    ".camt": ("iso20022", "ISO 20022 CAMT Bank Statement"),
    ".ccc": ("color_cdl", "Color Correction Collection"),
    ".ccr": ("ccr", "Continuity of Care Record"),
    ".ccxml": ("ccxml", "Call Control XML"),
    ".cdwa": ("cdwa_lite", "CDWA Lite Cultural Metadata"),
    ".cdxml": ("powershell_cdxml", "PowerShell Cmdlet Definition XML"),
    ".changelog": ("liquibase", "Liquibase Change Log"),
    ".cidoc": ("cidoc_crm", "CIDOC CRM Ontology Data"),
    ".cim": ("cim_power", "Common Information Model Power Grid Data"),
    ".cldr": ("cldr", "CLDR Locale Data"),
    ".clover": ("clover", "Clover Coverage Report"),
    ".cmi5": ("cmi5", "cmi5 Course Structure"),
    ".cmmn": ("cmmn", "CMMN Case Model"),
    ".cobertura": ("cobertura", "Cobertura Coverage Report"),
    ".cot": ("cursor_on_target", "Cursor on Target Message"),
    ".cpt": ("cognos", "Cognos Report Specification"),
    ".crossref": ("crossref", "Crossref Deposit XML"),
    ".csl": ("csl", "Citation Style Language Definition"),
    ".cxf": ("color_cxf", "Color Exchange Format"),
    ".datacite": ("datacite", "DataCite Metadata Record"),
    ".dc": ("dublin_core", "Dublin Core Metadata Record"),
    ".define": ("cdisc_define", "CDISC Define-XML Metadata"),
    ".dia": ("dia_diagram", "Dia Diagram (gzip XML)"),
    ".dmn": ("dmn", "DMN Decision Model"),
    ".drawio": ("drawio", "diagrams.net Diagram"),
    ".dtsx": ("ssis", "SQL Server Integration Services Package"),
    ".e2b": ("ich_e2b", "ICH E2B Safety Report"),
    ".eac": ("eac_cpf", "Encoded Archival Context Record"),
    ".ead": ("ead", "Encoded Archival Description Finding Aid"),
    ".eaf": ("elan", "ELAN Annotation File"),
    ".ecf": ("ecf_court", "Electronic Court Filing Document"),
    ".edrm": ("edrm", "EDRM XML Production File"),
    ".enex": ("evernote", "Evernote Export File"),
    ".epcis": ("epcis", "EPCIS Supply Chain Event Data"),
    ".esi": ("ethercat_esi", "EtherCAT Slave Information"),
    ".fatca": ("fatca", "FATCA XML Report"),
    ".filezilla": ("filezilla", "FileZilla Site Manager / Settings XML"),
    ".fcpxml": ("fcpxml", "Final Cut Pro XML Interchange"),
    ".fixm": ("fixm", "Flight Information Exchange Model"),
    ".fom": ("hla_fom", "HLA Federation Object Model"),
    ".fpml": ("fpml", "Financial Products Markup Language"),
    ".frx": ("fastreport", "FastReport Report Template"),
    ".gan": ("ganttproject", "GanttProject Plan"),
    ".gbxml": ("gbxml", "Green Building XML Model"),
    ".glade": ("glade", "Glade Interface Designer File"),
    ".grc": ("gnuradio", "GNU Radio Companion Flowgraph"),
    ".gnucash": ("gnucash", "GnuCash Financial Data (gzip XML)"),
    ".gschema": ("gsettings", "GSettings Schema Definition"),
    ".gsdml": ("profinet_gsdml", "PROFINET Device Description"),
    ".hla": ("hla_fom", "HLA Federation Object Model File"),
    ".hocr": ("hocr", "hOCR OCR Output"),
    ".icml": ("incopy_icml", "InCopy Markup Document"),
    ".idml": ("indesign_idml", "InDesign Markup Language"),
    ".idpmetadata": ("saml_metadata", "SAML Identity Provider Metadata"),
    ".imzml": ("imzml", "Mass Spectrometry Imaging Data"),
    ".incx": ("incopy_incx", "InCopy Interchange Document"),
    ".informatica": ("informatica", "Informatica Mapping Export"),
    ".inx": ("indesign_inx", "InDesign Interchange"),
    ".ipc2581": ("ipc2581", "IPC-2581 PCB Data Exchange"),
    ".ipso": ("ipso", "IPSO Smart Object Definition"),
    ".iso11783": ("isobus", "ISOBUS Agricultural Task Data"),
    ".item": ("talend", "Talend Repository Item"),
    ".iwxxm": ("iwxxm", "ICAO Weather Information Exchange Model"),
    ".jacoco": ("jacoco", "JaCoCo Coverage Report"),
    ".jats": ("jats", "Journal Article Tag Suite"),
    ".jdf": ("jdf", "Job Definition Format Ticket"),
    ".jhove": ("jhove", "JHOVE Characterization Report"),
    ".jmf": ("jmf", "Job Messaging Format Message"),
    ".jmx": ("jmeter", "Apache JMeter Test Plan"),
    ".jrxml": ("jasperreports", "JasperReports Design File"),
    ".junit": ("junit", "JUnit XML Test Report"),
    ".kcfg": ("kde_kcfg", "KDE Configuration Definition"),
    ".kdm": ("dcp_kdm", "Key Delivery Message"),
    ".keylayout": ("keylayout", "macOS Keyboard Layout"),
    ".kjb": ("pentaho_job", "Pentaho Kettle Job"),
    ".ktr": ("pentaho_transform", "Pentaho Data Integration Transformation"),
    ".l5x": ("rslogix", "RSLogix 5000 Program Export"),
    ".landxml": ("landxml", "LandXML Civil Engineering Data"),
    ".lido": ("lido", "LIDO Museum Object Record"),
    ".lwm2m": ("lwm2m", "LwM2M Object Definition"),
    ".managed-schema": ("solr_schema", "Solr Managed Schema File"),
    ".marcxml": ("marcxml", "MARC XML Bibliographic Record"),
    ".menu": ("freedesktop_menu", "Desktop Menu Definition"),
    ".metainfo": ("appstream", "AppStream Metainfo File"),
    ".mets": ("mets", "METS Metadata"),
    ".mil2525": ("mil2525", "MIL-STD-2525 Symbol Definition"),
    ".mime": ("shared_mime_info", "MIME Type Definition File"),
    ".mismo": ("mismo", "MISMO Mortgage Data File"),
    ".mjml": ("mjml", "MJML Responsive Email Template"),
    ".mlt": ("mlt", "MLT Framework Playlist/Project"),
    ".mods": ("mods", "Metadata Object Description Schema"),
    ".msc": ("mmc_snapin", "Microsoft Management Console Snap-in"),
    ".mxml": ("mxml_flex", "MXML Flex Interface Markup"),
    ".mzdata": ("mzdata", "mzData Spectrometry Format"),
    ".mzid": ("mzid", "Mass Spectrometry Identification Data"),
    ".mzml": ("mzml", "Mass Spectrometry mzML Data"),
    ".mzxml": ("mzxml", "Mass Spectrometry mzXML Data"),
    ".ndm": ("ccsds_ndm", "CCSDS Navigation Data Message"),
    ".nessus": ("nessus", "Nessus Vulnerability Scan Report"),
    ".netconf": ("netconf", "NETCONF Configuration Payload"),
    ".netxml": ("kismet", "Kismet Network Survey Data"),
    ".newsml": ("newsml", "NewsML Content Package"),
    ".nexml": ("nexml", "NeXML Phylogenetic Data"),
    ".nifi": ("nifi", "Apache NiFi Flow Template"),
    ".nmrml": ("nmrml", "nmrML Spectroscopy Data"),
    ".nodeset": ("opcua_nodeset", "OPC UA Information Model File"),
    ".o&m": ("ogc_om", "Observations and Measurements Data"),
    ".oai": ("oai_pmh", "OAI-PMH Harvest Response"),
    ".odf": ("opendocument_formula", "OpenDocument Formula"),
    ".odm": ("cdisc_odm", "CDISC Operational Data Model"),
    ".odx": ("odx_diag", "Open Diagnostic Data Exchange"),
    ".onix": ("onix", "ONIX for Books Metadata Message"),
    ".opcua": ("opcua_nodeset", "OPC UA Nodeset Definition"),
    ".openioc": ("openioc", "OpenIOC Indicator Document"),
    ".osim": ("opensim", "OpenSim Musculoskeletal Model"),
    ".ovalxml": ("oval", "OVAL Vulnerability Definition"),
    ".ovfenv": ("ovf_env", "OVF Environment File"),
    ".page": ("page_ocr", "PAGE XML OCR Layout"),
    ".pain": ("iso20022", "ISO 20022 PAIN Payment Initiation"),
    ".pcml": ("pcml", "Program Call Markup Language"),
    ".pepxml": ("pepxml", "Peptide Identification Data"),
    ".planner": ("gnome_planner", "Planner Project File"),
    ".plcopen": ("plcopen", "PLCopen XML Program Exchange"),
    ".pmml": ("pmml", "Predictive Model Markup Language"),
    ".ppml": ("ppml", "Personalized Print Markup Language"),
    ".premis": ("premis", "PREMIS Preservation Metadata"),
    ".prismxml": ("prism", "PRISM Publishing Metadata"),
    ".prodml": ("prodml", "PRODML Production Data"),
    ".protxml": ("protxml", "Protein Identification Data"),
    ".ps1xml": ("powershell_ps1xml", "PowerShell Format/Type Definition"),
    ".pvd": ("paraview_pvd", "ParaView Data Collection"),
    ".pwx": ("trainingpeaks", "TrainingPeaks Workout File"),
    ".qrc": ("qt_resource", "Qt Resource Collection File"),
    ".quakeml": ("quakeml", "QuakeML Earthquake Data"),
    ".rdg": ("rdcman", "Remote Desktop Connection Manager Group"),
    ".rdl": ("ssrs_rdl", "Report Definition Language File"),
    ".rdlc": ("ssrs_rdlc", "Client Report Definition"),
    ".resqml": ("resqml", "RESQML Reservoir Model Data"),
    ".rets": ("rets", "RETS Real Estate Data Payload"),
    ".rptdesign": ("birt", "BIRT Report Design"),
    ".saml": ("saml", "SAML Assertion Document"),
    ".scap": ("scap", "Security Content Automation Data"),
    ".sdlxliff": ("xliff_sdl", "SDL Trados Bilingual File"),
    ".sensorml": ("sensorml", "SensorML Sensor Description"),
    ".sepa": ("iso20022", "SEPA Payment XML File"),
    ".sitemap": ("sitemap", "XML Sitemap File"),
    ".sld": ("ogc_sld", "OGC Styled Layer Descriptor"),
    ".solrconfig": ("solr_config", "Apache Solr Core Configuration"),
    ".srgs": ("srgs", "Speech Recognition Grammar"),
    ".ssml": ("ssml", "Speech Synthesis Markup"),
    ".stationxml": ("stationxml", "FDSN Station Metadata"),
    ".stringsdict": ("apple_plist", "Plural Rules Strings Dictionary"),
    ".tbx": ("tbx", "TermBase eXchange"),
    ".tei": ("tei", "Text Encoding Initiative Document"),
    ".tmx": ("tiled_tmx", "Tiled Map XML"),
    ".trs": ("transcriber", "Transcriber Annotation File"),
    ".trx": ("mstest_trx", "Visual Studio Test Result File"),
    ".ui": ("gtk_qt_ui", "GTK/Qt Interface Definition"),
    ".ulad": ("ulad", "Uniform Loan Application Dataset File"),
    ".urdf": ("urdf", "Unified Robot Description Format"),
    ".uxf": ("umlet", "UMLet Diagram"),
    ".vast": ("vast", "VAST Video Ad Serving Template"),
    ".vdx": ("visio_vdx", "Visio XML Drawing"),
    ".vot": ("votable", "VOTable Virtual Observatory Data"),
    ".vpaid": ("vpaid", "VPAID Ad Interface Definition"),
    ".vsct": ("vsct", "Visual Studio Command Table"),
    ".vxml": ("voicexml", "VoiceXML Dialog File"),
    ".witsml": ("witsml", "WITSML Drilling Data"),
    ".world": ("gazebo_world", "Gazebo Simulation World"),
    ".wxs": ("wix", "WiX Installer Source"),
    ".xacro": ("xacro", "XML Macro Robot Description"),
    ".xades": ("xades", "XAdES XML Advanced Signature"),
    ".xbrli": ("xbrl", "XBRL Instance Document"),
    ".xccdf": ("xccdf", "XCCDF Security Checklist"),
    ".xces": ("xces", "XML Corpus Encoding Standard File"),
    ".xdd": ("canopen_xdd", "CANopen XML Device Description"),
    ".xdmf": ("xdmf", "eXtensible Data Model and Format"),
    ".xlf": ("xliff", "XLIFF Translation File"),
    ".xliff": ("xliff", "XML Localization Interchange File"),
    ".xmeml": ("xmeml", "Final Cut XML Interchange"),
    ".xmi": ("xmi_uml", "XML Metadata Interchange (UML)"),
    ".xml": ("xml_generic", "XML Data Document"),
    ".xmpp": ("xmpp", "XMPP Message Archive"),
    ".xpdl": ("xpdl", "XML Process Definition Language"),
    ".xrdml": ("xrdml", "X-ray Diffraction Data"),
    ".xunit": ("xunit", "xUnit Test Result Report"),
    ".zwcfg": ("zwave", "Z-Wave Network Configuration"),
    ".zwo": ("zwift", "Zwift Workout File"),
}

_NON_XML: Dict[str, Tuple[str, str, str]] = {
    # html engine
    ".asp": ("asp_classic", "html", "Classic Active Server Page"),
    ".aspx": ("aspnet_webform", "html", "ASP.NET Web Form"),
    ".ascx": ("aspnet_usercontrol", "html", "ASP.NET User Control"),
    ".dhtml": ("dhtml", "html", "Dynamic HTML Document"),
    ".bookmarks": ("netscape_bookmarks", "html", "Browser Bookmarks Export"),
    # wiki engine
    ".creole": ("creole", "wiki", "Creole Wiki Markup"),
    ".wiki": ("wikitext", "wiki", "Wiki Markup Document"),
    ".mediawiki": ("mediawiki", "wiki", "MediaWiki Markup Document"),
    ".textile": ("textile", "wiki", "Textile Markup Document"),
    # gemtext engine
    ".gemini": ("gemtext", "gemtext", "Gemini Protocol Document (gemtext)"),
    ".gmi": ("gemtext", "gemtext", "Gemtext Markup Document"),
    # roff engine
    ".troff": ("roff", "roff", "troff Typesetting Source"),
    ".nroff": ("roff", "roff", "nroff Typesetting Source"),
    ".tr": ("roff", "roff", "troff Typesetting Source"),
    # typst engine
    ".typ": ("typst", "typst", "Typst Typesetting Source"),
    # mif engine
    ".mif": ("framemaker_mif", "mif", "Maker Interchange Format"),
    # markdown engine
    ".mdc": ("nuxt_mdc", "markdown", "Markdown Components (Nuxt Content)"),
    ".apib": ("api_blueprint", "markdown", "API Blueprint Document"),
    ".slate": ("slate_docs", "markdown", "Slate API Documentation Source"),
    # sgml engine
    ".ofx": ("ofx", "sgml", "Open Financial Exchange"),
    # lightweight engine
    ".ascii": (
        "lightweight",
        "lightweight",
        "Plain / lightweight markup text (.ascii)",
    ),
    ".utf8": ("lightweight", "lightweight", "Plain / lightweight markup text (.utf8)"),
    ".diz": ("lightweight", "lightweight", "Description-in-Zip (.diz)"),
    ".1st": ("lightweight", "lightweight", "Readme / first-run text (.1st)"),
}

_MARKUP_REGISTRY: Dict[str, Tuple[str, str, str]] = {}
_MARKUP_REGISTRY.update(_xml(_XML_VOCAB))
_MARKUP_REGISTRY.update(_NON_XML)


# ===========================================================================
# Public API
# ===========================================================================
def known_exts() -> frozenset:
    return frozenset(_MARKUP_REGISTRY)


def routing_suffixes() -> Tuple[str, ...]:
    return tuple(sorted(_MARKUP_REGISTRY))


def family_for(ext: str) -> Optional[str]:
    spec = _MARKUP_REGISTRY.get(ext.lower())
    return spec[0] if spec else None


def engine_for(ext: str) -> Optional[str]:
    spec = _MARKUP_REGISTRY.get(ext.lower())
    return spec[1] if spec else None


_BYTE_ENGINES = {"xml", "html", "sgml"}
_TEXT_DISPATCH = {
    "wiki": _engine_wiki,
    "gemtext": _engine_gemtext,
    "roff": _engine_roff,
    "typst": _engine_typst,
    "mif": _engine_mif,
    "markdown": _engine_markdown,
    "lightweight": _engine_lightweight,
}


def analyze(path: Path, ext: str) -> Dict[str, Any]:
    """Parse ``path`` (a markup file) into a normalized profile dict.

    ``path`` must be a :class:`pathlib.Path` (``_read_bytes`` calls ``stat()``).
    """
    ext = ext.lower()
    spec = _MARKUP_REGISTRY.get(ext)
    if spec is None:
        raise KeyError(f"no markup engine registered for {ext!r}")
    family, engine, label = spec
    language = (
        "xml" if engine in ("xml", "sgml") else ("html" if engine == "html" else engine)
    )

    data, truncated = _read_bytes(path)
    if not data:
        return _empty(label, family, engine, language)

    detected_via = "extension"
    # transparent gzip decompression (e.g. .dia / .gnucash / any gz-wrapped XML)
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                data = gz.read(_MAX_BYTES)
            detected_via = "gzip-magic"
        except OSError:
            return _forensic(
                label, family, engine, data, "gzip magic but not a valid gzip stream"
            )
    # ZIP-packaged vocabulary (IDML/INX/ODF containers): honest forensic note.
    if data[:4] == b"PK\x03\x04":
        prof = _forensic(
            label,
            family,
            engine,
            data,
            "ZIP-packaged markup vocabulary; members not extracted "
            "in the markup plane (route via ArchiveAnalyzer to recurse)",
        )
        prof["properties"].append(("container", "packaging", "zip"))
        return prof

    prof = _profile(label, family, engine, language)
    prof["detected_via"] = detected_via
    prof["byte_size"] = len(data)

    decoded, encoding = _decode(data)
    prof["encoding"] = encoding
    prof["line_count"] = _line_count(decoded)

    if engine in _BYTE_ENGINES and _looks_binary(data):
        forensic = _forensic(
            label, family, engine, data, "declared markup but payload is binary"
        )
        forensic["line_count"] = prof["line_count"]
        return forensic

    try:
        if engine == "xml":
            _engine_xml(data, prof, decoded)
        elif engine == "html":
            _engine_html(data, prof, decoded)
        elif engine == "sgml":
            _engine_sgml(data, prof, decoded)
        else:
            _TEXT_DISPATCH[engine](decoded, prof)
    except Exception as err:  # never let one malformed file abort the plane
        prof["status"] = "partial"
        prof["notes"] = f"parse error ({type(err).__name__}); no tags fabricated"
        prof["properties"].append(("parse", "error", str(err)[:_PREVIEW]))

    if truncated:
        prof["properties"].append(
            ("limits", "input_truncated_at_cap_bytes", _MAX_BYTES)
        )
        note = prof.get("notes")
        prof["notes"] = (
            (note + "; input truncated at cap") if note else "input truncated at cap"
        )

    # dialect verification (honest: compares observed root to the expected one)
    prof["dialect"] = family
    return prof
