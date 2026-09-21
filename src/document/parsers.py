"""
Per-type document parsers for the ``document`` analysis plane.

This module implements the *child-class hierarchy* the DocumentAnalyzer plane is
built around: a small abstract :class:`DocumentTypeParser` super-class and one
concrete child per document *content kind* still residual after the code / schema
/ database / data / binary / config / text / markup planes had claimed their
universes:

    ManifestParser        30 exts  package / lock / streaming / build manifests
    QueryParser           12 exts  query-language sources (SQL dialects, KQL,
                                    PromQL, DAX, SPL, N1QL, migrations, ...)
    MakefileParser         6 exts  make / automake / MMS build descriptions
    CertificateTextParser  5 exts  PEM / CSR / SSH key & signature text
    NotebookParser         5 exts  Mathematica / Maple / Maxima / Sage worksheets
    DocumentFileParser     4 exts  FDF form data / Google-Doc shortcuts / PML
    LicenseParser          3 exts  SPDX / DEP-5 copyright / NOTICE text
    DiffParser             3 exts  unified & context diffs / reject files

Every child runs a *real*, pure-stdlib, structure-aware parser that decomposes a
file into the canonical shape the DocumentAnalyzer flattens
(document -> sections -> records -> fields, plus file-level properties). The
generic serialization helpers (JSON / XML / INI / delimited / key-value sniffing,
the ``_profile`` / ``_section`` / ``_record`` / ``_field`` / ``_forensic``
builders) are shared with -- and imported from -- the verified ``text`` plane
(:mod:`..text.textual_formats`) so this plane never re-implements or forks that
machinery.

Honesty contract (identical to the text / config / database planes): content is
sniffed first, an inherently-binary payload degrades to an honest forensic byte
profile with *no fabricated records*, key / credential material is never decoded
into its secret content (only public structural facts -- PEM block type & DER
length, an SSH key's standard SHA-256 fingerprint -- are recorded), the raw
payload is never stored, and a partial parse is reported ``partial`` -- never
stubbed or invented.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..text import textual_formats as tf

# Re-exported shared builders (kept as short local aliases).
_section = tf._section
_record = tf._record
_field = tf._field
_profile = tf._profile
_forensic = tf._forensic
_empty = tf._empty
_field_type = tf._field_type
_PREVIEW = tf._PREVIEW


def _lines(text: str) -> List[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


# ===========================================================================
# base
# ===========================================================================
class DocumentTypeParser:
    """Abstract parent for every document-kind parser.

    A child sets :attr:`KIND` (the ``content_kind`` recorded on the file row),
    :attr:`EXTENSIONS` (the suffixes it owns) and per-ext ``(family, label)``
    metadata, then implements :meth:`parse` to return a ``profile`` dict in the
    exact shape :func:`..text.textual_formats._profile` produces.
    """

    KIND = "document"
    EXTENSIONS: Tuple[str, ...] = ()
    #: ext -> (syntax_family, human format label)
    LABELS: Dict[str, Tuple[str, str]] = {}

    def meta(self, ext: str) -> Tuple[str, str]:
        return self.LABELS.get(ext, (self.KIND, ext.lstrip(".") or self.KIND))

    # child API -------------------------------------------------------------
    def parse(
        self,
        path: Path,
        data: bytes,
        text: str,
        ext: str,
        encoding: str,
        line_count: int,
    ) -> Dict[str, Any]:
        raise NotImplementedError

    # helpers ---------------------------------------------------------------
    def _forensic(
        self, ext: str, data: bytes, note: str, via: str = "extension"
    ) -> Dict[str, Any]:
        fam, label = self.meta(ext)
        return _forensic(self.KIND, fam, label, data, len(data), note, via=via)

    def _auto(
        self, text: str, ext: str, byte_size: int, encoding: str, lc: int
    ) -> Dict[str, Any]:
        """Delegate to the shared content-sniffing structural parser."""
        fam, label = self.meta(ext)
        prof = tf._e_auto(text, self.KIND, fam, label, byte_size, encoding, lc)
        prof["format"] = label
        prof["family"] = fam
        return prof


# ===========================================================================
# 1. manifests
# ===========================================================================
class ManifestParser(DocumentTypeParser):
    """Package / lock / streaming / build manifests.

    JSON / YAML / XML / key-value manifests route to the shared structural
    sniffer; the genuinely bespoke formats (BitTorrent bencode, HTML5 AppCache,
    JAD MIDlet descriptors, PowerShell ``.psd1`` data, Ruby gem/pod specs,
    ``go.sum`` checksum lists, BagIt tag files) get real dedicated parsers.
    Inherently-binary manifests (bun ``.lockb``, OneNote ``.onetoc2``) degrade
    to an honest forensic profile.
    """

    KIND = "manifest"
    EXTENSIONS = (
        ".appcache",
        ".appinstaller",
        ".bagit",
        ".bower",
        ".chartlock",
        ".composer",
        ".delta",
        ".dvc",
        ".f4m",
        ".gemspec",
        ".hackage",
        ".hoodie",
        ".iceberg",
        ".ism",
        ".ismc",
        ".jad",
        ".lockb",
        ".manifest",
        ".mlflow",
        ".mpd",
        ".mpdstream",
        ".onetoc2",
        ".podspec",
        ".psd1",
        ".pubspec",
        ".sum",
        ".torrent",
        ".vcpkg",
        ".vpm",
        ".webmanifest",
    )
    LABELS = {
        ".appcache": ("appcache", "HTML5 application cache manifest"),
        ".appinstaller": ("xml", "MSIX App Installer manifest"),
        ".bagit": ("bagit", "BagIt tag manifest"),
        ".bower": ("json", "Bower package manifest"),
        ".chartlock": ("yaml", "Helm Chart.lock"),
        ".composer": ("json", "Composer package manifest"),
        ".delta": ("json", "Delta Lake table manifest"),
        ".dvc": ("yaml", "DVC stage / data manifest"),
        ".f4m": ("xml", "Adobe HDS F4M media manifest"),
        ".gemspec": ("ruby", "RubyGems gemspec"),
        ".hackage": ("cabal", "Hackage cabal manifest"),
        ".hoodie": ("json", "Apache Hudi manifest"),
        ".iceberg": ("json", "Apache Iceberg table metadata"),
        ".ism": ("xml", "IIS Smooth Streaming manifest"),
        ".ismc": ("xml", "IIS Smooth Streaming client manifest"),
        ".jad": ("jad", "Java MIDlet descriptor (JAD)"),
        ".lockb": ("binary", "Bun binary lockfile"),
        ".manifest": ("xml", "Windows side-by-side / ClickOnce manifest"),
        ".mlflow": ("yaml", "MLflow MLproject / model manifest"),
        ".mpd": ("xml", "MPEG-DASH media presentation description"),
        ".mpdstream": ("xml", "MPEG-DASH stream manifest"),
        ".onetoc2": ("binary", "OneNote table-of-contents"),
        ".podspec": ("ruby", "CocoaPods podspec"),
        ".psd1": ("powershell", "PowerShell data manifest (.psd1)"),
        ".pubspec": ("yaml", "Dart pub package manifest"),
        ".sum": ("gosum", "Go module checksum list (go.sum)"),
        ".torrent": ("bencode", "BitTorrent metainfo"),
        ".vcpkg": ("json", "vcpkg port manifest"),
        ".vpm": ("json", "VRChat package manifest"),
        ".webmanifest": ("json", "W3C web application manifest"),
    }
    _BINARY = {".lockb", ".onetoc2"}

    def parse(self, path, data, text, ext, encoding, line_count):
        fam, label = self.meta(ext)
        if ext == ".torrent" or data[:1] == b"d" and ext in ("", ".torrent"):
            prof = self._bencode(data, ext)
            if prof is not None:
                return prof
        if ext in self._BINARY or tf._looks_binary(data):
            return self._forensic(
                ext, data, f"{label}: binary manifest, forensic profile only"
            )
        byte_size, lc = len(data), line_count
        if ext == ".appcache":
            return self._appcache(text, ext, byte_size, encoding, lc)
        if ext == ".jad":
            return self._kv_colon(
                text, ext, byte_size, encoding, lc, "midlet-attribute"
            )
        if ext == ".bagit":
            return self._kv_colon(text, ext, byte_size, encoding, lc, "bag-declaration")
        if ext == ".psd1":
            return self._psd1(text, ext, byte_size, encoding, lc)
        if ext in (".gemspec", ".podspec"):
            return self._ruby_spec(text, ext, byte_size, encoding, lc)
        if ext == ".sum":
            return self._gosum(text, ext, byte_size, encoding, lc)
        if ext == ".hackage":
            return self._cabal(text, ext, byte_size, encoding, lc)
        # everything else is JSON / YAML / XML -> shared structural sniffer
        return self._auto(text, ext, byte_size, encoding, lc)

    # --- bencode (.torrent) ---------------------------------------------
    def _bencode(self, data: bytes, ext: str) -> Optional[Dict[str, Any]]:
        try:
            value, end = _bdecode(data, 0)
        except Exception:
            return None
        if not isinstance(value, dict):
            return None
        fam, label = self.meta(ext)
        top = _section("metainfo", "manifest", 1)
        files_sec = _section("files", "file-list", 2)
        props: List[Tuple] = []

        def _s(v):
            if isinstance(v, bytes):
                return v.decode("utf-8", "replace")
            return v

        info = value.get(b"info", {}) if isinstance(value.get(b"info"), dict) else {}
        for key in (
            b"announce",
            b"created by",
            b"creation date",
            b"comment",
            b"encoding",
        ):
            if key in value:
                props.append(("torrent", _s(key), _s(value[key])))
        # info dictionary -> one record with typed fields
        fields = []
        ordv = 0
        for k in (b"name", b"piece length", b"length", b"private", b"source"):
            if k in info:
                fields.append(_field(_s(k), _s(info[k]), ordv))
                ordv += 1
        if b"pieces" in info and isinstance(info[b"pieces"], bytes):
            fields.append(
                _field("piece_count", len(info[b"pieces"]) // 20, ordv, ftype="INT")
            )
            ordv += 1
        top["records"].append(_record("info", _s(info.get(b"name")), fields))
        # multi-file torrents
        flist = info.get(b"files")
        if isinstance(flist, list):
            for i, fe in enumerate(flist):
                if not isinstance(fe, dict):
                    continue
                pth = fe.get(b"path")
                name = (
                    "/".join(_s(p) for p in pth) if isinstance(pth, list) else _s(pth)
                )
                ff = [
                    _field("path", name, 0),
                    _field("length", _s(fe.get(b"length")), 1, ftype="INT"),
                ]
                files_sec["records"].append(_record("file", name, ff))
                if i >= tf._RECORD_BUDGET:
                    break
        sections = [top] + ([files_sec] if files_sec["records"] else [])
        return _profile(
            self.KIND,
            fam,
            label,
            "bencode",
            sections=sections,
            detected_via="content",
            byte_size=len(data),
            line_count=0,
            properties=props,
        )

    # --- HTML5 AppCache --------------------------------------------------
    def _appcache(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        cur = "CACHE"
        secs: Dict[str, Dict[str, Any]] = {}
        order = 0
        for ln, raw in enumerate(_lines(text), start=1):
            line = raw.strip()
            if not line or line == "CACHE MANIFEST" or line.startswith("#"):
                continue
            m = re.match(r"^(CACHE|NETWORK|FALLBACK|SETTINGS):\s*$", line)
            if m:
                cur = m.group(1)
                continue
            sec = secs.get(cur)
            if sec is None:
                order += 1
                sec = _section(cur, "cache-section", order)
                secs[cur] = sec
            if cur == "FALLBACK" and " " in line:
                a, b = line.split(None, 1)
                flds = [_field("online_url", a, 0), _field("fallback_url", b, 1)]
            else:
                flds = [_field("url", line, 0)]
            sec["records"].append(
                _record(cur.lower() + "-entry", line, flds, start_line=ln, text=line)
            )
        return _profile(
            self.KIND,
            fam,
            label,
            "appcache",
            sections=list(secs.values()),
            byte_size=byte_size,
            line_count=lc,
        )

    # --- key: value manifests (JAD, BagIt) ------------------------------
    def _kv_colon(self, text, ext, byte_size, encoding, lc, rtype):
        fam, label = self.meta(ext)
        sec = _section("attributes", "key-value", 1)
        for ln, raw in enumerate(_lines(text), start=1):
            line = raw.rstrip()
            if not line or line.lstrip().startswith("#"):
                continue
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if not k:
                continue
            sec["records"].append(_record(rtype, k, [_field(k, v, 0)], start_line=ln))
        return _profile(
            self.KIND,
            fam,
            label,
            "keyvalue",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status="ok" if sec["records"] else "partial",
        )

    # --- PowerShell data (.psd1) ----------------------------------------
    _PSD1_KV = re.compile(r"(?m)^\s*([A-Za-z_][\w]*)\s*=\s*(.+?)\s*$")

    def _psd1(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("hashtable", "powershell-data", 1)
        for m in self._PSD1_KV.finditer(text):
            k, v = m.group(1), m.group(2).rstrip(";")
            v = v.strip().strip("'\"")
            sec["records"].append(_record("entry", k, [_field(k, v, 0)]))
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        return _profile(
            self.KIND,
            fam,
            label,
            "psd1",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status="ok" if sec["records"] else "partial",
        )

    # --- Ruby gem / pod specs -------------------------------------------
    _SPEC_ASSIGN = re.compile(r"(?m)^\s*(?:\w+)\.(\w+)\s*=\s*(['\"])(.*?)\2")
    _SPEC_DEP = re.compile(
        r"(?m)^\s*(?:\w+)\.(?:add_(?:runtime_|development_)?dependency|dependency)\s*"
        r"(['\"])(.*?)\1\s*(?:,\s*(['\"])(.*?)\3)?"
    )

    def _ruby_spec(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        meta = _section("spec", "gem-metadata", 1)
        deps = _section("dependencies", "dependency-list", 2)
        for m in self._SPEC_ASSIGN.finditer(text):
            attr, val = m.group(1), m.group(3)
            meta["records"].append(_record("attribute", attr, [_field(attr, val, 0)]))
        for m in self._SPEC_DEP.finditer(text):
            name, ver = m.group(2), m.group(4) or ""
            deps["records"].append(
                _record(
                    "dependency",
                    name,
                    [_field("name", name, 0), _field("requirement", ver, 1)],
                )
            )
        secs = [s for s in (meta, deps) if s["records"]]
        return _profile(
            self.KIND,
            fam,
            label,
            "ruby-dsl",
            sections=secs,
            byte_size=byte_size,
            line_count=lc,
            status="ok" if secs else "partial",
        )

    # --- go.sum ----------------------------------------------------------
    def _gosum(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("checksums", "module-checksum", 1)
        for ln, raw in enumerate(_lines(text), start=1):
            parts = raw.split()
            if len(parts) != 3:
                continue
            module, version, h = parts
            sec["records"].append(
                _record(
                    "checksum",
                    module,
                    [
                        _field("module", module, 0),
                        _field("version", version, 1),
                        _field(
                            "hash",
                            h,
                            2,
                            ftype="HEX" if h.startswith("h1:") else "STRING",
                        ),
                    ],
                    start_line=ln,
                )
            )
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        return _profile(
            self.KIND,
            fam,
            label,
            "gosum",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status="ok" if sec["records"] else "partial",
        )

    # --- cabal (.hackage) ------------------------------------------------
    _CABAL_KV = re.compile(r"(?m)^([A-Za-z][\w-]*)\s*:\s*(.*)$")

    def _cabal(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("package", "cabal-field", 1)
        for m in self._CABAL_KV.finditer(text):
            k, v = m.group(1).strip(), m.group(2).strip()
            if (
                not k
                or k[0].islower()
                and k
                not in (
                    "name",
                    "version",
                    "license",
                    "author",
                    "maintainer",
                    "synopsis",
                    "category",
                    "build-type",
                    "cabal-version",
                )
            ):
                # keep only top-level fields (indented continuations skipped)
                if m.start() != 0 and text[m.start() - 1] not in "\n":
                    continue
            sec["records"].append(_record("field", k, [_field(k, v, 0)]))
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        return _profile(
            self.KIND,
            fam,
            label,
            "cabal",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status="ok" if sec["records"] else "partial",
        )


# ===========================================================================
# 2. query languages
# ===========================================================================
class QueryParser(DocumentTypeParser):
    """Query-language sources.

    A real light tokenizer splits the source into statements, classifies each by
    its leading verb (SQL DML/DDL, DAX ``EVALUATE``/``DEFINE``, PromQL
    expressions), and extracts referenced identifiers (the tables / measures /
    streams after ``FROM`` / ``JOIN`` / ``INTO`` / ``UPDATE`` / ``TABLE``). Pipe
    dialects (KQL, Splunk SPL) are decomposed by their ``|`` operator stages.
    """

    KIND = "query"
    EXTENSIONS = (
        ".aql",
        ".dax",
        ".dml",
        ".esql",
        ".kql",
        ".ksql",
        ".migration",
        ".n1ql",
        ".plsql",
        ".promql",
        ".spl",
        ".tsql",
    )
    LABELS = {
        ".aql": ("aql", "ArangoDB AQL query"),
        ".dax": ("dax", "Power BI DAX query"),
        ".dml": ("sql", "Data Manipulation Language script"),
        ".esql": ("esql", "IBM ESQL / Elasticsearch SQL"),
        ".kql": ("kql", "Kusto / KQL query"),
        ".ksql": ("ksql", "ksqlDB streaming query"),
        ".migration": ("sql", "database migration script"),
        ".n1ql": ("n1ql", "Couchbase N1QL query"),
        ".plsql": ("plsql", "Oracle PL/SQL"),
        ".promql": ("promql", "Prometheus PromQL expression"),
        ".spl": ("spl", "Splunk SPL search"),
        ".tsql": ("tsql", "T-SQL (SQL Server) script"),
    }
    _PIPE = {".kql", ".spl"}
    _SQLISH = {
        ".dml",
        ".esql",
        ".ksql",
        ".migration",
        ".n1ql",
        ".plsql",
        ".tsql",
        ".aql",
    }
    _VERB = re.compile(r"^\s*(\w+)")
    _IDENT_AFTER = re.compile(
        r"\b(?:FROM|JOIN|INTO|UPDATE|TABLE|VIEW|INDEX|DATABASE|STREAM|DELETE\s+FROM)\s+"
        r"([`\"\[]?[\w.$#]+[`\"\]]?)",
        re.IGNORECASE,
    )

    def parse(self, path, data, text, ext, encoding, line_count):
        if tf._looks_binary(data):
            return self._forensic(ext, data, "binary payload under a query extension")
        byte_size = len(data)
        if ext in self._PIPE:
            return self._pipe(text, ext, byte_size, encoding, line_count)
        if ext == ".dax":
            return self._dax(text, ext, byte_size, encoding, line_count)
        if ext == ".promql":
            return self._promql(text, ext, byte_size, encoding, line_count)
        return self._sql(text, ext, byte_size, encoding, line_count)

    # --- SQL-ish statement splitter -------------------------------------
    def _strip_sql_comments(self, text: str) -> str:
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        text = re.sub(r"(?m)--.*$", "", text)
        return text

    def _split_statements(self, text: str) -> List[str]:
        out, buf, i, n = [], [], 0, len(text)
        in_s = None
        while i < n:
            c = text[i]
            if in_s:
                buf.append(c)
                if c == in_s:
                    in_s = None
                elif c == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
            elif c in "'\"":
                in_s = c
                buf.append(c)
            elif c == ";":
                stmt = "".join(buf).strip()
                if stmt:
                    out.append(stmt)
                buf = []
            else:
                buf.append(c)
            i += 1
        tail = "".join(buf).strip()
        if tail:
            out.append(tail)
        return out

    def _sql(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        clean = self._strip_sql_comments(text)
        sec = _section("statements", "statement-list", 1)
        props: List[Tuple] = []
        verbs: Dict[str, int] = {}
        for idx, stmt in enumerate(self._split_statements(clean)):
            m = self._VERB.match(stmt)
            verb = m.group(1).upper() if m else "STATEMENT"
            verbs[verb] = verbs.get(verb, 0) + 1
            idents = []
            for im in self._IDENT_AFTER.finditer(stmt):
                tok = im.group(1).strip('`"[]')
                if tok and tok.upper() not in ("SELECT", "WHERE"):
                    idents.append(tok)
            fields = [_field("statement_type", verb, 0)]
            for j, ident in enumerate(_uniq(idents)[:32]):
                fields.append(_field("references", ident, j + 1))
            sec["records"].append(
                _record(verb.lower(), verb, fields, text=stmt[:_PREVIEW])
            )
            if idx >= tf._RECORD_BUDGET:
                break
        for v, c in sorted(verbs.items()):
            props.append(("statement_verbs", v, c))
        return _profile(
            self.KIND,
            fam,
            label,
            "sql",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            properties=props,
            status="ok" if sec["records"] else "partial",
        )

    # --- pipe dialects (KQL / SPL) --------------------------------------
    def _pipe(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("queries", "pipe-query", 1)
        # a query is a run of non-blank, non-comment lines; stages split on '|'
        blocks, cur = [], []
        for raw in _lines(text):
            line = raw.rstrip()
            s = line.strip()
            if not s or s.startswith("//") or s.startswith("#"):
                if cur:
                    blocks.append("\n".join(cur))
                    cur = []
                continue
            cur.append(line)
        if cur:
            blocks.append("\n".join(cur))
        for qi, block in enumerate(blocks):
            stages = [
                st.strip() for st in re.split(r"(?<!\|)\|(?!\|)", block) if st.strip()
            ]
            fields = [_field("stage_count", len(stages), 0, ftype="INT")]
            for si, st in enumerate(stages[:64]):
                op = (
                    self._VERB.match(st).group(1)
                    if self._VERB.match(st)
                    else st.split()[0] if st.split() else "stage"
                )
                fields.append(_field(f"stage{si}", op, si + 1))
            sec["records"].append(
                _record("query", f"query{qi + 1}", fields, text=block[:_PREVIEW])
            )
            if qi >= tf._RECORD_BUDGET:
                break
        return _profile(
            self.KIND,
            fam,
            label,
            "pipe",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status="ok" if sec["records"] else "partial",
        )

    # --- DAX -------------------------------------------------------------
    _DAX_DEF = re.compile(
        r"(?im)^\s*(DEFINE|EVALUATE|ORDER\s+BY|MEASURE|VAR|COLUMN|TABLE)\b"
    )

    def _dax(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("dax", "dax-block", 1)
        for ln, raw in enumerate(_lines(text), start=1):
            m = self._DAX_DEF.match(raw)
            if not m:
                continue
            kw = re.sub(r"\s+", " ", m.group(1).upper())
            sec["records"].append(
                _record(
                    kw.lower().replace(" ", "_"),
                    kw,
                    [_field("keyword", kw, 0)],
                    start_line=ln,
                    text=raw.strip()[:_PREVIEW],
                )
            )
        if not sec["records"]:
            # a bare measure expression -> single record
            sec["records"].append(
                _record(
                    "expression", None, [_field("expression", text.strip()[:2048], 0)]
                )
            )
        return _profile(
            self.KIND,
            fam,
            label,
            "dax",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
        )

    # --- PromQL ----------------------------------------------------------
    _METRIC = re.compile(r"\b([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(?:\{|\()")
    _FUNC = re.compile(
        r"\b(rate|sum|avg|min|max|count|increase|histogram_quantile|"
        r"irate|delta|deriv|predict_linear|topk|bottomk|quantile|"
        r"stddev|stdvar|absent|label_replace|by|without)\b",
        re.IGNORECASE,
    )

    def _promql(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("expressions", "promql-expr", 1)
        for ln, raw in enumerate(_lines(text), start=1):
            expr = raw.strip()
            if not expr or expr.startswith("#"):
                continue
            metrics = _uniq(self._METRIC.findall(expr))
            funcs = _uniq(m.lower() for m in self._FUNC.findall(expr))
            fields = [_field("expression", expr, 0)]
            for i, mtr in enumerate(metrics[:32]):
                fields.append(_field("metric", mtr, i + 1))
            for i, fn in enumerate(funcs[:32]):
                fields.append(_field("function", fn, 100 + i))
            sec["records"].append(
                _record("expression", None, fields, start_line=ln, text=expr[:_PREVIEW])
            )
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        return _profile(
            self.KIND,
            fam,
            label,
            "promql",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status="ok" if sec["records"] else "partial",
        )


# ===========================================================================
# 3. makefiles
# ===========================================================================
class MakefileParser(DocumentTypeParser):
    """make / automake / MMS build descriptions.

    Real make grammar: variable assignments (``=`` ``:=`` ``?=`` ``+=`` ``::=``),
    rules (``target [target...]: prerequisites`` with tab-indented recipe lines),
    and directives (``include`` / ``ifeq`` / ``ifdef`` / ``define`` / ``vpath``).
    """

    KIND = "makefile"
    EXTENSIONS = (".am", ".dep", ".mak", ".makefile", ".mk", ".mms")
    LABELS = {
        ".am": ("automake", "Automake Makefile.am"),
        ".dep": ("make", "make dependency fragment"),
        ".mak": ("make", "Makefile (.mak)"),
        ".makefile": ("make", "Makefile"),
        ".mk": ("make", "make fragment (.mk)"),
        ".mms": ("mms", "MMS / MMK description (VMS)"),
    }
    _ASSIGN = re.compile(r"^([A-Za-z_][\w.]*)\s*(::=|:=|\?=|\+=|=)\s*(.*)$")
    _RULE = re.compile(r"^([^\t:#=][^:=]*?):(?!=)\s*(.*)$")
    _DIRECTIVE = re.compile(
        r"^\s*(include|-include|sinclude|ifeq|ifneq|ifdef|ifndef|else|endif|"
        r"define|endef|vpath|export|unexport|override)\b\s*(.*)$"
    )

    def parse(self, path, data, text, ext, encoding, line_count):
        if tf._looks_binary(data):
            return self._forensic(
                ext, data, "binary payload under a makefile extension"
            )
        fam, label = self.meta(ext)
        v_sec = _section("variables", "assignment", 1)
        r_sec = _section("rules", "rule", 2)
        d_sec = _section("directives", "directive", 3)
        lines = _lines(text)
        i, n = 0, len(lines)
        while i < n:
            raw = lines[i]
            line = raw.rstrip()
            i += 1
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if raw.startswith("\t"):  # a recipe line without a preceding rule
                continue
            dm = self._DIRECTIVE.match(line)
            if dm:
                kw, rest = dm.group(1), dm.group(2).strip()
                d_sec["records"].append(
                    _record(
                        "directive",
                        kw,
                        [_field("directive", kw, 0), _field("argument", rest, 1)],
                    )
                )
                continue
            am = self._ASSIGN.match(line)
            if am:
                name, op, val = am.group(1), am.group(2), am.group(3).strip()
                v_sec["records"].append(
                    _record(
                        "variable",
                        name,
                        [
                            _field("name", name, 0),
                            _field("operator", op, 1),
                            _field("value", val, 2),
                        ],
                    )
                )
                continue
            rm = self._RULE.match(line)
            if rm and ":" in line:
                targets = rm.group(1).split()
                prereqs = rm.group(2).split()
                # count following tab-indented recipe lines
                recipe = 0
                while i < n and (lines[i].startswith("\t")):
                    recipe += 1
                    i += 1
                for t in targets:
                    fields = [
                        _field("target", t, 0),
                        _field("recipe_lines", recipe, 1, ftype="INT"),
                    ]
                    for j, p in enumerate(prereqs[:64]):
                        fields.append(_field("prerequisite", p, j + 2))
                    r_sec["records"].append(
                        _record("rule", t, fields, text=line[:_PREVIEW])
                    )
                continue
        secs = [s for s in (v_sec, r_sec, d_sec) if s["records"]]
        return _profile(
            self.KIND,
            fam,
            label,
            "make",
            sections=secs,
            byte_size=len(data),
            line_count=line_count,
            status="ok" if secs else "partial",
        )


# ===========================================================================
# 4. certificate / key / signature text
# ===========================================================================
class CertificateTextParser(DocumentTypeParser):
    """PEM containers, SSH key files and minisign signatures.

    Only *public structural* facts are recorded -- a PEM block's type & DER byte
    length, an SSH key's algorithm / comment / standard SHA-256 fingerprint, a
    signature's algorithm. Private-key body bytes are never decoded into secret
    content; the base64 payload itself is never stored.
    """

    KIND = "certificate_text"
    EXTENSIONS = (".authorized_keys", ".csr", ".known_hosts", ".minisig", ".pem")
    LABELS = {
        ".authorized_keys": ("ssh", "SSH authorized_keys"),
        ".csr": ("pem", "PKCS#10 certificate signing request"),
        ".known_hosts": ("ssh", "SSH known_hosts"),
        ".minisig": ("minisign", "minisign signature"),
        ".pem": ("pem", "PEM container"),
    }
    _PEM = re.compile(
        r"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----", re.DOTALL
    )

    def parse(self, path, data, text, ext, encoding, line_count):
        byte_size = len(data)
        if ext in (".pem", ".csr"):
            return self._pem(text, ext, byte_size, encoding, line_count)
        if ext == ".authorized_keys":
            return self._ssh_keys(
                text, ext, byte_size, encoding, line_count, host=False
            )
        if ext == ".known_hosts":
            return self._ssh_keys(text, ext, byte_size, encoding, line_count, host=True)
        return self._minisig(text, ext, byte_size, encoding, line_count)

    def _pem(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("pem-blocks", "pem-block", 1)
        for m in self._PEM.finditer(text):
            btype = m.group(1).strip()
            body = re.sub(r"\s+", "", m.group(2))
            try:
                der = base64.b64decode(body, validate=False)
                der_len = len(der)
            except (binascii.Error, ValueError):
                der_len = None
            secret = "PRIVATE KEY" in btype
            fields = [
                _field("block_type", btype, 0),
                _field("base64_chars", len(body), 1, ftype="INT"),
            ]
            if der_len is not None:
                fields.append(_field("der_bytes", der_len, 2, ftype="INT"))
            if secret:
                fields.append(_field("redacted", "private key body not decoded", 3))
            sec["records"].append(_record("pem_block", btype, fields))
        status = "ok" if sec["records"] else "partial"
        return _profile(
            self.KIND,
            fam,
            label,
            "pem",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status=status,
        )

    def _ssh_keys(self, text, ext, byte_size, encoding, lc, host):
        fam, label = self.meta(ext)
        sec = _section("keys", "ssh-key", 1)
        keytypes = (
            "ssh-rsa",
            "ssh-dss",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        )
        for ln, raw in enumerate(_lines(text), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            # find the key-type token (authorized_keys may prefix options)
            idx = next((k for k, p in enumerate(parts) if p in keytypes), None)
            if idx is None or idx + 1 >= len(parts):
                continue
            ktype = parts[idx]
            blob = parts[idx + 1]
            comment = " ".join(parts[idx + 2 :]) if idx + 2 < len(parts) else ""
            fields = [_field("key_type", ktype, 0)]
            if host:
                hosts = parts[0]
                fields.insert(0, _field("host", hosts, 0, ftype="STRING"))
                fields.append(
                    _field(
                        "hashed", str(hosts.startswith("|1|")).lower(), 9, ftype="BOOL"
                    )
                )
            try:
                dec = base64.b64decode(blob, validate=False)
                fp = hashlib.sha256(dec).digest()
                fields.append(
                    _field(
                        "fingerprint_sha256",
                        "SHA256:" + base64.b64encode(fp).decode().rstrip("="),
                        5,
                    )
                )
                fields.append(_field("key_bytes", len(dec), 6, ftype="INT"))
            except (binascii.Error, ValueError):
                pass
            if comment:
                fields.append(_field("comment", comment, 7))
            sec["records"].append(_record("ssh_key", ktype, fields, start_line=ln))
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        status = "ok" if sec["records"] else "partial"
        return _profile(
            self.KIND,
            fam,
            label,
            "ssh",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status=status,
        )

    def _minisig(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("signature", "minisign", 1)
        lines = [l for l in _lines(text) if l.strip()]
        untrusted = next(
            (
                l.split(":", 1)[1].strip()
                for l in lines
                if l.startswith("untrusted comment:")
            ),
            "",
        )
        trusted = next(
            (
                l.split(":", 1)[1].strip()
                for l in lines
                if l.startswith("trusted comment:")
            ),
            "",
        )
        b64 = [
            l
            for l in lines
            if not l.startswith(("untrusted comment:", "trusted comment:"))
        ]
        algo = ""
        if b64:
            try:
                raw = base64.b64decode(b64[0], validate=False)
                algo = raw[:2].decode("ascii", "replace")
            except (binascii.Error, ValueError):
                pass
        fields = [
            _field("algorithm", algo or "unknown", 0),
            _field("untrusted_comment", untrusted, 1),
            _field("trusted_comment", trusted, 2),
        ]
        sec["records"].append(_record("signature", algo or None, fields))
        return _profile(
            self.KIND,
            fam,
            label,
            "minisign",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
        )


# ===========================================================================
# 5. notebooks
# ===========================================================================
class NotebookParser(DocumentTypeParser):
    """Computational-notebook worksheets (non-Jupyter; ``.ipynb`` is JSON and is
    already handled by the data plane).

    Mathematica ``.nb`` ``Cell[...]`` expressions, wxMaxima ``.wxm`` cell markers,
    Sage ``.sagews`` cell sentinels and Maple ``.mw`` / ``.mws`` worksheets are
    each split into their cells; every cell becomes a record with its cell type.
    """

    KIND = "notebook"
    EXTENSIONS = (".mw", ".mws", ".nb", ".sagews", ".wxm")
    LABELS = {
        ".mw": ("maple", "Maple worksheet (XML)"),
        ".mws": ("maple", "Maple classic worksheet"),
        ".nb": ("mathematica", "Mathematica / Wolfram notebook"),
        ".sagews": ("sage", "Sage worksheet"),
        ".wxm": ("maxima", "wxMaxima worksheet"),
    }
    _NB_CELL = re.compile(r'Cell\[[^,\]]*,\s*"([A-Za-z]+)"')
    _WXM_CELL = re.compile(
        r"/\*\s*\[wxMaxima:\s*([\w ]+?)\s+start\s*\]\s*\*/(.*?)"
        r"/\*\s*\[wxMaxima:\s*[\w ]+?\s+end\s*\]\s*\*/",
        re.DOTALL,
    )

    def parse(self, path, data, text, ext, encoding, line_count):
        byte_size = len(data)
        if ext == ".nb":
            return self._mathematica(data, text, ext, byte_size, encoding, line_count)
        if ext == ".wxm":
            return self._wxmaxima(text, ext, byte_size, encoding, line_count)
        if ext == ".sagews":
            return self._sagews(text, ext, byte_size, encoding, line_count)
        return self._maple(text, data, ext, byte_size, encoding, line_count)

    def _mathematica(self, data, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        if tf._looks_binary(data) or not text.lstrip().startswith(("(*", "Notebook")):
            if tf._looks_binary(data):
                return self._forensic(ext, data, "binary Mathematica notebook")
        sec = _section("cells", "nb-cell", 1)
        counts: Dict[str, int] = {}
        for m in self._NB_CELL.finditer(text):
            ctype = m.group(1)
            counts[ctype] = counts.get(ctype, 0) + 1
            sec["records"].append(
                _record("cell", ctype, [_field("cell_type", ctype, 0)])
            )
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        props = [("cell_types", k, v) for k, v in sorted(counts.items())]
        return _profile(
            self.KIND,
            fam,
            label,
            "mathematica",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            properties=props,
            status="ok" if sec["records"] else "partial",
        )

    def _wxmaxima(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("cells", "wxm-cell", 1)
        for m in self._WXM_CELL.finditer(text):
            ctype = m.group(1).strip()
            body = m.group(2).strip()
            sec["records"].append(
                _record(
                    "cell", ctype, [_field("cell_type", ctype, 0)], text=body[:_PREVIEW]
                )
            )
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        return _profile(
            self.KIND,
            fam,
            label,
            "wxmaxima",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status="ok" if sec["records"] else "partial",
        )

    def _sagews(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        # Sage worksheets delimit cells with the marker U+FE20 (input) / U+FE21
        sec = _section("cells", "sagews-cell", 1)
        cells = re.split("[\ufe20\ufe21]", text)
        idx = 0
        for chunk in cells:
            chunk = chunk.strip("\ufe22\ufe23\n ")
            if not chunk:
                continue
            idx += 1
            sec["records"].append(
                _record(
                    "cell",
                    f"cell{idx}",
                    [_field("index", idx, 0, ftype="INT")],
                    text=chunk[:_PREVIEW],
                )
            )
            if idx >= tf._RECORD_BUDGET:
                break
        if not sec["records"]:  # no markers -> treat whole file as one cell
            sec["records"].append(
                _record(
                    "cell",
                    "cell1",
                    [_field("index", 1, 0, ftype="INT")],
                    text=text[:_PREVIEW],
                )
            )
        return _profile(
            self.KIND,
            fam,
            label,
            "sage",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
        )

    def _maple(self, text, data, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        stripped = text.lstrip()
        if stripped.startswith("<"):
            return self._auto(text, ext, byte_size, encoding, lc)
        # Classic .mws: line-oriented; capture executable-group markers.
        sec = _section("groups", "maple-group", 1)
        for ln, raw in enumerate(_lines(text), start=1):
            if (
                raw.strip().startswith("{")
                or "MPLDOC" in raw
                or raw.strip().startswith(">")
            ):
                sec["records"].append(
                    _record(
                        "group",
                        None,
                        [_field("text", raw.strip()[:512], 0)],
                        start_line=ln,
                    )
                )
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        status = "ok" if sec["records"] else "partial"
        return _profile(
            self.KIND,
            fam,
            label,
            "maple",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status=status,
        )


# ===========================================================================
# 6. misc document files
# ===========================================================================
class DocumentFileParser(DocumentTypeParser):
    """FDF form data, Google-Doc shortcut files and Palm markup.

    ``.fdf`` PDF form-data: ``/T (field) /V (value)`` dictionaries -> records.
    ``.gdoc`` / ``.gslides``: tiny JSON pointers (url / doc_id / resource_id) ->
    the shared JSON sniffer. ``.pml`` Palm markup: escape-code lines and text.
    """

    KIND = "document"
    EXTENSIONS = (".fdf", ".gdoc", ".gslides", ".pml")
    LABELS = {
        ".fdf": ("fdf", "PDF Forms Data Format"),
        ".gdoc": ("json", "Google Docs shortcut"),
        ".gslides": ("json", "Google Slides shortcut"),
        ".pml": ("pml", "Palm Markup Language"),
    }
    _FDF_FIELD = re.compile(
        r"/T\s*\((?P<t>(?:\\.|[^()\\])*)\)"
        r"(?:.*?/V\s*(?:\((?P<v>(?:\\.|[^()\\])*)\)|/(?P<vn>\w+)))?",
        re.DOTALL,
    )

    def parse(self, path, data, text, ext, encoding, line_count):
        byte_size = len(data)
        if ext in (".gdoc", ".gslides"):
            return self._auto(text, ext, byte_size, encoding, line_count)
        if ext == ".fdf":
            return self._fdf(text, ext, byte_size, encoding, line_count)
        return self._pml(text, data, ext, byte_size, encoding, line_count)

    def _fdf(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("form-fields", "fdf-field", 1)
        for m in self._FDF_FIELD.finditer(text):
            name = (m.group("t") or "").strip()
            if not name:
                continue
            val = m.group("v")
            if val is None and m.group("vn"):
                val = "/" + m.group("vn")
            sec["records"].append(
                _record(
                    "field",
                    name,
                    [_field("field_name", name, 0), _field("value", (val or ""), 1)],
                )
            )
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        status = "ok" if sec["records"] else "partial"
        return _profile(
            self.KIND,
            fam,
            label,
            "fdf",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status=status,
        )

    _PML_TAG = re.compile(r"\\(\w)")

    def _pml(self, text, data, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        if tf._looks_binary(data):
            return self._forensic(ext, data, "binary payload under .pml")
        sec = _section("markup", "pml-line", 1)
        tagcount: Dict[str, int] = {}
        for ln, raw in enumerate(_lines(text), start=1):
            line = raw.rstrip()
            if not line.strip():
                continue
            tags = self._PML_TAG.findall(line)
            for t in tags:
                tagcount[t] = tagcount.get(t, 0) + 1
            sec["records"].append(
                _record(
                    "line",
                    None,
                    [
                        _field("text", line[:512], 0),
                        _field("tag_count", len(tags), 1, ftype="INT"),
                    ],
                    start_line=ln,
                )
            )
            if len(sec["records"]) >= tf._RECORD_BUDGET:
                break
        props = [("pml_tags", t, c) for t, c in sorted(tagcount.items())]
        return _profile(
            self.KIND,
            fam,
            label,
            "pml",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            properties=props,
            status="ok" if sec["records"] else "partial",
        )


# ===========================================================================
# 7. license / copyright / notice
# ===========================================================================
class LicenseParser(DocumentTypeParser):
    """SPDX identifiers, Debian DEP-5 ``copyright`` paragraphs and NOTICE text.

    Detects an ``SPDX-License-Identifier``, fingerprints the license family from
    signature phrases (MIT / Apache-2.0 / GPL / BSD / MPL / ISC), and extracts
    ``Copyright (c) YEAR HOLDER`` lines. A Debian ``copyright`` file in DEP-5
    format is decomposed into its RFC822 paragraphs.
    """

    KIND = "license"
    EXTENSIONS = (".copyright", ".license", ".notice")
    LABELS = {
        ".copyright": ("dep5", "copyright / DEP-5 file"),
        ".license": ("license", "license text"),
        ".notice": ("notice", "NOTICE attribution file"),
    }
    _SPDX = re.compile(r"SPDX-License-Identifier:\s*([^\s]+)")
    _COPYRIGHT = re.compile(
        r"(?im)^\s*(?:Copyright|\(c\)|©)\s*(?:\(c\)|©)?\s*"
        r"((?:\d{4}(?:\s*[-,]\s*\d{4})*)?\s*.+?)\s*$"
    )
    _FAMILIES = [
        ("Apache-2.0", "Apache License"),
        ("MIT", "Permission is hereby granted, free of charge"),
        ("GPL", "GNU GENERAL PUBLIC LICENSE"),
        ("LGPL", "GNU LESSER GENERAL PUBLIC LICENSE"),
        ("AGPL", "GNU AFFERO GENERAL PUBLIC LICENSE"),
        ("MPL-2.0", "Mozilla Public License Version 2.0"),
        ("BSD", "Redistribution and use in source and binary forms"),
        ("ISC", "ISC License"),
        (
            "Unlicense",
            "This is free and unencumbered software released into the public domain",
        ),
    ]

    def parse(self, path, data, text, ext, encoding, line_count):
        byte_size = len(data)
        if tf._looks_binary(data):
            return self._forensic(ext, data, "binary payload under a license extension")
        fam, label = self.meta(ext)
        if ext == ".copyright" and re.search(r"(?im)^Format:\s*https?://", text):
            return self._dep5(text, ext, byte_size, encoding, line_count)

        props: List[Tuple] = []
        spdx = self._SPDX.search(text)
        if spdx:
            props.append(("license", "spdx_id", spdx.group(1)))
        detected = [name for name, sig in self._FAMILIES if sig.lower() in text.lower()]
        for d in detected:
            props.append(("license", "detected_family", d))

        sec = _section("copyright", "copyright-line", 1)
        seen = set()
        for m in self._COPYRIGHT.finditer(text):
            holder = m.group(1).strip()
            if len(holder) < 3 or holder.lower() in seen:
                continue
            seen.add(holder.lower())
            yrs = re.findall(r"\d{4}", holder)
            fields = [_field("holder", holder, 0)]
            if yrs:
                fields.append(_field("year", yrs[0], 1, ftype="INT"))
            sec["records"].append(_record("copyright", holder, fields))
            if len(sec["records"]) >= 2000:
                break
        secs = [sec] if sec["records"] else []
        status = "ok" if (secs or props) else "partial"
        return _profile(
            self.KIND,
            fam,
            label,
            "license",
            sections=secs,
            byte_size=byte_size,
            line_count=line_count,
            properties=props,
            status=status,
        )

    def _dep5(self, text, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sec = _section("paragraphs", "dep5-paragraph", 1)
        for pi, para in enumerate(re.split(r"\n\s*\n", text)):
            fields = []
            label_field = None
            ordv = 0
            for fm in re.finditer(r"(?m)^([A-Za-z][\w-]*):\s*(.*)$", para):
                k, v = fm.group(1), fm.group(2).strip()
                fields.append(_field(k, v, ordv))
                ordv += 1
                if k in ("Files", "License", "Format") and label_field is None:
                    label_field = f"{k}={v}"
            if fields:
                sec["records"].append(_record("paragraph", label_field, fields))
            if pi >= tf._RECORD_BUDGET:
                break
        return _profile(
            self.KIND,
            fam,
            label,
            "dep5",
            sections=[sec],
            byte_size=byte_size,
            line_count=lc,
            status="ok" if sec["records"] else "partial",
        )


# ===========================================================================
# 8. diffs / patches
# ===========================================================================
class DiffParser(DocumentTypeParser):
    """Unified & context diffs and ``.rej`` reject files.

    Each changed file becomes a section; each ``@@ -a,b +c,d @@`` hunk becomes a
    record whose fields carry the old/new ranges and the added / removed line
    counts. ``git diff`` extended headers (rename / mode / index) are captured as
    file-level fields.
    """

    KIND = "diff"
    EXTENSIONS = (".diff", ".patch", ".rej")
    LABELS = {
        ".diff": ("diff", "unified/context diff"),
        ".patch": ("patch", "patch file"),
        ".rej": ("diff", "patch reject file"),
    }
    _HUNK = re.compile(r"^@@+\s*-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s*@@")
    _GIT = re.compile(r"^diff --git a/(.+?) b/(.+)$")
    _OLD = re.compile(r"^--- (?:a/)?(.+?)(?:\t.*)?$")
    _NEW = re.compile(r"^\+\+\+ (?:b/)?(.+?)(?:\t.*)?$")

    def parse(self, path, data, text, ext, encoding, line_count):
        if tf._looks_binary(data):
            return self._forensic(ext, data, "binary payload under a diff extension")
        fam, label = self.meta(ext)
        lines = _lines(text)
        sections: List[Dict[str, Any]] = []
        cur: Optional[Dict[str, Any]] = None
        ordinal = 0
        total_add = total_del = total_hunks = 0
        cur_hunk: Optional[Dict[str, Any]] = None
        add = rem = 0

        def _close_hunk():
            nonlocal cur_hunk, add, rem
            if cur_hunk is not None:
                cur_hunk["fields"].append(_field("added", add, 90, ftype="INT"))
                cur_hunk["fields"].append(_field("removed", rem, 91, ftype="INT"))
                cur_hunk = None
                add = rem = 0

        def _new_section(name):
            nonlocal cur, ordinal
            _close_hunk()
            ordinal += 1
            cur = _section(name, "file-diff", ordinal)
            sections.append(cur)
            return cur

        for ln, raw in enumerate(lines, start=1):
            gm = self._GIT.match(raw)
            if gm:
                _new_section(gm.group(2))
                continue
            om = self._OLD.match(raw)
            if om and (raw.startswith("--- ")):
                if cur is None or cur["records"] or cur.get("_named"):
                    _new_section(om.group(1))
                cur["_named"] = True
                cur["records"] and None
                continue
            nm = self._NEW.match(raw)
            if nm and raw.startswith("+++ "):
                if cur is not None:
                    cur["name"] = nm.group(1)[:256]
                    cur["path"] = nm.group(1)[:512]
                continue
            hm = self._HUNK.match(raw)
            if hm:
                if cur is None:
                    _new_section(f"hunk-group-{ordinal + 1}")
                _close_hunk()
                total_hunks += 1
                os_, oc = int(hm.group(1)), int(hm.group(2) or 1)
                ns_, nc = int(hm.group(3)), int(hm.group(4) or 1)
                fields = [
                    _field("old_start", os_, 0, ftype="INT"),
                    _field("old_count", oc, 1, ftype="INT"),
                    _field("new_start", ns_, 2, ftype="INT"),
                    _field("new_count", nc, 3, ftype="INT"),
                ]
                rec = _record(
                    "hunk",
                    f"@@ -{os_},{oc} +{ns_},{nc} @@",
                    fields,
                    start_line=ln,
                    text=raw.strip()[:_PREVIEW],
                )
                cur["records"].append(rec)
                cur_hunk = rec
                continue
            if cur_hunk is not None:
                if raw.startswith("+") and not raw.startswith("+++"):
                    add += 1
                    total_add += 1
                elif raw.startswith("-") and not raw.startswith("---"):
                    rem += 1
                    total_del += 1
        _close_hunk()
        for s in sections:
            s.pop("_named", None)
        props = [
            ("diff", "files_changed", len(sections)),
            ("diff", "hunks", total_hunks),
            ("diff", "lines_added", total_add),
            ("diff", "lines_removed", total_del),
        ]
        status = "ok" if sections else "partial"
        return _profile(
            self.KIND,
            fam,
            label,
            "diff",
            sections=sections,
            byte_size=len(data),
            line_count=line_count,
            properties=props,
            status=status,
        )


# ===========================================================================
# bencode decoder (stdlib-only, for .torrent)
# ===========================================================================
def _bdecode(data: bytes, i: int) -> Tuple[Any, int]:
    c = data[i : i + 1]
    if c == b"i":
        j = data.index(b"e", i)
        return int(data[i + 1 : j]), j + 1
    if c == b"l":
        i += 1
        out = []
        while data[i : i + 1] != b"e":
            v, i = _bdecode(data, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while data[i : i + 1] != b"e":
            k, i = _bdecode(data, i)
            v, i = _bdecode(data, i)
            out[k] = v
        return out, i + 1
    if c.isdigit():
        colon = data.index(b":", i)
        length = int(data[i:colon])
        start = colon + 1
        return data[start : start + length], start + length
    raise ValueError(f"invalid bencode at {i}")


def _uniq(seq) -> List[str]:
    seen, out = set(), []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


# ===========================================================================
# registry
# ===========================================================================
_PARSER_CLASSES = (
    ManifestParser,
    QueryParser,
    MakefileParser,
    CertificateTextParser,
    NotebookParser,
    DocumentFileParser,
    LicenseParser,
    DiffParser,
)


def build_registry() -> Dict[str, DocumentTypeParser]:
    """ext -> shared parser instance, with a hard collision guard."""
    reg: Dict[str, DocumentTypeParser] = {}
    for cls in _PARSER_CLASSES:
        inst = cls()
        for ext in cls.EXTENSIONS:
            e = ext.lower()
            if e in reg:
                raise RuntimeError(
                    f"document extension {e} claimed by both "
                    f"{reg[e].__class__.__name__} and {cls.__name__}"
                )
            reg[e] = inst
    return reg
