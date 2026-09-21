"""
Per-type parsers for the ``misc`` analysis plane.

This module implements the *child-class hierarchy* the MiscAnalyzer plane is
built around: a small abstract :class:`MiscTypeParser` super-class and one
concrete child per residual content kind still unclaimed after the code / schema
/ database / archive / binary / data / config / text / markup / document planes
had taken their universes:

    StylesheetParser     1 ext   .qss    Qt Style Sheet (CSS-like widget styling)
    VideoProjectParser   2 exts  .osp    OpenShot project (JSON clip timeline)
                                 .tscproj Camtasia project (JSON scene/media tree)
    SqlDumpParser        1 ext   .pgdump PostgreSQL pg_dump SQL script

Every child runs a *real*, pure-stdlib, structure-aware parser that decomposes a
file into the canonical shape the MiscAnalyzer flattens
(document -> sections -> records -> fields, plus file-level properties). The
generic serialization / builder helpers (``_profile`` / ``_section`` /
``_record`` / ``_field`` / ``_forensic`` / byte helpers) are shared with -- and
imported from -- the verified ``text`` plane
(:mod:`..text.textual_formats`) so this plane never re-implements that machinery.

Honesty contract (identical to the text / config / document planes): content is
sniffed first, an inherently-binary payload degrades to an honest forensic byte
profile with *no fabricated records*, the raw payload is never stored, and a
partial parse is reported ``partial`` -- never stubbed or invented.
"""
from __future__ import annotations

import json
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
_PREVIEW = tf._PREVIEW


def _lines(text: str) -> List[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _split_top_commas(s: str) -> List[str]:
    """Split on commas that are not nested inside ()/[] (SQL column lists)."""
    out: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


# ===========================================================================
# base
# ===========================================================================
class MiscTypeParser:
    """Abstract parent for every misc-kind parser."""

    KIND = "misc"
    EXTENSIONS: Tuple[str, ...] = ()
    #: ext -> (syntax_family, human format label)
    LABELS: Dict[str, Tuple[str, str]] = {}

    def meta(self, ext: str) -> Tuple[str, str]:
        return self.LABELS.get(ext, (self.KIND, ext.lstrip(".") or self.KIND))

    def parse(self, path: Path, data: bytes, text: str, ext: str,
              encoding: str, line_count: int) -> Dict[str, Any]:
        raise NotImplementedError

    # helpers ---------------------------------------------------------------
    def _forensic(self, ext: str, data: bytes, note: str,
                  via: str = "extension") -> Dict[str, Any]:
        fam, label = self.meta(ext)
        return _forensic(self.KIND, fam, label, data, len(data), note, via=via)

    def _auto(self, text: str, ext: str, byte_size: int, encoding: str,
              lc: int) -> Dict[str, Any]:
        fam, label = self.meta(ext)
        prof = tf._e_auto(text, self.KIND, fam, label, byte_size, encoding, lc)
        prof["format"] = label
        prof["family"] = fam
        return prof


# ===========================================================================
# 1. Qt Style Sheets (.qss)
# ===========================================================================
class StylesheetParser(MiscTypeParser):
    """Qt Style Sheet (.qss): a CSS-flavored widget-styling grammar.

    Real parse: strip ``/* ... */`` comments, split into ``selector { decls }``
    rules by a brace scan (QSS never nests braces), split each rule body into
    ``property: value`` declarations on the first colon. Every rule becomes a
    record (its selector the label, one field per declaration); a census of
    selector kinds (widget class / ``#id`` / ``.class`` / ``::subcontrol`` /
    ``:pseudo-state``) and the distinct property set are recorded as properties.
    """

    KIND = "stylesheet"
    EXTENSIONS = (".qss",)
    LABELS = {".qss": ("qss", "Qt Style Sheet")}

    _WIDGET = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\b")
    _ID = re.compile(r"#([A-Za-z_][\w-]*)")
    _CLASS = re.compile(r"\.([A-Za-z_][\w-]*)")

    def parse(self, path, data, text, ext, encoding, line_count):
        if tf._looks_binary(data):
            return self._forensic(ext, data, "binary payload under a .qss extension")
        fam, label = self.meta(ext)
        clean = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        rules_sec = _section("rules", "style-rule", 1)

        widget_sel = id_sel = class_sel = subcontrol = pseudo = 0
        decl_total = 0
        properties_seen: "dict[str, int]" = {}
        n = len(clean)
        i = 0
        sel_start = 0
        while i < n:
            ch = clean[i]
            if ch == "{":
                selector = clean[sel_start:i].strip()
                depth = 1
                j = i + 1
                while j < n and depth:
                    if clean[j] == "{":
                        depth += 1
                    elif clean[j] == "}":
                        depth -= 1
                    j += 1
                body = clean[i + 1:j - 1]
                self._emit_rule(rules_sec, selector, body, properties_seen)
                if selector:
                    for part in selector.split(","):
                        p = part.strip()
                        if not p:
                            continue
                        widget_sel += len(self._WIDGET.findall(p))
                        id_sel += len(self._ID.findall(p))
                        class_sel += len(self._CLASS.findall(p))
                        subcontrol += p.count("::")
                        pseudo += len(re.findall(r"(?<!:):(?!:)[A-Za-z]", p))
                i = j
                sel_start = j
                continue
            i += 1
        # declaration total from emitted records (each record's ordinal-0 field
        # is a declaration_count, so subtract it back out)
        decl_total = sum(len(r["fields"]) - 1 for r in rules_sec["records"])
        props = [
            ("stylesheet", "rule_count", len(rules_sec["records"])),
            ("stylesheet", "declaration_count", decl_total),
            ("stylesheet", "distinct_property_count", len(properties_seen)),
            ("selectors", "widget_class_selectors", widget_sel),
            ("selectors", "id_selectors", id_sel),
            ("selectors", "class_selectors", class_sel),
            ("selectors", "subcontrol_selectors", subcontrol),
            ("selectors", "pseudo_state_selectors", pseudo),
        ]
        for prop, cnt in sorted(properties_seen.items()):
            props.append(("property_histogram", prop, cnt))
        status = "ok" if rules_sec["records"] else "partial"
        return _profile(self.KIND, fam, label, "qss", sections=[rules_sec],
                        byte_size=len(data), line_count=line_count,
                        properties=props, status=status)

    def _emit_rule(self, sec, selector, body, properties_seen):
        fields = []
        decls = 0
        for raw in body.split(";"):
            decl = raw.strip()
            if not decl or ":" not in decl:
                continue
            prop, val = decl.split(":", 1)
            prop, val = prop.strip(), val.strip()
            if not prop:
                continue
            decls += 1
            properties_seen[prop] = properties_seen.get(prop, 0) + 1
            fields.append(_field(prop, val, decls))
        # ordinal-0 field carries the declaration count for the record
        head = [_field("declaration_count", decls, 0, ftype="INT")] + fields
        sec["records"].append(_record(
            "rule", selector or None, head, text=(selector or "")[:_PREVIEW]))


# ===========================================================================
# 2. Video-editor project files (.osp / .tscproj)
# ===========================================================================
class VideoProjectParser(MiscTypeParser):
    """JSON project files for video editors.

    ``.osp`` (OpenShot): a JSON document with ``clips`` / ``files`` / ``effects``
    / ``layers`` arrays plus project settings (fps, width, height, duration).
    ``.tscproj`` (Camtasia): a JSON document with a ``sourceBin`` media list and a
    ``timeline -> sceneTrack -> scenes[] -> csml -> tracks[] -> medias[]`` tree.
    Each is decomposed into real record sections with a genuine census; a
    non-JSON / binary payload degrades to an honest forensic profile.
    """

    KIND = "project"
    EXTENSIONS = (".osp", ".tscproj")
    LABELS = {
        ".osp": ("openshot", "OpenShot video project"),
        ".tscproj": ("camtasia", "Camtasia video project"),
    }

    def parse(self, path, data, text, ext, encoding, line_count):
        if tf._looks_binary(data):
            return self._forensic(ext, data, f"binary payload under a {ext} extension")
        try:
            doc = json.loads(text)
        except (ValueError, json.JSONDecodeError) as exc:
            return self._forensic(ext, data, f"invalid JSON project: {exc}")
        if not isinstance(doc, dict):
            fam, label = self.meta(ext)
            return _profile(self.KIND, fam, label, "json", sections=[],
                            byte_size=len(data), line_count=line_count,
                            status="partial", notes="JSON root is not an object")
        if ext == ".osp":
            return self._openshot(doc, ext, len(data), encoding, line_count)
        return self._camtasia(doc, ext, len(data), encoding, line_count)

    # --- OpenShot -------------------------------------------------------
    def _openshot(self, doc, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        clips = doc.get("clips") if isinstance(doc.get("clips"), list) else []
        files = doc.get("files") if isinstance(doc.get("files"), list) else []
        effects = doc.get("effects") if isinstance(doc.get("effects"), list) else []
        layers = doc.get("layers") if isinstance(doc.get("layers"), list) else []
        # effects may also be embedded per-clip
        embedded_fx = sum(len(c.get("effects", []))
                          for c in clips if isinstance(c, dict)
                          and isinstance(c.get("effects"), list))

        clips_sec = _section("clips", "timeline-clip", 1)
        for idx, c in enumerate(clips):
            if not isinstance(c, dict):
                continue
            fields = [
                _field("id", c.get("id"), 0),
                _field("title", c.get("title") or _basename(c.get("reader", {})), 1),
                _field("layer", c.get("layer"), 2, ftype="INT"),
                _field("position", c.get("position"), 3, ftype="FLOAT"),
                _field("start", c.get("start"), 4, ftype="FLOAT"),
                _field("end", c.get("end"), 5, ftype="FLOAT"),
            ]
            clips_sec["records"].append(_record("clip", c.get("id"), fields))
            if len(clips_sec["records"]) >= tf._RECORD_BUDGET:
                break

        files_sec = _section("files", "media-file", 2)
        for f in files:
            if not isinstance(f, dict):
                continue
            reader = f.get("reader") if isinstance(f.get("reader"), dict) else {}
            fields = [
                _field("id", f.get("id"), 0),
                _field("path", f.get("path") or reader.get("path"), 1),
                _field("media_type", f.get("media_type") or reader.get("media_type"), 2),
            ]
            files_sec["records"].append(_record("file", f.get("id"), fields))
            if len(files_sec["records"]) >= tf._RECORD_BUDGET:
                break

        fx_sec = _section("effects", "effect", 3)
        for e in effects:
            if not isinstance(e, dict):
                continue
            fx_sec["records"].append(_record("effect", e.get("id"), [
                _field("id", e.get("id"), 0),
                _field("type", e.get("type") or e.get("class_name"), 1),
            ]))
            if len(fx_sec["records"]) >= tf._RECORD_BUDGET:
                break

        fps = doc.get("fps") if isinstance(doc.get("fps"), dict) else {}
        fps_val = None
        if fps.get("num") and fps.get("den"):
            try:
                fps_val = round(float(fps["num"]) / float(fps["den"]), 4)
            except (TypeError, ZeroDivisionError):
                fps_val = None
        version = doc.get("version")
        if isinstance(version, dict):
            version = version.get("openshot-qt") or version.get("libopenshot") \
                or json.dumps(version)
        props = [
            ("project", "clip_count", len(clips_sec["records"])),
            ("project", "file_count", len(files_sec["records"])),
            ("project", "effect_count", len(fx_sec["records"]) + embedded_fx),
            ("project", "layer_count", len(layers)),
            ("project", "fps", fps_val),
            ("project", "width", doc.get("width")),
            ("project", "height", doc.get("height")),
            ("project", "duration", doc.get("duration")),
            ("project", "sample_rate", doc.get("sample_rate")),
            ("project", "channels", doc.get("channels")),
            ("project", "version", version),
        ]
        secs = [s for s in (clips_sec, files_sec, fx_sec) if s["records"]]
        return _profile(self.KIND, fam, label, "openshot", sections=secs,
                        detected_via="content", byte_size=byte_size,
                        line_count=lc, properties=props,
                        status="ok" if secs else "partial")

    # --- Camtasia -------------------------------------------------------
    def _camtasia(self, doc, ext, byte_size, encoding, lc):
        fam, label = self.meta(ext)
        sources = doc.get("sourceBin") if isinstance(doc.get("sourceBin"), list) else []
        src_sec = _section("sources", "media-source", 1)
        for s in sources:
            if not isinstance(s, dict):
                continue
            fields = [
                _field("id", s.get("id"), 0),
                _field("src", s.get("src"), 1),
            ]
            rect = s.get("rect")
            if isinstance(rect, list):
                fields.append(_field("rect", ",".join(str(x) for x in rect), 2))
            src_sec["records"].append(_record("source", s.get("id"), fields))
            if len(src_sec["records"]) >= tf._RECORD_BUDGET:
                break

        # timeline -> sceneTrack -> scenes[] -> csml -> tracks[] -> medias[]
        tracks_sec = _section("tracks", "timeline-track", 2)
        scene_count = track_count = media_count = 0
        timeline = doc.get("timeline") if isinstance(doc.get("timeline"), dict) else {}
        scene_track = timeline.get("sceneTrack") if isinstance(timeline.get("sceneTrack"), dict) else {}
        scenes = scene_track.get("scenes") if isinstance(scene_track.get("scenes"), list) else []
        for scene in scenes:
            if not isinstance(scene, dict):
                continue
            scene_count += 1
            csml = scene.get("csml") if isinstance(scene.get("csml"), dict) else {}
            tracks = csml.get("tracks") if isinstance(csml.get("tracks"), list) else []
            for ti, tr in enumerate(tracks):
                if not isinstance(tr, dict):
                    continue
                track_count += 1
                medias = tr.get("medias") if isinstance(tr.get("medias"), list) else []
                media_count += len(medias)
                tracks_sec["records"].append(_record("track", tr.get("trackIndex", ti), [
                    _field("track_index", tr.get("trackIndex", ti), 0, ftype="INT"),
                    _field("media_count", len(medias), 1, ftype="INT"),
                ]))
                if len(tracks_sec["records"]) >= tf._RECORD_BUDGET:
                    break

        authoring = doc.get("authoringClientName") if isinstance(
            doc.get("authoringClientName"), dict) else {}
        props = [
            ("project", "width", doc.get("width")),
            ("project", "height", doc.get("height")),
            ("project", "edit_rate", doc.get("editRate")),
            ("project", "video_frame_rate", doc.get("videoFormatFrameRate")),
            ("project", "source_count", len(src_sec["records"])),
            ("project", "scene_count", scene_count),
            ("project", "track_count", track_count),
            ("project", "media_count", media_count),
            ("project", "authoring_tool", authoring.get("name")),
            ("project", "authoring_version", authoring.get("version")),
        ]
        secs = [s for s in (src_sec, tracks_sec) if s["records"]]
        return _profile(self.KIND, fam, label, "camtasia", sections=secs,
                        detected_via="content", byte_size=byte_size,
                        line_count=lc, properties=props,
                        status="ok" if secs else "partial")


def _basename(reader: Any) -> Optional[str]:
    if isinstance(reader, dict):
        p = reader.get("path")
        if isinstance(p, str):
            return Path(p).name
    return None


# ===========================================================================
# 3. PostgreSQL pg_dump scripts (.pgdump)
# ===========================================================================
class SqlDumpParser(MiscTypeParser):
    """PostgreSQL ``pg_dump`` plain-text SQL script.

    A real line/statement census that understands pg_dump's grammar: dollar-quoted
    function bodies (``$$ ... $$`` / ``$tag$ ... $tag$``) are not split mid-body,
    and ``COPY table (cols) FROM stdin;`` data blocks are consumed to their ``\\.``
    terminator with their data rows counted (never stored). ``CREATE TABLE``
    statements are decomposed into their columns (constraint clauses excluded);
    every other statement is classified by its leading verb + object. Statement
    verb / object histograms and per-kind counts are recorded as properties.
    """

    KIND = "database_dump"
    EXTENSIONS = (".pgdump",)
    LABELS = {".pgdump": ("postgresql", "PostgreSQL pg_dump script")}

    _CREATE_TABLE = re.compile(
        r"^\s*CREATE\s+(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE\s+"
        r"(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)", re.IGNORECASE)
    _COPY = re.compile(
        r"^\s*COPY\s+([^\s(]+)\s*(?:\(([^)]*)\))?.*\bFROM\s+stdin;\s*$",
        re.IGNORECASE)
    _CONSTRAINT_KW = {"CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK",
                      "EXCLUDE", "LIKE"}
    _DOLLAR = re.compile(r"\$[A-Za-z_]*\$")

    def parse(self, path, data, text, ext, encoding, line_count):
        if tf._looks_binary(data):
            return self._forensic(ext, data, "binary payload under a .pgdump extension "
                                              "(pg_dump custom/tar format is not plain SQL)")
        fam, label = self.meta(ext)
        lines = _lines(text)
        n = len(lines)

        tables_sec = _section("tables", "table-definition", 1)
        copy_sec = _section("copy_data", "copy-block", 2)
        stmt_sec = _section("statements", "sql-statement", 3)

        verbs: Dict[str, int] = {}
        counts = {"create_table": 0, "copy": 0, "copy_rows_total": 0,
                  "alter": 0, "insert": 0, "create_index": 0,
                  "create_sequence": 0, "create_function": 0,
                  "create_view": 0, "total_statements": 0}

        i = 0
        buf: List[str] = []
        dollar_open: Optional[str] = None
        while i < n:
            line = lines[i]
            i += 1
            # COPY ... FROM stdin; data block (only when not mid-statement)
            if not buf and dollar_open is None:
                cm = self._COPY.match(line)
                if cm:
                    table = cm.group(1)
                    cols = [c.strip().strip('"') for c in (cm.group(2) or "").split(",")
                            if c.strip()]
                    rows = 0
                    while i < n and lines[i].rstrip() != r"\.":
                        rows += 1
                        i += 1
                    if i < n:  # skip the terminating \.
                        i += 1
                    counts["copy"] += 1
                    counts["copy_rows_total"] += rows
                    counts["total_statements"] += 1
                    verbs["COPY"] = verbs.get("COPY", 0) + 1
                    fields = [_field("table", table, 0),
                              _field("column_count", len(cols), 1, ftype="INT"),
                              _field("row_count", rows, 2, ftype="INT")]
                    for j, c in enumerate(cols[:64]):
                        fields.append(_field("column", c, j + 3))
                    copy_sec["records"].append(_record("copy", table, fields))
                    continue
                # between statements: drop blank lines and standalone SQL
                # comments so they never pollute the next statement's leading verb
                st = line.strip()
                if not st or st.startswith("--"):
                    continue

            buf.append(line)
            # track dollar-quoting so we never split a function body on a ';'
            for tok in self._DOLLAR.findall(line):
                if dollar_open is None:
                    dollar_open = tok
                elif tok == dollar_open:
                    dollar_open = None
            if dollar_open is None and line.rstrip().endswith(";"):
                stmt = "\n".join(buf).strip()
                buf = []
                if stmt:
                    self._classify(stmt, tables_sec, stmt_sec, verbs, counts)

        if buf:  # trailing statement without a final ';'
            stmt = "\n".join(buf).strip()
            if stmt:
                self._classify(stmt, tables_sec, stmt_sec, verbs, counts)

        props: List[Tuple] = [("dump", k, v) for k, v in counts.items()]
        for verb, c in sorted(verbs.items()):
            props.append(("statement_verbs", verb, c))
        secs = [s for s in (tables_sec, copy_sec, stmt_sec) if s["records"]]
        status = "ok" if secs else "partial"
        return _profile(self.KIND, fam, label, "pgdump", sections=secs,
                        byte_size=len(data), line_count=line_count,
                        properties=props, status=status)

    def _classify(self, stmt, tables_sec, stmt_sec, verbs, counts):
        counts["total_statements"] += 1
        head = stmt.lstrip()
        words = head.split(None, 2)
        verb = words[0].upper() if words else "STATEMENT"
        obj = words[1].upper() if len(words) > 1 else ""
        verbs[verb] = verbs.get(verb, 0) + 1

        ctm = self._CREATE_TABLE.match(stmt)
        if ctm:
            counts["create_table"] += 1
            self._emit_table(ctm.group(1), stmt, tables_sec)
            return
        if verb == "CREATE":
            if obj == "INDEX" or (obj == "UNIQUE"):
                counts["create_index"] += 1
            elif obj == "SEQUENCE":
                counts["create_sequence"] += 1
            elif obj == "FUNCTION" or obj == "PROCEDURE":
                counts["create_function"] += 1
            elif obj in ("VIEW", "MATERIALIZED"):
                counts["create_view"] += 1
        elif verb == "ALTER":
            counts["alter"] += 1
        elif verb == "INSERT":
            counts["insert"] += 1

        target = self._target(stmt, verb, obj)
        stmt_sec["records"].append(_record(
            verb.lower(), (f"{verb} {obj}".strip() or verb),
            [_field("statement_type", verb, 0),
             _field("object", obj, 1),
             _field("target", target, 2)],
            text=re.sub(r"\s+", " ", stmt)[:_PREVIEW]))

    def _emit_table(self, name, stmt, tables_sec):
        name = name.strip().strip('"')
        cols: List[str] = []
        start = stmt.find("(")
        if start != -1:
            depth = 0
            end = start
            for k in range(start, len(stmt)):
                if stmt[k] == "(":
                    depth += 1
                elif stmt[k] == ")":
                    depth -= 1
                    if depth == 0:
                        end = k
                        break
            body = stmt[start + 1:end]
            for part in _split_top_commas(body):
                part = part.strip()
                if not part:
                    continue
                first = part.split(None, 1)[0]
                if first.upper() in self._CONSTRAINT_KW:
                    continue
                cols.append(first.strip('"'))
        fields = [_field("table_name", name, 0),
                  _field("column_count", len(cols), 1, ftype="INT")]
        for j, c in enumerate(cols[:256]):
            fields.append(_field("column", c, j + 2))
        tables_sec["records"].append(_record(
            "table", name, fields, text=re.sub(r"\s+", " ", stmt)[:_PREVIEW]))

    @staticmethod
    def _target(stmt: str, verb: str, obj: str) -> Optional[str]:
        m = re.search(
            r"(?is)\b(?:TABLE|INDEX|SEQUENCE|VIEW|FUNCTION|PROCEDURE|INTO|ON|SCHEMA|"
            r"EXTENSION|TYPE|TRIGGER)\s+(?:IF\s+NOT\s+EXISTS\s+)?"
            r"([\"\w.]+)", stmt)
        return m.group(1).strip('"') if m else None


# ===========================================================================
# registry
# ===========================================================================
_PARSER_CLASSES = (StylesheetParser, VideoProjectParser, SqlDumpParser)


def build_registry() -> Dict[str, MiscTypeParser]:
    """ext -> shared parser instance, with a hard collision guard."""
    reg: Dict[str, MiscTypeParser] = {}
    for cls in _PARSER_CLASSES:
        inst = cls()
        for ext in cls.EXTENSIONS:
            e = ext.lower()
            if e in reg:
                raise RuntimeError(
                    f"misc extension {e} claimed by both "
                    f"{reg[e].__class__.__name__} and {cls.__name__}")
            reg[e] = inst
    return reg
