"""
MCP-backed enrichment layer -- content-type-aware "more information" tables for
every file the analyzers censused, plus its own SQLite database.

This layer sits *beside* the analyzer classes (it never edits their fixed
schemas): after the router planes have run, :class:`AnalysisEngine` hands the
file->analyzer mapping, the repository file census and the merged code-analyzer
tables to :class:`McpEnrichmentEngine`, which produces additional per-file
intelligence and emits it as its own ``mcp_enrichment.db`` (+ ``.sql`` dump)
that also folds into the unified database.

Two tiers of information, and the whole layer is **soft**: it always produces
real deterministic rows, and it *adds* agent-derived rows only when a provider
is actually reachable -- if no agent/MCP backend is detected it silently skips
the agent tier and never raises.

* **Deterministic (always run, no agent needed).** For every file we classify a
  *content family* (code / markup / data / config / document / text / schema /
  database / binary / media / archive / misc) from its analyzer class and
  extension, then compute genuinely useful metrics:

  - generic text metrics (line/char counts, blank-line ratio, max/avg line
    length, long-line count, trailing-whitespace lines, tab-vs-space
    indentation, TODO/FIXME markers, BOM, trailing newline, non-ASCII ratio);
  - family-specific metrics -- JSON depth/keys, CSV rows/cols/delimiter, XML tag
    count/depth, Markdown headings/links/fences/tables, HTML tags/scripts,
    config keys/sections, and for binary/media the byte size, Shannon entropy,
    printable ratio, magic-signature format detection and a header hex dump;
  - quality & smells findings (long lines, trailing whitespace, mixed
    indentation, oversized file, missing trailing newline, TODO markers,
    undocumented public symbols);
  - security & risk flags via a redacting regex set (private-key headers, cloud
    keys, generic secret/token/password assignments, JWTs, PII, URLs with
    embedded credentials, executable binary signatures) -- evidence is always
    truncated/masked, full secrets are never stored;
  - symbol-level docs joined out of the code-analyzer tables (per function /
    class: has a docstring? one-line summary?), and an extractive summary +
    purpose + tags per readable file.

* **Soft agent enrichment (added only when reachable).** Using the same
  :mod:`file_analyzer.document.agent_mcp` transport the dynamic layer uses (with
  ``discover=True`` so desktop/CLI-configured MCP servers count), we probe for a
  reachable provider. When one exists, each readable, size-capped file gets a
  content-type-aware prompt (summary / purpose / tags / quality / risk /
  symbol descriptions); the reply is parsed as JSON and folded into the same
  tables with an honest ``agent:<name>`` method label. Any failure on any file
  is swallowed -- that file simply keeps its deterministic rows. Every call is
  recorded in an audit table and every configured provider is snapshotted.

Standard-library only at import time (the CI import gate imports this module on a
bare interpreter); :mod:`file_analyzer.document.agent_mcp` is imported lazily inside the
agent tier so importing this module never pulls in the transport.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ======================================================================
# Content-family classification
# ======================================================================
#: analyzer_class -> content family (the coarse routing).
_CLASS_FAMILY = {
    "code": "code",
    "schema": "schema",
    "database": "database",
    "data": "data",
    "config": "config",
    "text": "text",
    "markup": "markup",
    "document": "document",
    "document_parser": "document",
    "archive": "archive",
    "binary": "binary",
    "misc": "misc",
}

_MEDIA_EXTS = {
    # images
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "tiff",
    "tif",
    "webp",
    "ico",
    "svg",
    "heic",
    "heif",
    "psd",
    "raw",
    "cr2",
    "nef",
    # audio
    "mp3",
    "wav",
    "flac",
    "aac",
    "ogg",
    "oga",
    "m4a",
    "wma",
    "aiff",
    "opus",
    # video
    "mp4",
    "m4v",
    "mkv",
    "mov",
    "avi",
    "wmv",
    "flv",
    "webm",
    "mpg",
    "mpeg",
}
_ARCHIVE_EXTS = {
    "zip",
    "tar",
    "gz",
    "tgz",
    "bz2",
    "xz",
    "7z",
    "rar",
    "jar",
    "war",
    "ear",
    "whl",
    "egg",
    "zst",
    "lz",
    "lzma",
    "cab",
    "iso",
    "dmg",
}
_DATABASE_EXTS = {"db", "sqlite", "sqlite3", "mdb", "accdb", "dbf", "frm", "myd"}
_BINARY_EXTS = {
    "exe",
    "dll",
    "so",
    "dylib",
    "o",
    "obj",
    "a",
    "lib",
    "class",
    "pyc",
    "pyo",
    "wasm",
    "bin",
    "dat",
    "elf",
    "ko",
    "pdb",
    "dex",
    "node",
}
_DATA_EXTS = {"json", "jsonl", "csv", "tsv", "ndjson", "parquet", "avro", "arrow"}
_CONFIG_EXTS = {
    "ini",
    "cfg",
    "conf",
    "toml",
    "yaml",
    "yml",
    "env",
    "properties",
    "editorconfig",
}
_MARKUP_EXTS = {
    "md",
    "markdown",
    "rst",
    "html",
    "htm",
    "xml",
    "xhtml",
    "tex",
    "adoc",
    "textile",
}
_DOC_EXTS = {"pdf", "docx", "doc", "pptx", "ppt", "xlsx", "xls", "odt", "rtf", "epub"}
_TEXT_EXTS = {"txt", "log", "text", "me", "nfo"}

#: Text families we can read and run the generic text metrics over.
_TEXT_FAMILIES = {"code", "markup", "data", "config", "document", "text", "schema"}

_LONG_LINE = 120
_HUGE_TEXT_BYTES = 1_000_000


def classify_family(analyzer_class: Optional[str], extension: str) -> str:
    """Map (analyzer_class, extension) to a fine-grained content family.

    The router's ``analyzer_class`` is coarse (it lumps every non-code text file
    into ``data``), so for content-type awareness the *extension* is the primary
    signal and the analyzer class is only the fallback:

    * a recognized non-code extension always wins (an ``.md`` routed as ``data``
      is still ``markup``, a ``.png`` routed as ``binary`` is still ``media``);
    * ``analyzer_class == "code"`` is authoritative for source code (its hundreds
      of extensions are not enumerated here);
    * otherwise fall back to the analyzer class, then ``misc``.
    """
    ext = (extension or "").lower().lstrip(".")
    # Extension-driven families that are unambiguous regardless of routing.
    if ext in _MEDIA_EXTS:
        return "media"
    if ext in _ARCHIVE_EXTS:
        return "archive"
    if ext in _DATABASE_EXTS:
        return "database"
    if ext in _BINARY_EXTS:
        return "binary"
    cls = (analyzer_class or "").lower()
    # Source code: trust the router (extension set is open-ended).
    if cls == "code":
        return "code"
    # Refine the remaining text extensions the router folded together.
    if ext in _DATA_EXTS:
        return "data"
    if ext in _CONFIG_EXTS:
        return "config"
    if ext in _MARKUP_EXTS:
        return "markup"
    if ext in _DOC_EXTS:
        return "document"
    if ext in _TEXT_EXTS:
        return "text"
    fam = _CLASS_FAMILY.get(cls)
    return fam or "misc"


# ======================================================================
# Magic-signature detection (byte prefixes)
# ======================================================================
#: (offset, signature-bytes, format-label, is_executable)
_MAGIC = [
    (0, b"\x89PNG\r\n\x1a\n", "png", False),
    (0, b"\xff\xd8\xff", "jpeg", False),
    (0, b"GIF87a", "gif", False),
    (0, b"GIF89a", "gif", False),
    (0, b"BM", "bmp", False),
    (0, b"II*\x00", "tiff", False),
    (0, b"MM\x00*", "tiff", False),
    (0, b"RIFF", "riff", False),
    (0, b"OggS", "ogg", False),
    (0, b"fLaC", "flac", False),
    (0, b"ID3", "mp3", False),
    (0, b"%PDF", "pdf", False),
    (0, b"%!PS", "postscript", False),
    (0, b"PK\x03\x04", "zip", False),
    (0, b"PK\x05\x06", "zip", False),
    (0, b"\x1f\x8b", "gzip", False),
    (0, b"BZh", "bzip2", False),
    (0, b"\xfd7zXZ\x00", "xz", False),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", False),
    (0, b"Rar!\x1a\x07", "rar", False),
    (0, b"SQLite format 3\x00", "sqlite", False),
    (0, b"\x7fELF", "elf", True),
    (0, b"MZ", "pe", True),
    (0, b"\xca\xfe\xba\xbe", "java_class_or_macho_fat", True),
    (0, b"\xfe\xed\xfa\xce", "mach_o", True),
    (0, b"\xfe\xed\xfa\xcf", "mach_o", True),
    (0, b"\xcf\xfa\xed\xfe", "mach_o", True),
    (4, b"ftyp", "mp4_family", False),
]


def detect_magic(head: bytes) -> Tuple[str, bool]:
    """Return (format-label, is_executable) from a file's leading bytes."""
    for offset, sig, label, is_exe in _MAGIC:
        if head[offset : offset + len(sig)] == sig:
            return label, is_exe
    return "", False


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy (bits/byte) of a byte string, in [0, 8]."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(
        -sum((c / n) * math.log2(c / n) for c in counts.values()),
        4,
    )


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable text (incl. tab/newline/cr)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b < 127)
    return round(printable / len(data), 4)


# ======================================================================
# Security & risk patterns (redacting)
# ======================================================================
#: (pattern_name, category, severity, compiled-regex). Each match's evidence is
#: masked before storage -- full secret values are never persisted.
_SECURITY_PATTERNS: List[Tuple[str, str, str, "re.Pattern[str]"]] = [
    (
        "private_key_header",
        "secret",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    ("aws_access_key_id", "secret", "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "google_api_key",
        "secret",
        "high",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    (
        "slack_token",
        "secret",
        "high",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ),
    (
        "jwt",
        "secret",
        "medium",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ),
    (
        "generic_secret_assignment",
        "secret",
        "high",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|pwd|access[_-]?key|"
            r"client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*"
            r"['\"]?[A-Za-z0-9_\-/+=.]{8,}['\"]?"
        ),
    ),
    (
        "url_with_credentials",
        "secret",
        "high",
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@[^\s/]+"),
    ),
    (
        "email",
        "pii",
        "low",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "phone",
        "pii",
        "low",
        re.compile(r"(?<!\d)\+?\d[\d\s().\-]{9,}\d(?!\d)"),
    ),
    (
        "credit_card",
        "pii",
        "high",
        re.compile(r"\b(?:\d[ \-]?){13,16}\b"),
    ),
    (
        "ssn",
        "pii",
        "high",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
]

#: Families where a security scan of the (readable) text makes sense.
_SCAN_FAMILIES = {"code", "markup", "data", "config", "text", "document", "schema"}


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum -- keeps the credit-card matcher from firing on any digits."""
    nums = [int(c) for c in digits if c.isdigit()]
    if not (13 <= len(nums) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(nums)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact(text: str, keep: int = 4) -> str:
    """Mask a matched secret/PII value, keeping only a short prefix."""
    text = text.strip()
    if len(text) <= keep:
        return "*" * len(text)
    head = text[:keep]
    return f"{head}{'*' * min(len(text) - keep, 12)}"


def scan_security(text: str) -> List[Dict[str, Any]]:
    """Return redacted security/PII findings from a text body."""
    out: List[Dict[str, Any]] = []
    line_starts: Optional[List[int]] = None
    for name, category, severity, rx in _SECURITY_PATTERNS:
        for m in rx.finditer(text):
            value = m.group(0)
            if name == "credit_card" and not _luhn_ok(value):
                continue
            if line_starts is None:
                line_starts = _line_starts(text)
            line = _line_of(line_starts, m.start())
            out.append(
                {
                    "category": category,
                    "pattern_name": name,
                    "severity": severity,
                    "line": line,
                    "evidence": _redact(value),
                }
            )
            if len(out) >= 500:  # bound the per-file evidence explosion
                return out
    return out


def _line_starts(text: str) -> List[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _line_of(starts: List[int], pos: int) -> int:
    # binary search for the greatest start <= pos
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


# ======================================================================
# The enrichment engine
# ======================================================================
class McpEnrichmentEngine:
    """Build content-type-aware enrichment tables (deterministic + soft agent)."""

    def __init__(
        self,
        mapping_rows: Iterable[Dict[str, Any]],
        repository_files: Optional[List[Dict[str, Any]]] = None,
        code_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        *,
        registry: Optional[Any] = None,
        roster: Optional[str] = None,
        agents_include: Optional[Iterable[str]] = None,
        agents_exclude: Optional[Iterable[str]] = None,
        enable_agent: bool = True,
        project_dir: Optional[str] = None,
        max_file_bytes: int = 2_000_000,
        max_agent_files: int = 40,
        agent_max_tokens: int = 1024,
        agent_content_chars: int = 6000,
    ):
        self.mapping_rows = [r for r in mapping_rows if r.get("file_location")]
        self.code_tables = code_tables or {}
        self.enable_agent = enable_agent
        self.registry = registry
        self.roster = roster
        self.agents_include = list(agents_include) if agents_include else None
        self.agents_exclude = list(agents_exclude) if agents_exclude else None
        self.project_dir = project_dir
        self.max_file_bytes = max_file_bytes
        self.max_agent_files = max_agent_files
        self.agent_max_tokens = agent_max_tokens
        self.agent_content_chars = agent_content_chars

        # file_id -> census record (name/size), when supplied.
        self._file_meta: Dict[int, Dict[str, Any]] = {}
        for rec in repository_files or []:
            fid = rec.get("file_id")
            if fid is not None:
                self._file_meta[fid] = rec

        # output tables
        self.files: List[Dict[str, Any]] = []
        self.summaries: List[Dict[str, Any]] = []
        self.quality_findings: List[Dict[str, Any]] = []
        self.security_flags: List[Dict[str, Any]] = []
        self.symbol_docs: List[Dict[str, Any]] = []
        self.content_metrics: List[Dict[str, Any]] = []
        self.agent_calls: List[Dict[str, Any]] = []
        self.providers: List[Dict[str, Any]] = []

        # counters
        self._summary_id = 0
        self._finding_id = 0
        self._flag_id = 0
        self._symbol_doc_id = 0
        self._metric_row_id = 0
        self._call_id = 0
        self._provider_id = 0

        # per-file scratch consumed by the agent tier
        # file_id -> {"path", "family", "text", "name", "undocumented": [names]}
        self._readable: Dict[int, Dict[str, Any]] = {}
        # (file_id) -> summary row, so the agent can upgrade it in place
        self._summary_by_file: Dict[int, Dict[str, Any]] = {}
        # file_id -> undocumented symbol names (surfaced to the agent tier)
        self._undocumented_by_file: Dict[int, List[str]] = {}

    # ------------------------------------------------------------------
    def analyze(self) -> "McpEnrichmentEngine":
        """Run the deterministic tier over every file, then the soft agent tier."""
        # Symbol docs + undocumented-symbol findings come from the code tables
        # and are emitted *before* the per-file loop so each file's rollup counts
        # pick them up. Track undocumented names per file for the agent tier.
        symbol_docs_by_file = self._build_symbol_docs()
        for file_id, rows in symbol_docs_by_file.items():
            for r in rows:
                self._emit_symbol_doc(r)
            undocumented = [
                r["symbol_name"] for r in rows if not r["has_doc"] and r["symbol_name"]
            ]
            if undocumented:
                shown = ", ".join(str(n) for n in undocumented[:10])
                self._emit_finding(
                    file_id,
                    "code",
                    "info",
                    "undocumented_symbols",
                    f"{len(undocumented)} of {len(rows)} symbol(s) lack a docstring: "
                    f"{shown}{' ...' if len(undocumented) > 10 else ''}.",
                )
                self._undocumented_by_file[file_id] = undocumented

        for row in self.mapping_rows:
            try:
                self._analyze_file(row)
            except Exception:
                # One unreadable/odd file never aborts the enrichment layer.
                continue
        if self.enable_agent:
            try:
                self._run_agent_tier()
            except Exception:
                # The agent tier is strictly additive; never let it break the run.
                pass
        return self

    # -- deterministic tier -------------------------------------------
    def _analyze_file(self, row: Dict[str, Any]) -> None:
        file_id = row.get("file_id")
        path = Path(row["file_location"])
        analyzer_class = row.get("analyzer_class")
        ext = path.suffix.lower().lstrip(".")
        family = classify_family(analyzer_class, ext)

        meta = self._file_meta.get(file_id, {})
        byte_size = meta.get("size")
        try:
            if byte_size is None:
                byte_size = path.stat().st_size
        except OSError:
            byte_size = None

        rec: Dict[str, Any] = {
            "file_id": file_id,
            "file_name": path.name,
            "extension": ext,
            "analyzer_class": analyzer_class,
            "content_family": family,
            "byte_size": byte_size,
            "is_text": 0,
            "read_status": "skipped",
            "magic_format": "",
            "magic_hex": "",
            "quality_findings": 0,
            "security_flags": 0,
        }

        is_text_family = family in _TEXT_FAMILIES
        if is_text_family:
            self._enrich_text_file(rec, path, family, file_id)
        else:
            self._enrich_binary_file(rec, path, family, file_id)

        # roll up the finding/flag counts for this file
        rec["quality_findings"] = sum(
            1 for f in self.quality_findings if f["file_id"] == file_id
        )
        rec["security_flags"] = sum(
            1 for f in self.security_flags if f["file_id"] == file_id
        )
        self.files.append(rec)

    def _enrich_text_file(
        self, rec: Dict[str, Any], path: Path, family: str, file_id: Any
    ) -> None:
        text, status, has_bom = self._read_text(path)
        rec["read_status"] = status
        rec["is_text"] = 1 if status in ("ok", "truncated") else 0
        rec["has_bom"] = 1 if has_bom else 0
        if text is None:
            return

        # ----- generic text metrics -----
        lines = text.splitlines()
        line_count = len(lines)
        char_count = len(text)
        blank = sum(1 for ln in lines if not ln.strip())
        lengths = [len(ln) for ln in lines] or [0]
        long_lines = sum(1 for n in lengths if n > _LONG_LINE)
        trailing_ws = sum(1 for ln in lines if ln != ln.rstrip())
        tab_indent = sum(1 for ln in lines if ln[:1] == "\t")
        space_indent = sum(1 for ln in lines if ln[:1] == " ")
        todo = len(re.findall(r"\b(?:TODO|FIXME|XXX|HACK)\b", text))
        non_ascii = sum(1 for ch in text if ord(ch) > 127)
        ends_nl = 1 if text.endswith(("\n", "\r")) else 0

        rec.update(
            {
                "line_count": line_count,
                "char_count": char_count,
                "blank_line_ratio": round(blank / line_count, 4) if line_count else 0.0,
                "max_line_len": max(lengths),
                "avg_line_len": round(sum(lengths) / len(lengths), 2),
                "long_line_count": long_lines,
                "trailing_ws_lines": trailing_ws,
                "tab_indent_lines": tab_indent,
                "space_indent_lines": space_indent,
                "todo_count": todo,
                "non_ascii_ratio": (
                    round(non_ascii / char_count, 4) if char_count else 0.0
                ),
                "ends_with_newline": ends_nl,
            }
        )

        # ----- family-specific metrics -----
        self._family_metrics(file_id, family, rec, text)

        # ----- quality & smells -----
        self._quality_findings(file_id, family, rec)

        # ----- security & risk -----
        if family in _SCAN_FAMILIES and status in ("ok", "truncated"):
            flags = scan_security(text)
            for fl in flags:
                self._emit_flag(file_id, family, fl)

        # ----- deterministic summary + tags -----
        self._deterministic_summary(file_id, family, rec, text)

        # stash for the agent tier
        self._readable[file_id] = {
            "path": str(path),
            "family": family,
            "name": rec["file_name"],
            "text": text,
        }

    def _enrich_binary_file(
        self, rec: Dict[str, Any], path: Path, family: str, file_id: Any
    ) -> None:
        head = b""
        data = b""
        try:
            with open(path, "rb") as fh:
                data = fh.read(self.max_file_bytes)
            head = data[:64]
            rec["read_status"] = (
                "truncated"
                if rec["byte_size"] and rec["byte_size"] > self.max_file_bytes
                else "ok"
            )
        except OSError:
            rec["read_status"] = "unreadable"
            return

        fmt, is_exe = detect_magic(head)
        rec["magic_format"] = fmt
        rec["magic_hex"] = head[:16].hex()
        entropy = shannon_entropy(data)
        pr = printable_ratio(data)

        self._add_metric(file_id, family, "byte_size", num=rec["byte_size"])
        self._add_metric(file_id, family, "entropy", num=entropy)
        self._add_metric(file_id, family, "printable_ratio", num=pr)
        if fmt:
            self._add_metric(file_id, family, "magic_format", text=fmt)
        self._add_metric(file_id, family, "header_hex", text=rec["magic_hex"])

        # A detected executable payload is a genuine risk flag.
        if is_exe:
            self._emit_flag(
                file_id,
                family,
                {
                    "category": "executable",
                    "pattern_name": f"binary_signature_{fmt}",
                    "severity": "medium",
                    "line": 0,
                    "evidence": rec["magic_hex"],
                },
            )
        # Very high entropy on a large blob often means encryption/packing.
        if entropy >= 7.5 and (rec["byte_size"] or 0) > 4096:
            self._emit_flag(
                file_id,
                family,
                {
                    "category": "entropy",
                    "pattern_name": "high_entropy_payload",
                    "severity": "low",
                    "line": 0,
                    "evidence": f"entropy={entropy}",
                },
            )

        # a bare-bones summary row so every file has one
        purpose = {
            "media": "binary media asset",
            "archive": "compressed archive container",
            "database": "embedded database file",
            "binary": "compiled/opaque binary payload",
        }.get(family, "binary file")
        tags = [family]
        if fmt:
            tags.append(fmt)
        self._emit_summary(
            file_id,
            family,
            method="local",
            summary=f"{family} file ({fmt or 'unknown format'}), "
            f"{rec['byte_size']} bytes, entropy {entropy}.",
            purpose=purpose,
            tags=tags,
        )

    # -- family-specific metric extractors ----------------------------
    def _family_metrics(
        self, file_id: Any, family: str, rec: Dict[str, Any], text: str
    ) -> None:
        ext = rec["extension"]
        if ext in ("json", "jsonl", "ndjson"):
            self._json_metrics(file_id, family, ext, text)
        elif ext in ("csv", "tsv"):
            self._csv_metrics(file_id, family, ext, text)
        elif ext in ("xml", "html", "htm", "xhtml", "svg"):
            self._xml_html_metrics(file_id, family, ext, text)
        elif ext in ("md", "markdown", "rst"):
            self._markdown_metrics(file_id, family, text)
        elif family == "config":
            self._config_metrics(file_id, family, ext, text)

    def _json_metrics(self, file_id: Any, family: str, ext: str, text: str) -> None:
        if ext in ("jsonl", "ndjson"):
            records, bad = 0, 0
            for ln in text.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                records += 1
                try:
                    json.loads(ln)
                except ValueError:
                    bad += 1
            self._add_metric(file_id, family, "jsonl_records", num=records)
            self._add_metric(file_id, family, "jsonl_invalid_records", num=bad)
            return
        try:
            obj = json.loads(text)
            valid = True
        except ValueError:
            obj = None
            valid = False
        self._add_metric(file_id, family, "json_is_valid", num=1 if valid else 0)
        if valid:
            depth, keys, arrays = self._json_shape(obj)
            self._add_metric(file_id, family, "json_max_depth", num=depth)
            self._add_metric(file_id, family, "json_key_count", num=keys)
            self._add_metric(file_id, family, "json_array_count", num=arrays)

    @staticmethod
    def _json_shape(obj: Any) -> Tuple[int, int, int]:
        max_depth = 0
        keys = 0
        arrays = 0
        stack: List[Tuple[Any, int]] = [(obj, 1)]
        while stack:
            cur, depth = stack.pop()
            max_depth = max(max_depth, depth)
            if isinstance(cur, dict):
                keys += len(cur)
                for v in cur.values():
                    stack.append((v, depth + 1))
            elif isinstance(cur, list):
                arrays += 1
                for v in cur:
                    stack.append((v, depth + 1))
        return max_depth, keys, arrays

    def _csv_metrics(self, file_id: Any, family: str, ext: str, text: str) -> None:
        import csv as _csv

        sample = text[:8192]
        delimiter = "\t" if ext == "tsv" else ","
        try:
            dialect = _csv.Sniffer().sniff(sample, delimiters=",\t;|")
            delimiter = dialect.delimiter
        except Exception:
            pass
        rows = 0
        cols = 0
        try:
            reader = _csv.reader(text.splitlines(), delimiter=delimiter)
            for i, r in enumerate(reader):
                rows += 1
                if i == 0:
                    cols = len(r)
        except Exception:
            rows = len(text.splitlines())
        self._add_metric(file_id, family, "csv_rows", num=rows)
        self._add_metric(file_id, family, "csv_columns", num=cols)
        self._add_metric(
            file_id,
            family,
            "csv_delimiter",
            text=("\\t" if delimiter == "\t" else delimiter),
        )

    def _xml_html_metrics(self, file_id: Any, family: str, ext: str, text: str) -> None:
        tags = re.findall(r"<\s*([A-Za-z][\w:-]*)", text)
        self._add_metric(file_id, family, "tag_count", num=len(tags))
        self._add_metric(
            file_id, family, "distinct_tags", num=len(set(t.lower() for t in tags))
        )
        if ext in ("html", "htm", "xhtml"):
            self._add_metric(
                file_id,
                family,
                "script_tags",
                num=len(re.findall(r"(?i)<\s*script\b", text)),
            )
            self._add_metric(
                file_id,
                family,
                "link_tags",
                num=len(re.findall(r"(?i)<\s*a\b", text)),
            )
            self._add_metric(
                file_id,
                family,
                "form_tags",
                num=len(re.findall(r"(?i)<\s*form\b", text)),
            )
        else:  # xml / svg: approximate nesting depth
            self._add_metric(
                file_id, family, "xml_max_depth", num=self._xml_depth(text)
            )

    @staticmethod
    def _xml_depth(text: str) -> int:
        depth = 0
        max_depth = 0
        for m in re.finditer(r"<(/?)([A-Za-z][\w:-]*)([^>]*?)(/?)>", text):
            closing, _name, _attrs, self_close = m.groups()
            if closing:
                depth = max(0, depth - 1)
            elif self_close:
                max_depth = max(max_depth, depth + 1)
            else:
                depth += 1
                max_depth = max(max_depth, depth)
        return max_depth

    def _markdown_metrics(self, file_id: Any, family: str, text: str) -> None:
        headings = len(re.findall(r"(?m)^#{1,6}\s", text))
        links = len(re.findall(r"\[[^\]]+\]\([^)]+\)", text))
        images = len(re.findall(r"!\[[^\]]*\]\([^)]+\)", text))
        fences = len(re.findall(r"(?m)^```", text)) // 2
        tables = len(re.findall(r"(?m)^\s*\|.*\|\s*$", text))
        self._add_metric(file_id, family, "md_headings", num=headings)
        self._add_metric(file_id, family, "md_links", num=links)
        self._add_metric(file_id, family, "md_images", num=images)
        self._add_metric(file_id, family, "md_code_fences", num=fences)
        self._add_metric(file_id, family, "md_table_rows", num=tables)

    def _config_metrics(self, file_id: Any, family: str, ext: str, text: str) -> None:
        sections = len(re.findall(r"(?m)^\s*\[[^\]]+\]\s*$", text))
        kv = len(re.findall(r"(?m)^\s*[A-Za-z_][\w.\-]*\s*[:=]", text))
        self._add_metric(file_id, family, "config_sections", num=sections)
        self._add_metric(file_id, family, "config_keys", num=kv)

    # -- quality & smells ---------------------------------------------
    def _quality_findings(self, file_id: Any, family: str, rec: Dict[str, Any]) -> None:
        if rec.get("long_line_count"):
            self._emit_finding(
                file_id,
                family,
                "info",
                "long_lines",
                f"{rec['long_line_count']} line(s) exceed {_LONG_LINE} chars "
                f"(max {rec['max_line_len']}).",
            )
        if rec.get("trailing_ws_lines"):
            self._emit_finding(
                file_id,
                family,
                "info",
                "trailing_whitespace",
                f"{rec['trailing_ws_lines']} line(s) have trailing whitespace.",
            )
        if rec.get("tab_indent_lines") and rec.get("space_indent_lines"):
            self._emit_finding(
                file_id,
                family,
                "warning",
                "mixed_indentation",
                f"mixes tab-indented ({rec['tab_indent_lines']}) and "
                f"space-indented ({rec['space_indent_lines']}) lines.",
            )
        if (rec.get("byte_size") or 0) > _HUGE_TEXT_BYTES:
            self._emit_finding(
                file_id,
                family,
                "warning",
                "oversized_file",
                f"text file is {rec['byte_size']} bytes (> {_HUGE_TEXT_BYTES}).",
            )
        if rec.get("line_count") and not rec.get("ends_with_newline"):
            self._emit_finding(
                file_id,
                family,
                "info",
                "missing_trailing_newline",
                "file does not end with a newline.",
            )
        if rec.get("todo_count"):
            self._emit_finding(
                file_id,
                family,
                "info",
                "todo_markers",
                f"{rec['todo_count']} TODO/FIXME/XXX/HACK marker(s).",
            )

    # -- deterministic summary ----------------------------------------
    def _deterministic_summary(
        self, file_id: Any, family: str, rec: Dict[str, Any], text: str
    ) -> None:
        # extractive: first meaningful non-blank, non-noise lines
        snippet_lines: List[str] = []
        for ln in text.splitlines():
            s = ln.strip().lstrip("#/*<!-;% ").strip()
            if s and not s.startswith(("import ", "from ", "package ", "using ")):
                snippet_lines.append(s)
            if len(snippet_lines) >= 3:
                break
        summary = " ".join(snippet_lines)[:280] or f"{family} file {rec['file_name']}."
        tags = [family, rec["extension"]] if rec["extension"] else [family]
        purpose = {
            "code": "source code module",
            "markup": "markup / documentation source",
            "data": "structured data file",
            "config": "configuration file",
            "document": "document text",
            "text": "plain-text file",
            "schema": "schema / interface definition",
        }.get(family, f"{family} file")
        self._emit_summary(
            file_id, family, method="local", summary=summary, purpose=purpose, tags=tags
        )

    # -- symbol docs from the code tables -----------------------------
    def _build_symbol_docs(self) -> Dict[int, List[Dict[str, Any]]]:
        """Join symbol_index -> functions/classes to a has-doc row per symbol."""
        by_file: Dict[int, List[Dict[str, Any]]] = {}
        if not self.code_tables:
            return by_file
        kind_by_id = {
            k.get("kind_id"): k.get("kind_name")
            for k in self.code_tables.get("kind_reference", [])
        }
        funcs = {
            f.get("function_id"): f for f in self.code_tables.get("functions_table", [])
        }
        classes = {
            c.get("class_id"): c for c in self.code_tables.get("classes_table", [])
        }
        for sym in self.code_tables.get("symbol_index", []):
            kind = kind_by_id.get(sym.get("kind_id"), "")
            target = sym.get("target_entity_id")
            file_id = sym.get("file_id")
            if kind == "function":
                entity = funcs.get(target)
                if not entity:
                    continue
                name = entity.get("function_name")
                doc = entity.get("function_description")
                symbol_kind = "function"
            elif kind == "class/struct/interface":
                entity = classes.get(target)
                if not entity:
                    continue
                name = entity.get("class_name")
                doc = entity.get("class_description")
                symbol_kind = "class"
            else:
                continue
            has_doc = bool(doc and str(doc).strip())
            row = {
                "file_id": file_id,
                "symbol_kind": symbol_kind,
                "symbol_name": name,
                "has_doc": 1 if has_doc else 0,
                "doc_summary": (
                    str(doc).strip().splitlines()[0][:200] if has_doc else ""
                ),
                "doc_source": "code" if has_doc else "",
                "method": "code",
            }
            by_file.setdefault(file_id, []).append(row)
        return by_file

    # -- soft agent tier ----------------------------------------------
    def _run_agent_tier(self) -> None:
        """Add agent-derived rows when a provider is reachable; else skip."""
        registry = self.registry
        if registry is None:
            try:
                from ..document.agent_mcp import AgentRegistry

                registry = AgentRegistry(discover=True, project_dir=self.project_dir)
            except Exception:
                return  # transport unavailable -> silently skip the agent tier
        # honour the operator's include/exclude allow-list, if a registry
        # supports it (soft: an unknown/empty filter is a no-op).
        if (self.agents_include or self.agents_exclude) and hasattr(registry, "select"):
            try:
                registry = registry.select(self.agents_include, self.agents_exclude)
            except Exception:
                pass
        self._snapshot_providers(registry)

        provider_name = self._pick_provider(registry)
        if not provider_name:
            return  # nothing reachable -> deterministic tables already stand

        try:
            connector = registry.connector(provider_name)
            if not connector.reachable():
                return
        except Exception:
            return

        method = f"agent:{provider_name}"
        # deterministic order, capped
        targets = sorted(self._readable.items(), key=lambda kv: (kv[0] is None, kv[0]))
        processed = 0
        for file_id, info in targets:
            if processed >= self.max_agent_files:
                break
            processed += 1
            try:
                self._agent_enrich_file(connector, provider_name, method, file_id, info)
            except Exception:
                # any failure on one file: keep its deterministic rows, move on
                continue
        try:
            connector.close()
        except Exception:
            pass

    def _pick_provider(self, registry: Any) -> str:
        try:
            available = registry.available()
        except Exception:
            return ""
        if not available:
            return ""
        if self.roster and self.roster in available:
            return self.roster
        return available[0]

    def _agent_enrich_file(
        self,
        connector: Any,
        provider_name: str,
        method: str,
        file_id: Any,
        info: Dict[str, Any],
    ) -> None:
        from ..document.agent_mcp import AgentError, ProviderUnavailable
        from ..document.dynamic_engine import extract_json

        family = info["family"]
        content = info["text"][: self.agent_content_chars]
        undoc = self._undocumented_by_file.get(file_id) or []
        system = (
            "You are a meticulous senior software and content analyst. Analyze the "
            "given file and reply with a single minified JSON object only, no prose."
        )
        undoc_hint = (
            (
                "Prioritize describing these undocumented symbols: "
                + ", ".join(str(n) for n in undoc[:20])
                + ".\n"
            )
            if undoc
            else ""
        )
        user = (
            f"File name: {info['name']}\n"
            f"Content family: {family}\n"
            f"{undoc_hint}"
            "Return JSON with keys: "
            '"summary" (<=60 words), "purpose" (short phrase), '
            '"tags" (array of short strings), "quality" (array of short issue '
            'strings), "risks" (array of short risk strings), '
            '"symbols" (object mapping symbol name to a one-line description).\n\n'
            f"----- BEGIN CONTENT -----\n{content}\n----- END CONTENT -----"
        )
        try:
            res = connector.chat(
                [{"role": "user", "content": user}],
                system=system,
                max_tokens=self.agent_max_tokens,
                role="assistant",
            )
        except (ProviderUnavailable, AgentError) as exc:
            self._emit_call(
                provider_name,
                "",
                connector.transport,
                "enrich",
                status="error",
                error=str(exc),
            )
            return

        self._emit_call(
            provider_name,
            res.model,
            res.transport,
            "enrich",
            status=res.status,
            error=res.error,
            prompt_tokens=res.prompt_tokens,
            completion_tokens=res.completion_tokens,
            latency_ms=res.latency_ms,
        )
        if res.status != "ok":
            return
        parsed = extract_json(res.text)
        if not isinstance(parsed, dict):
            return

        # upgrade / add a summary row from the agent
        summary = str(parsed.get("summary") or "").strip()
        purpose = str(parsed.get("purpose") or "").strip()
        tags = parsed.get("tags")
        if not isinstance(tags, list):
            tags = []
        if summary or purpose or tags:
            existing = self._summary_by_file.get(file_id)
            if existing is not None:
                existing["method"] = method
                if summary:
                    existing["summary"] = summary[:280]
                if purpose:
                    existing["purpose"] = purpose[:120]
                if tags:
                    existing["tags"] = json.dumps(
                        [str(t)[:40] for t in tags[:12]], ensure_ascii=False
                    )
            else:
                self._emit_summary(
                    file_id,
                    family,
                    method=method,
                    summary=summary[:280],
                    purpose=purpose[:120],
                    tags=[str(t)[:40] for t in tags[:12]],
                )

        for q in parsed.get("quality") or []:
            if isinstance(q, str) and q.strip():
                self._emit_finding(
                    file_id,
                    family,
                    "info",
                    "agent_quality",
                    q.strip()[:280],
                    method=method,
                )
        for rsk in parsed.get("risks") or []:
            if isinstance(rsk, str) and rsk.strip():
                self._emit_flag(
                    file_id,
                    family,
                    {
                        "category": "agent_risk",
                        "pattern_name": "agent_flag",
                        "severity": "info",
                        "line": 0,
                        "evidence": rsk.strip()[:200],
                    },
                    method=method,
                )
        symbols = parsed.get("symbols")
        if isinstance(symbols, dict):
            for sym_name, desc in list(symbols.items())[:50]:
                if not isinstance(desc, str) or not desc.strip():
                    continue
                self._emit_symbol_doc(
                    {
                        "file_id": file_id,
                        "symbol_kind": "agent",
                        "symbol_name": str(sym_name)[:120],
                        "has_doc": 1,
                        "doc_summary": desc.strip()[:200],
                        "doc_source": method,
                        "method": method,
                    }
                )

    def _snapshot_providers(self, registry: Any) -> None:
        try:
            probes = registry.probe_all()
        except Exception:
            return
        for probe in probes:
            self._provider_id += 1
            self.providers.append(
                {
                    "provider_id": self._provider_id,
                    "name": probe.get("name"),
                    "kind": probe.get("kind"),
                    "transport": probe.get("transport"),
                    "reachable": 1 if probe.get("reachable") else 0,
                    "reason": probe.get("reason"),
                    "model": probe.get("model"),
                    "endpoint": probe.get("base_url") or probe.get("binary"),
                }
            )

    # -- I/O ----------------------------------------------------------
    def _read_text(self, path: Path) -> Tuple[Optional[str], str, bool]:
        """Read a file as UTF-8 text (size-capped). Returns (text, status, has_bom)."""
        try:
            with open(path, "rb") as fh:
                raw = fh.read(self.max_file_bytes + 1)
        except OSError:
            return None, "unreadable", False
        truncated = len(raw) > self.max_file_bytes
        raw = raw[: self.max_file_bytes]
        has_bom = raw[:3] == b"\xef\xbb\xbf"
        # Reject files that look binary (NUL bytes) rather than mis-decoding them.
        if b"\x00" in raw[:4096]:
            return None, "binary", has_bom
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", "replace")
        return text, ("truncated" if truncated else "ok"), has_bom

    # -- row emitters -------------------------------------------------
    def _add_metric(
        self,
        file_id: Any,
        family: str,
        metric: str,
        *,
        num: Optional[float] = None,
        text: Optional[str] = None,
    ) -> None:
        self._metric_row_id += 1
        self.content_metrics.append(
            {
                "metric_row_id": self._metric_row_id,
                "file_id": file_id,
                "content_family": family,
                "metric": metric,
                "value_num": num,
                "value_text": text,
            }
        )

    def _emit_summary(
        self,
        file_id: Any,
        family: str,
        *,
        method: str,
        summary: str,
        purpose: str,
        tags: List[str],
    ) -> None:
        self._summary_id += 1
        row = {
            "summary_id": self._summary_id,
            "file_id": file_id,
            "content_family": family,
            "method": method,
            "summary": summary,
            "purpose": purpose,
            "tags": json.dumps(tags, ensure_ascii=False),
        }
        self.summaries.append(row)
        self._summary_by_file.setdefault(file_id, row)

    def _emit_finding(
        self,
        file_id: Any,
        family: str,
        severity: str,
        rule: str,
        detail: str,
        *,
        method: str = "code",
        line: int = 0,
    ) -> None:
        self._finding_id += 1
        self.quality_findings.append(
            {
                "finding_id": self._finding_id,
                "file_id": file_id,
                "content_family": family,
                "severity": severity,
                "rule": rule,
                "detail": detail,
                "line": line,
                "method": method,
            }
        )

    def _emit_flag(
        self,
        file_id: Any,
        family: str,
        flag: Dict[str, Any],
        *,
        method: str = "code",
    ) -> None:
        self._flag_id += 1
        self.security_flags.append(
            {
                "flag_id": self._flag_id,
                "file_id": file_id,
                "content_family": family,
                "category": flag.get("category"),
                "pattern_name": flag.get("pattern_name"),
                "severity": flag.get("severity"),
                "line": flag.get("line", 0),
                "evidence": flag.get("evidence"),
                "method": method,
            }
        )

    def _emit_symbol_doc(self, row: Dict[str, Any]) -> None:
        self._symbol_doc_id += 1
        row = dict(row)
        row["symbol_doc_id"] = self._symbol_doc_id
        self.symbol_docs.append(row)

    def _emit_call(
        self,
        provider: str,
        model: str,
        transport: str,
        task: str,
        *,
        status: str = "ok",
        error: str = "",
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        latency_ms: float = 0.0,
    ) -> None:
        self._call_id += 1
        self.agent_calls.append(
            {
                "call_id": self._call_id,
                "provider": provider,
                "model": model,
                "transport": transport,
                "task": task,
                "status": status,
                "error": error,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "latency_ms": round(latency_ms, 2),
            }
        )

    # -- component catalogue (self-describing, always present) --------
    def component_catalog(self) -> List[Dict[str, Any]]:
        agent_active = any(p.get("reachable") for p in self.providers)
        rows = [
            (1, "Content classification", "content_family", "deterministic", False),
            (
                1,
                "Content classification",
                "magic_signature_detection",
                "deterministic",
                False,
            ),
            (2, "Generic text metrics", "line_char_counts", "deterministic", False),
            (
                2,
                "Generic text metrics",
                "indentation_and_whitespace",
                "deterministic",
                False,
            ),
            (2, "Generic text metrics", "non_ascii_and_bom", "deterministic", False),
            (3, "Family metrics", "json_shape", "deterministic", False),
            (3, "Family metrics", "csv_shape", "deterministic", False),
            (3, "Family metrics", "xml_html_structure", "deterministic", False),
            (3, "Family metrics", "markdown_structure", "deterministic", False),
            (3, "Family metrics", "config_keys_sections", "deterministic", False),
            (3, "Family metrics", "binary_entropy_printable", "deterministic", False),
            (4, "Quality & smells", "long_lines", "deterministic", False),
            (4, "Quality & smells", "mixed_indentation", "deterministic", False),
            (4, "Quality & smells", "oversized_file", "deterministic", False),
            (4, "Quality & smells", "todo_markers", "deterministic", False),
            (4, "Quality & smells", "undocumented_symbols", "deterministic", False),
            (5, "Security & risk", "private_keys_and_secrets", "deterministic", False),
            (5, "Security & risk", "pii_detection", "deterministic", False),
            (5, "Security & risk", "credentials_in_urls", "deterministic", False),
            (5, "Security & risk", "executable_signatures", "deterministic", False),
            (6, "Symbol docs", "docstring_presence", "deterministic", False),
            (7, "Summary & tags", "extractive_summary", "deterministic", False),
            (8, "Agent enrichment", "agent_summary_purpose_tags", "agent", True),
            (8, "Agent enrichment", "agent_quality_notes", "agent", True),
            (8, "Agent enrichment", "agent_risk_notes", "agent", True),
            (8, "Agent enrichment", "agent_symbol_descriptions", "agent", True),
        ]
        out = []
        for i, (sec, title, comp, layer, needs_agent) in enumerate(rows, start=1):
            out.append(
                {
                    "catalog_id": i,
                    "section_id": sec,
                    "section_title": title,
                    "component": comp,
                    "layer": layer,
                    "requires_agent": 1 if needs_agent else 0,
                    "computed": 1 if (not needs_agent or agent_active) else 0,
                    "notes": "",
                }
            )
        return out

    # ------------------------------------------------------------------
    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        """The enrichment tables, keyed as the database generator expects."""
        return {
            "mcp_files_table": self.files,
            "mcp_summaries_table": self.summaries,
            "mcp_quality_findings_table": self.quality_findings,
            "mcp_security_flags_table": self.security_flags,
            "mcp_symbol_docs_table": self.symbol_docs,
            "mcp_content_metrics_table": self.content_metrics,
            "mcp_agent_calls_table": self.agent_calls,
            "mcp_providers_table": self.providers,
            "mcp_component_catalog_table": self.component_catalog(),
        }


# ======================================================================
# Database generator (own .db + .sql, folds into the unified DB)
# ======================================================================
class McpEnrichmentDatabaseGenerator:
    """Materialize the MCP-enrichment database (Database 5) + its .sql dump.

    Mirrors :class:`file_analyzer.document.document_db.DocumentParserDatabaseGenerator`:
    a fresh on-disk SQLite file is created with unquoted names, filled from the
    enrichment tables (guaranteed template columns so empty tables still carry
    the columns their indexes/views reference), indexes + convenience VIEWs are
    installed, and a portable ``.sql`` dump is written via ``iterdump()``.
    """

    #: Guaranteed columns per table so indexes/views resolve even when empty.
    _TEMPLATES: Dict[str, List[str]] = {
        "mcp_files": [
            "file_id",
            "file_name",
            "extension",
            "analyzer_class",
            "content_family",
            "byte_size",
            "is_text",
            "read_status",
            "line_count",
            "char_count",
            "blank_line_ratio",
            "max_line_len",
            "avg_line_len",
            "long_line_count",
            "trailing_ws_lines",
            "tab_indent_lines",
            "space_indent_lines",
            "todo_count",
            "has_bom",
            "ends_with_newline",
            "non_ascii_ratio",
            "magic_format",
            "magic_hex",
            "quality_findings",
            "security_flags",
        ],
        "mcp_summaries": [
            "file_id",
            "content_family",
            "method",
            "summary",
            "purpose",
            "tags",
        ],
        "mcp_quality_findings": [
            "file_id",
            "content_family",
            "severity",
            "rule",
            "detail",
            "line",
            "method",
        ],
        "mcp_security_flags": [
            "file_id",
            "content_family",
            "category",
            "pattern_name",
            "severity",
            "line",
            "evidence",
            "method",
        ],
        "mcp_symbol_docs": [
            "file_id",
            "symbol_kind",
            "symbol_name",
            "has_doc",
            "doc_summary",
            "doc_source",
            "method",
        ],
        "mcp_content_metrics": [
            "file_id",
            "content_family",
            "metric",
            "value_num",
            "value_text",
        ],
        "mcp_agent_calls": [
            "provider",
            "model",
            "transport",
            "task",
            "status",
            "error",
            "prompt_tokens",
            "completion_tokens",
            "latency_ms",
        ],
        "mcp_providers": [
            "name",
            "kind",
            "transport",
            "reachable",
            "reason",
            "model",
            "endpoint",
        ],
        "mcp_component_catalog": [
            "section_id",
            "section_title",
            "component",
            "layer",
            "requires_agent",
            "computed",
            "notes",
        ],
    }

    _REAL_COLS = frozenset(
        {
            "value_num",
            "avg_line_len",
            "blank_line_ratio",
            "non_ascii_ratio",
            "entropy",
            "printable_ratio",
            "latency_ms",
        }
    )

    def __init__(
        self,
        tables: Dict[str, List[Dict[str, Any]]],
        db_path: str = "mcp_enrichment.db",
        sql_path: str = "mcp_enrichment.sql",
        schema_name: str = "mcp_enrichment",
    ):
        self.tables = tables or {}
        self.db_path = Path(db_path)
        self.sql_path = Path(sql_path)
        self.schema_name = schema_name

    # -- helpers (mirror DocumentParserDatabaseGenerator) -------------
    @staticmethod
    def _fresh_db(path: Path) -> sqlite3.Connection:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode = OFF;")
        conn.execute("PRAGMA synchronous = OFF;")
        return conn

    @staticmethod
    def _dump_sql(conn: sqlite3.Connection, sql_path: Path, banner: str) -> None:
        sql_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "-- " + "=" * 74,
            f"-- {banner}",
            "-- Generated by McpEnrichmentDatabaseGenerator (sqlite dialect).",
            "-- " + "=" * 74,
            "",
        ]
        lines.extend(conn.iterdump())
        sql_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    @classmethod
    def _affinity(cls, col: str) -> str:
        lc = col.lower()
        if lc in cls._REAL_COLS:
            return "REAL"
        if lc.endswith(
            (
                "_id",
                "_count",
                "_len",
                "_lines",
                "_bytes",
                "line",
                "size",
                "_tokens",
                "depth",
                "_records",
            )
        ) or lc in (
            "is_text",
            "has_bom",
            "ends_with_newline",
            "has_doc",
            "reachable",
            "requires_agent",
            "computed",
        ):
            return "INTEGER"
        if lc.endswith(("ratio", "entropy", "_ms")):
            return "REAL"
        return "TEXT"

    @staticmethod
    def _encode(val: Any) -> Any:
        if isinstance(val, bool):
            return 1 if val else 0
        if isinstance(val, (dict, list)):
            return json.dumps(val, ensure_ascii=False)
        return val

    @staticmethod
    def _columns_for(rows: List[Dict[str, Any]], pk: str) -> List[str]:
        cols: List[str] = [pk]
        for row in rows:
            for k in row:
                if k not in cols:
                    cols.append(k)
        return cols

    def _create_and_fill(
        self, cur: sqlite3.Cursor, table: str, pk: str, rows: List[Dict[str, Any]]
    ) -> int:
        cols = [pk]
        for c in self._TEMPLATES.get(table, []):
            if c not in cols:
                cols.append(c)
        for c in self._columns_for(rows, pk):
            if c not in cols:
                cols.append(c)
        col_defs = []
        for c in cols:
            if c == pk:
                col_defs.append(f"{c} INTEGER PRIMARY KEY")
            else:
                col_defs.append(f"{c} {self._affinity(c)}")
        cur.execute(f"CREATE TABLE {table} (\n  " + ",\n  ".join(col_defs) + "\n);")
        if not rows:
            return 0
        placeholders = ", ".join("?" for _ in cols)
        cur.executemany(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})",
            [tuple(self._encode(r.get(c)) for c in cols) for r in rows],
        )
        return len(rows)

    # ------------------------------------------------------------------
    def generate(self) -> Dict[str, Any]:
        conn = self._fresh_db(self.db_path)
        cur = conn.cursor()
        counts: Dict[str, int] = {}

        # (source table key, sqlite table name, primary key)
        spec = (
            ("mcp_files_table", "mcp_files", "file_id"),
            ("mcp_summaries_table", "mcp_summaries", "summary_id"),
            ("mcp_quality_findings_table", "mcp_quality_findings", "finding_id"),
            ("mcp_security_flags_table", "mcp_security_flags", "flag_id"),
            ("mcp_symbol_docs_table", "mcp_symbol_docs", "symbol_doc_id"),
            ("mcp_content_metrics_table", "mcp_content_metrics", "metric_row_id"),
            ("mcp_agent_calls_table", "mcp_agent_calls", "call_id"),
            ("mcp_providers_table", "mcp_providers", "provider_id"),
            ("mcp_component_catalog_table", "mcp_component_catalog", "catalog_id"),
        )
        for src_name, alias, pk in spec:
            rows = self.tables.get(src_name, [])
            counts[alias] = self._create_and_fill(cur, alias, pk, rows)

        cur.executescript("""
            CREATE INDEX ix_mcp_files_family   ON mcp_files (content_family);
            CREATE INDEX ix_mcp_metrics_file   ON mcp_content_metrics (file_id);
            CREATE INDEX ix_mcp_metrics_metric ON mcp_content_metrics (metric);
            CREATE INDEX ix_mcp_findings_file  ON mcp_quality_findings (file_id);
            CREATE INDEX ix_mcp_findings_rule  ON mcp_quality_findings (rule);
            CREATE INDEX ix_mcp_flags_file     ON mcp_security_flags (file_id);
            CREATE INDEX ix_mcp_flags_cat      ON mcp_security_flags (category);
            CREATE INDEX ix_mcp_symdocs_file   ON mcp_symbol_docs (file_id);
            CREATE INDEX ix_mcp_summaries_file ON mcp_summaries (file_id);

            -- Per-family file census with quality/risk rollups.
            CREATE VIEW v_mcp_family_summary AS
                SELECT content_family,
                       COUNT(*)                 AS files,
                       SUM(is_text)             AS text_files,
                       SUM(byte_size)           AS total_bytes,
                       SUM(quality_findings)    AS quality_findings,
                       SUM(security_flags)      AS security_flags
                FROM mcp_files
                GROUP BY content_family
                ORDER BY files DESC;

            -- Files carrying at least one security/PII flag, worst first.
            CREATE VIEW v_mcp_files_at_risk AS
                SELECT f.file_id, f.file_name, f.content_family,
                       COUNT(s.flag_id)                                   AS flags,
                       SUM(CASE WHEN s.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                       SUM(CASE WHEN s.severity = 'high' THEN 1 ELSE 0 END)     AS high
                FROM mcp_files f
                JOIN mcp_security_flags s ON s.file_id = f.file_id
                GROUP BY f.file_id, f.file_name, f.content_family
                ORDER BY critical DESC, high DESC, flags DESC;

            -- Security findings grouped by pattern (evidence stays redacted).
            CREATE VIEW v_mcp_security_by_pattern AS
                SELECT category, pattern_name, severity,
                       COUNT(*)                  AS hits,
                       COUNT(DISTINCT file_id)   AS files
                FROM mcp_security_flags
                GROUP BY category, pattern_name, severity
                ORDER BY hits DESC;

            -- Quality smells grouped by rule.
            CREATE VIEW v_mcp_quality_by_rule AS
                SELECT rule, severity,
                       COUNT(*)                  AS hits,
                       COUNT(DISTINCT file_id)   AS files
                FROM mcp_quality_findings
                GROUP BY rule, severity
                ORDER BY hits DESC;

            -- Documentation coverage per file (undocumented symbols surfaced).
            CREATE VIEW v_mcp_doc_coverage AS
                SELECT file_id,
                       COUNT(*)                          AS symbols,
                       SUM(has_doc)                      AS documented,
                       COUNT(*) - SUM(has_doc)           AS undocumented
                FROM mcp_symbol_docs
                GROUP BY file_id
                ORDER BY undocumented DESC;

            -- Which summaries came from an agent vs the deterministic tier.
            CREATE VIEW v_mcp_summary_provenance AS
                SELECT method, COUNT(*) AS summaries
                FROM mcp_summaries
                GROUP BY method
                ORDER BY summaries DESC;

            -- Provider health + how many calls each actually served.
            CREATE VIEW v_mcp_provider_usage AS
                SELECT p.name, p.kind, p.transport, p.reachable,
                       COUNT(c.call_id)                                   AS calls,
                       SUM(CASE WHEN c.status = 'ok' THEN 1 ELSE 0 END)   AS ok_calls,
                       SUM(COALESCE(c.prompt_tokens, 0))                  AS prompt_tokens,
                       SUM(COALESCE(c.completion_tokens, 0))              AS completion_tokens
                FROM mcp_providers p
                LEFT JOIN mcp_agent_calls c ON c.provider = p.name
                GROUP BY p.name, p.kind, p.transport, p.reachable;

            -- Enrichment coverage by section (deterministic vs agent).
            CREATE VIEW v_mcp_component_coverage AS
                SELECT section_id, section_title,
                       COUNT(*)              AS components,
                       SUM(requires_agent)   AS agent_backed,
                       SUM(computed)         AS computed
                FROM mcp_component_catalog
                GROUP BY section_id, section_title
                ORDER BY section_id;
            """)
        conn.commit()
        self._dump_sql(
            conn, self.sql_path, "Database 5: MCP content-aware enrichment layer"
        )
        conn.close()
        return {
            "database": str(self.db_path),
            "sql": str(self.sql_path),
            "counts": counts,
        }
