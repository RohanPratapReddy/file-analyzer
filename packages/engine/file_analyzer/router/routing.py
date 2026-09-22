"""
Extension -> analyzer routing and file-to-analyzer mapping.

This is the pure-Python core of the ``router`` package. It has NO heavy imports
at module load time (the analyzer engines are imported lazily only when the
extension sets are first needed), so it is cheap to import from
``RepositoryAnalyzer`` for the sole purpose of building the file->analyzer map.

Routing contract
----------------
Every repository file is assigned to exactly one *analyzer class* by its true
filename suffix (the last ``.`` component, matching how each engine keys its own
extension tables):

    * ``"code"``    -> PolyglotCodeAnalyzer   (source code, EXT_MAP)
    * ``"schema"``  -> SchemaAnalyzer          (SQL DDL + IDL/schema-def languages)
    * ``"archive"`` -> ArchiveAnalyzer          (zip/tar/compression containers:
                       extracted into ``temp/sandbox/`` and recursed into by a
                       nested AnalysisEngine; NOT handled by the Go plane)
    * ``"binary"``  -> MachineCodeAnalyzer      (executable / object / bytecode /
                       firmware: ELF/PE/Mach-O/.class/.pyc/WASM/DEX/ar/LLVM/UF2/OLE;
                       a dedicated post-planes stage, NOT handled by the Go plane)
    * ``"data"``    -> DataAnalyzer            (tabular / tensor / structured data)
    * ``None``      -> unrouted (no engine claims the suffix)

Priority is ``code > schema > document_parser > archive > binary > data``
(``document_parser`` is a dedicated high-priority plane for true document formats
-- ``.pdf`` / ``.doc*`` / ``.odt`` / ``.rtf`` / ``.epub`` / ... -- see
``DocumentParser``). Content-sniffed, extension-ambiguous
formats (``.json`` / ``.md``: SchemaAnalyzer only claims them when their *content*
is a Mongo/Avro/JSON-schema or a Redis-keyspace table) are deliberately routed to
DataAnalyzer, which is their overwhelmingly common case and which degrades to a
generic text/JSON profile otherwise. SchemaAnalyzer still receives every file
whose *suffix alone* unambiguously identifies a schema-definition language.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Logical analyzer-class identifiers, and the flat-facade names the per-shard
# worker imports (``from file_analyzer import <name>``).
ANALYZER_CLASSES: Dict[str, str] = {
    "code": "PolyglotCodeAnalyzer",
    "schema": "SchemaAnalyzer",
    "database": "DatabaseAnalyzer",
    "data": "DataAnalyzer",
    "archive": "ArchiveAnalyzer",
    "binary": "MachineCodeAnalyzer",
    "config": "ConfigAnalyzer",
    "text": "TextualAnalyzer",
    "markup": "MarkupAnalyzer",
    "document": "DocumentAnalyzer",
    "document_parser": "DocumentParser",
    "misc": "MiscAnalyzer",
}

# Container / archive / compression suffixes claimed by ArchiveAnalyzer. These are
# containers to be *extracted* and recursed into (a nested AnalysisEngine runs over
# the members), NOT data artifacts. Data-meaningful single-file containers that
# DataAnalyzer profiles in place (``.npz`` tensors, ``.docx``/``.xlsx`` documents,
# ``.pdf``, ``.glb``, ``.gpkg``, ``.ods``) are deliberately NOT listed here so they
# stay with DataAnalyzer. Routing is by true (last-component) suffix, so a
# ``foo.tar.gz`` / ``bar.csv.gz`` both resolve via ``.gz`` -> archive; the archive
# stage then decompresses and the *extracted* member is analyzed on its own merits.
_ARCHIVE_EXTS = frozenset(
    {
        # zip-family containers (PKZIP / OPC / ODF / spec-guaranteed-ZIP packages)
        ".zip",
        ".epub",
        ".usdz",
        ".3mf",
        ".kmz",
        ".jar",
        ".war",
        ".ear",
        ".apk",
        ".whl",
        ".xpi",
        ".vsix",
        ".nupkg",
        ".zipx",
        ".asice",
        ".bdoc",
        ".bcf",
        ".dwca",
        ".siard",
        ".wacz",
        ".xdm",
        ".pk3",
        ".pdx",
        ".ufdr",
        # tar (plain + transparently-compressed compounds resolve via last suffix)
        ".tar",
        ".tgz",
        ".tbz2",
        ".tbz",
        ".txz",
        ".tzst",
        ".webdataset",
        ".mbz",
        # single-stream compression
        ".gz",
        ".bz2",
        ".xz",
        ".lzma",
        ".zst",
        ".zstd",
        ".7z",
        ".br",
        ".lz",
        ".lz4",
        ".sz",
        ".z",
        ".tpz",
        # recognized-but-not-extractable-without-external-tools archive formats
        # (ArchiveAnalyzer catalogues them honestly and content-sniffs each one:
        # any that is actually a ZIP/tar/gzip/... underneath is still extracted).
        ".ace",
        ".arj",
        ".arc",
        ".cab",
        ".cpio",
        ".lha",
        ".lzh",
        ".zoo",
        ".hqx",
        ".sit",
        ".sitx",
        ".rar",
        ".r00",
        ".r01",
        ".000",
        ".001",
        ".002",
        ".z01",
        ".aip",
        ".dip",
        ".sip",
        ".ddoc",
        ".sce",
        ".biar",
        ".car",
        ".sapcar",
        ".sar",
        ".tpz",
        ".pds",
        ".pdse",
        ".xmit",
        ".ba2",
        ".bsa",
        ".gcf",
        ".pak",
        ".pck",
        ".vpk",
        ".rgss3a",
        ".rpa",
        ".wad",
        ".bundle",
        ".obb",
        ".odb",
        ".xcappdata",
        ".deskthemepack",
        ".themepack",
        ".warc",
        ".wpress",
        ".xry",
    }
)

# Suffixes that SchemaAnalyzer claims purely by extension (content-ambiguous
# ``.json`` / ``.md`` are intentionally excluded — see module docstring).
_SCHEMA_EXTS = frozenset(
    {
        ".sql",
        ".ddl",
        ".cql",
        ".psql",
        ".pgsql",
        ".mysql",
        ".hql",
        ".proto",
        ".thrift",
        ".graphql",
        ".gql",
        ".graphqls",
        ".avsc",
        ".avpr",
        ".avdl",
        ".fbs",
        ".capnp",
        ".xsd",
        # Residual schema-definition families (real engines in schema_defs.py).
        ".webidl",
        ".idl",
        ".smithy",
        ".cddl",
        ".dbml",
        ".yang",
        ".mib",
        ".msg",
        ".srv",
        ".shacl",
        ".ebnf",
        ".jsonschema",
        ".openapi",
        ".swagger",
        ".raml",
        ".crd",
        ".ksy",
        ".xcstrings",
    }
)

# Executable / object / bytecode / firmware suffixes claimed by MachineCodeAnalyzer.
# These are machine-code containers parsed by a dedicated post-planes stage (deep
# ELF/PE/Mach-O/.class/.pyc/WASM/DEX/ar/LLVM/UF2/OLE parsers), NOT plane shards and
# NOT semantic data artifacts. Kept disjoint from the higher-priority classes so no
# existing routing changes (see MachineCodeAnalyzer.ROUTED_EXTS for the rationale).
_BINARY_EXTS = frozenset(
    {
        ".elf",
        ".o",
        ".ko",
        ".so",
        ".prx",
        ".axf",
        ".bin",
        ".exe",
        ".dll",
        ".sys",
        ".efi",
        ".ocx",
        ".cpl",
        ".scr",
        ".drv",
        ".mui",
        ".winmd",
        ".dylib",
        ".macho",
        ".class",
        ".pyc",
        ".pyo",
        ".wasm",
        ".dex",
        ".odex",
        ".oat",
        ".vdex",
        ".art",
        ".bc",
        ".llbc",
        ".cma",
        ".cmo",
        ".cmx",
        ".cmxs",
        ".uf2",
        ".hex",
        ".srec",
        ".s19",
        ".s28",
        ".s37",
        ".msi",
        ".msm",
    }
)

# Lazily-populated caches for the code/data/database suffix universes.
_CODE_EXTS: Optional[frozenset] = None
_DATA_EXTS: Optional[frozenset] = None
_DATABASE_EXTS: Optional[frozenset] = None
_BINARY_FMT_EXTS: Optional[frozenset] = None
_CONFIG_EXTS: Optional[frozenset] = None
_TEXT_EXTS: Optional[frozenset] = None
_MARKUP_EXTS: Optional[frozenset] = None
_DOCUMENT_EXTS: Optional[frozenset] = None
_DOCUMENT_PARSER_EXTS: Optional[frozenset] = None
_MISC_EXTS: Optional[frozenset] = None


def _code_exts() -> frozenset:
    global _CODE_EXTS
    if _CODE_EXTS is None:
        from ..prog_lang.polyglot import PolyglotCodeAnalyzer

        _CODE_EXTS = frozenset(k.lower() for k in PolyglotCodeAnalyzer.EXT_MAP)
    return _CODE_EXTS


def _database_exts() -> frozenset:
    global _DATABASE_EXTS
    if _DATABASE_EXTS is None:
        from ..database.database_analyzer import DatabaseAnalyzer

        _DATABASE_EXTS = frozenset(DatabaseAnalyzer._known_exts())
    return _DATABASE_EXTS


def _data_exts() -> frozenset:
    global _DATA_EXTS
    if _DATA_EXTS is None:
        from ..data.data_analyzer import DataAnalyzer

        # _known_exts is an instance method but reads only class attributes.
        _DATA_EXTS = frozenset(DataAnalyzer.__new__(DataAnalyzer)._known_exts())
    return _DATA_EXTS


def _binary_format_exts() -> frozenset:
    """Last-component suffixes owned by BinaryFormatParser's structural universe.

    This is the non-executable binary universe (media / image / model / disk-image
    / firmware / scientific / serialization / font / ROM / capture) that
    MachineCodeAnalyzer parses through ``BinaryFormatParser`` in its
    ``_dispatch``-returns-None branch. Any suffix already claimed by a
    higher-priority plane, or by the semantic-data plane, is subtracted so this
    set can only add routes for currently-unrouted extensions -- no existing
    routing decision changes.
    """
    global _BINARY_FMT_EXTS
    if _BINARY_FMT_EXTS is None:
        from ..binary.format_parsers import BinaryFormatParser

        cand = set(BinaryFormatParser.routing_suffixes())
        owned = (
            set(_code_exts())
            | set(_SCHEMA_EXTS)
            | set(_document_parser_exts())
            | set(_database_exts())
            | set(_ARCHIVE_EXTS)
            | set(_BINARY_EXTS)
            | set(_data_exts())
        )
        # Genuinely dual-meaning last-component suffixes that are more commonly a
        # TEXT artifact than the binary format that merely shares the tail: ``.md5``
        # is a checksum manifest (the binary hit is only the ``.tar.md5`` firmware
        # tail) and ``.ora`` is an Oracle text config (vs OpenRaster ZIP). Left
        # unrouted here so the text plane keeps them; the concrete binary variants
        # are still content-sniffed if they ever reach MachineCodeAnalyzer.
        _BINARY_FMT_EXCLUDE = frozenset({".md5", ".ora"})
        _BINARY_FMT_EXTS = frozenset(cand - owned - _BINARY_FMT_EXCLUDE)
    return _BINARY_FMT_EXTS


def _document_parser_exts() -> frozenset:
    """Last-component suffixes owned by DocumentParser's document-format universe.

    The ``document`` ``extension_type`` universe from the canonical catalogue --
    word-processor documents, e-books, page-description / fixed-layout formats,
    notation and other rich documents (``.pdf`` / ``.doc`` / ``.docx`` / ``.odt``
    / ``.rtf`` / ``.epub`` / ``.mobi`` / ``.azw*`` / ``.pages`` / ``.keynote`` /
    ``.djvu`` / ...). This is a HIGH-priority plane (checked right after ``code``
    and ``schema``), so it deliberately *reclaims* these document suffixes from the
    lower-priority generic planes (data / binary-format / archive / text / the
    residual ``document`` plane) that previously absorbed them by tail. Only the
    two structured planes above it keep their suffixes: genuinely dual-use tails
    that are a *program* or a *schema* far more often than a document -- ``.gp`` /
    ``.ws`` / ``.ily`` (source code) and ``.msg`` (ROS message IDL) -- are
    subtracted here so those routing decisions do not change.
    """
    global _DOCUMENT_PARSER_EXTS
    if _DOCUMENT_PARSER_EXTS is None:
        from ..document.document_parser import DocumentParser

        cand = set(DocumentParser.routing_suffixes())
        owned = set(_code_exts()) | set(_SCHEMA_EXTS)
        _DOCUMENT_PARSER_EXTS = frozenset(cand - owned)
    return _DOCUMENT_PARSER_EXTS


def _config_exts() -> frozenset:
    """Last-component suffixes owned by ConfigAnalyzer's configuration universe.

    The 345 ``config``-type residual extensions (~57 syntax families:
    ini/json/yaml/toml/xml/plist/directive/rulelist/dockerfile/starlark/deb822/
    reg/crontab/fstab/sexpr/gettext/... plus inherently-binary preset/theme files
    that degrade to an honest forensic profile). Every suffix already claimed by a
    higher-priority plane -- including the non-executable binary universe -- is
    subtracted so this set can only add routes for currently-unrouted extensions;
    no existing routing decision changes.
    """
    global _CONFIG_EXTS
    if _CONFIG_EXTS is None:
        from ..config.config_analyzer import ConfigAnalyzer

        cand = set(ConfigAnalyzer.routing_suffixes())
        owned = (
            set(_code_exts())
            | set(_SCHEMA_EXTS)
            | set(_database_exts())
            | set(_ARCHIVE_EXTS)
            | set(_BINARY_EXTS)
            | set(_data_exts())
            | set(_document_parser_exts())
            | set(_binary_format_exts())
        )
        _CONFIG_EXTS = frozenset(cand - owned)
    return _CONFIG_EXTS


def _text_exts() -> frozenset:
    """Last-component suffixes owned by TextualAnalyzer's text-record universe.

    The residual *text-record* extensions across seven content kinds (data_text,
    text, log, documentation, template, scientific_data, subtitle). Every suffix
    already claimed by a higher-priority plane -- including the non-executable
    binary and configuration universes -- is subtracted so this set can only add
    routes for currently-unrouted extensions; no existing routing decision changes.
    """
    global _TEXT_EXTS
    if _TEXT_EXTS is None:
        from ..text.textual_analyzer import TextualAnalyzer

        cand = set(TextualAnalyzer.routing_suffixes())
        owned = (
            set(_code_exts())
            | set(_SCHEMA_EXTS)
            | set(_database_exts())
            | set(_ARCHIVE_EXTS)
            | set(_BINARY_EXTS)
            | set(_data_exts())
            | set(_binary_format_exts())
            | set(_document_parser_exts())
            | set(_config_exts())
        )
        _TEXT_EXTS = frozenset(cand - owned)
    return _TEXT_EXTS


def _markup_exts() -> frozenset:
    """Last-component suffixes owned by MarkupAnalyzer's markup universe.

    The residual *markup* extensions (HTML/XHTML vocabularies, ~200 XML
    application dialects, OFX SGML, and wiki/gemtext/roff/typst/MIF/markdown/
    lightweight markups). Every suffix already claimed by a higher-priority
    plane -- including the configuration and text-record universes -- is
    subtracted so this set can only add routes for currently-unrouted
    extensions; no existing routing decision changes.
    """
    global _MARKUP_EXTS
    if _MARKUP_EXTS is None:
        from ..markup.markup_analyzer import MarkupAnalyzer

        cand = set(MarkupAnalyzer.routing_suffixes())
        owned = (
            set(_code_exts())
            | set(_SCHEMA_EXTS)
            | set(_database_exts())
            | set(_ARCHIVE_EXTS)
            | set(_BINARY_EXTS)
            | set(_data_exts())
            | set(_binary_format_exts())
            | set(_config_exts())
            | set(_document_parser_exts())
            | set(_text_exts())
        )
        _MARKUP_EXTS = frozenset(cand - owned)
    return _MARKUP_EXTS


def _document_exts() -> frozenset:
    """Last-component suffixes owned by DocumentAnalyzer's document universe.

    The residual *document* extensions across eight content kinds (package/lock/
    streaming/build manifests, query-language sources, make/automake build
    descriptions, PEM/SSH/signature certificate text, computational notebooks,
    FDF/Google-doc/PML document files, SPDX/DEP-5 license text, and unified
    diffs). Every suffix already claimed by a higher-priority plane -- including
    the configuration, text-record and markup universes -- is subtracted so this
    set can only add routes for currently-unrouted extensions; no existing
    routing decision changes.
    """
    global _DOCUMENT_EXTS
    if _DOCUMENT_EXTS is None:
        from ..document.document_analyzer import DocumentAnalyzer

        cand = set(DocumentAnalyzer.routing_suffixes())
        owned = (
            set(_code_exts())
            | set(_SCHEMA_EXTS)
            | set(_database_exts())
            | set(_ARCHIVE_EXTS)
            | set(_BINARY_EXTS)
            | set(_data_exts())
            | set(_binary_format_exts())
            | set(_config_exts())
            | set(_text_exts())
            | set(_document_parser_exts())
            | set(_markup_exts())
        )
        _DOCUMENT_EXTS = frozenset(cand - owned)
    return _DOCUMENT_EXTS


def _misc_exts() -> frozenset:
    """Last-component suffixes owned by MiscAnalyzer -- the terminal plane.

    The residual structured-text extensions no earlier plane claims (Qt style
    sheets, OpenShot / Camtasia video-editor projects, PostgreSQL pg_dump
    scripts). Every suffix already claimed by a higher-priority plane -- through
    and including the document universe -- is subtracted, so this set can only add
    routes for currently-unrouted extensions; no existing routing decision
    changes.
    """
    global _MISC_EXTS
    if _MISC_EXTS is None:
        from ..misc.misc_analyzer import MiscAnalyzer

        cand = set(MiscAnalyzer.routing_suffixes())
        owned = (
            set(_code_exts())
            | set(_SCHEMA_EXTS)
            | set(_database_exts())
            | set(_ARCHIVE_EXTS)
            | set(_BINARY_EXTS)
            | set(_data_exts())
            | set(_binary_format_exts())
            | set(_config_exts())
            | set(_text_exts())
            | set(_markup_exts())
            | set(_document_parser_exts())
            | set(_document_exts())
        )
        _MISC_EXTS = frozenset(cand - owned)
    return _MISC_EXTS


def _suffix(name_or_path: Union[str, Path]) -> str:
    """Return the true (last-component) lowercase suffix, e.g. ``.tar.gz`` -> ``.gz``."""
    return Path(str(name_or_path)).suffix.lower()


def resolve_analyzer(name_or_path: Union[str, Path]) -> Optional[str]:
    """Map a filename / path to its analyzer-class id (``code``/``schema``/``data``) or None."""
    ext = _suffix(name_or_path)
    if not ext:
        return None
    if ext in _code_exts():
        return "code"
    if ext in _SCHEMA_EXTS:
        return "schema"
    # Document-format files (word-processor / e-book / page-description / notation
    # documents). A HIGH-priority plane: it reclaims these ``document``-type
    # suffixes from the lower-priority generic planes (data / binary-format /
    # archive / text / ...) that previously absorbed them by tail. Only ``code``
    # and ``schema`` above keep their dual-use tails (``.gp`` / ``.ws`` / ``.ily`` /
    # ``.msg``); those are already subtracted from this set.
    if ext in _document_parser_exts():
        return "document_parser"
    if ext in _database_exts():
        return "database"
    if ext in _ARCHIVE_EXTS:
        return "archive"
    if ext in _BINARY_EXTS:
        return "binary"
    if ext in _data_exts():
        return "data"
    # Non-executable structural binary formats (checked after the semantic-data
    # plane so a data-owned suffix is never shadowed; the set already excludes
    # every other plane's suffixes, so this only routes the previously-residual).
    if ext in _binary_format_exts():
        return "binary"
    # Configuration files (checked last; the set already excludes every other
    # plane's suffixes, so this only routes the previously-residual config exts).
    if ext in _config_exts():
        return "config"
    # Text-record files (checked last; the set already excludes every other
    # plane's suffixes, so this only routes the previously-residual text exts).
    if ext in _text_exts():
        return "text"
    # Markup files (checked last; the set already excludes every other plane's
    # suffixes, so this only routes the previously-residual markup exts).
    if ext in _markup_exts():
        return "markup"
    # Document files (checked last; the set already excludes every other plane's
    # suffixes, so this only routes the previously-residual document exts).
    if ext in _document_exts():
        return "document"
    # Misc files (the terminal plane; the set already excludes every other
    # plane's suffixes, so this only routes the previously-residual misc exts).
    if ext in _misc_exts():
        return "misc"
    return None


# ----------------------------------------------------------------------------
# Repository-path reconstruction (mirrors ImportLinkageAnalyzer / SchemaAnalyzer
# so a file's on-disk absolute path can be rebuilt from the relational tables).
# ----------------------------------------------------------------------------
def _clean_ext(ext: Optional[str]) -> Optional[str]:
    if ext in (None, "None", ""):
        return None
    return ext


def reconstruct_paths(
    dir_path: Union[str, Path],
    folders: List[Dict[str, Any]],
    extensions: List[Dict[str, Any]],
    files: List[Dict[str, Any]],
) -> Dict[int, Path]:
    """
    Rebuild the absolute on-disk path for every repository file row, keyed by
    ``file_id``. ``extension_name`` is "everything after the first dot"; combined
    with the deepest folder in ``location`` and the repository root this yields
    the concrete path each analyzer worker must open.
    """
    root = Path(dir_path).resolve()
    ext_by_id = {e["extension_id"]: e["extension_name"] for e in extensions}
    folder_by_id = {f["folder_id"]: f["folder_name"] for f in folders}

    out: Dict[int, Path] = {}
    for f in files:
        ext = _clean_ext(ext_by_id.get(f.get("file_extension_id")))
        location = f.get("location") or []
        deepest = location[-1] if location else 1
        folder_path = folder_by_id.get(deepest, ".")
        fname = f["file_name"] + (f".{ext}" if ext else "")
        rel = fname if folder_path in (".", "", None) else f"{folder_path}/{fname}"
        out[f["file_id"]] = (root / rel).resolve()
    return out


def build_mapping(
    dir_path: Union[str, Path],
    folders: List[Dict[str, Any]],
    extensions: List[Dict[str, Any]],
    files: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Produce the file->analyzer mapping rows:

        {"file_id": int, "file_location": str(abs path), "analyzer_class": str|None}

    Files no engine claims are still emitted with ``analyzer_class == None`` so the
    mapping is a faithful, total census of the repository.
    """
    paths = reconstruct_paths(dir_path, folders, extensions, files)
    mapping: List[Dict[str, Any]] = []
    for f in files:
        fid = f["file_id"]
        loc = paths.get(fid)
        mapping.append(
            {
                "file_id": fid,
                "file_location": str(loc) if loc is not None else None,
                "analyzer_class": resolve_analyzer(
                    loc.name if loc is not None else f["file_name"]
                ),
            }
        )
    return mapping


def group_into_shards(mapping: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group the mapping into one shard per analyzer class (preserving each engine's
    internal id-space and its ``link_repository`` contract, which both assume the
    whole file set of that domain is analyzed together).

        {"shard_id": str, "analyzer_class": str,
         "file_ids": [int...], "file_paths": [str...]}

    Only the plane-driven engines (``code``/``schema``/``database``/``data``) become shards.
    ``archive`` and ``binary`` files are intentionally excluded: they are handled by
    dedicated post-planes stages (``ArchiveAnalyzer`` -> extract -> nested
    AnalysisEngine; ``MachineCodeAnalyzer`` -> deep struct parse), not by the Go
    per-shard workers.
    """
    buckets: Dict[str, Dict[str, Any]] = {}
    for row in mapping:
        cls = row.get("analyzer_class")
        loc = row.get("file_location")
        if cls is None or loc is None:
            continue
        b = buckets.setdefault(cls, {"file_ids": [], "file_paths": []})
        b["file_ids"].append(row["file_id"])
        b["file_paths"].append(loc)

    shards: List[Dict[str, Any]] = []
    for cls in (
        "code",
        "schema",
        "database",
        "data",
        "config",
        "text",
        "markup",
        "document",
        "document_parser",
        "misc",
    ):
        b = buckets.get(cls)
        if not b or not b["file_paths"]:
            continue
        shards.append(
            {
                "shard_id": f"shard_{cls}",
                "analyzer_class": cls,
                "file_ids": b["file_ids"],
                "file_paths": b["file_paths"],
            }
        )
    return shards
