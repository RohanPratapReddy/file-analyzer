"""
Real, structural parsers for database *files* (one file → one on-disk store).

Every parser is pure-stdlib and works from the documented on-disk layout of the
engine.  Nothing here executes the database, links a native driver, decrypts an
encrypted store, or reads user *values* beyond what a bounded metadata/profile
pass needs — opaque, proprietary or encrypted stores degrade to an honest
forensic byte profile (``structural_parse=False``), never a fabricated schema.

The public entry point is :func:`analyze(path, ext)` which returns a normalised
``DatabaseProfile`` dict::

    {
      "engine":          "sqlite" | "dbase" | "berkeleydb" | ... ,
      "engine_family":   "relational"|"key_value"|"document"|"columnar"|
                         "time_series"|"graph"|"vector"|"mail_store"|
                         "accounting"|"password_manager"|"crypto_wallet"|
                         "analytics_cube"|"legacy_isam"|"forensic_timeline"|
                         "geospatial"|"embedded"|"unknown",
      "structural_parse": bool,          # True = real schema/counts extracted
      "likely_encrypted": bool,
      "status":          "ok" | "partial",
      "store":           { page_size, page_count, encoding, ... },  # store-level
      "tables":          [ {name, kind, row_count, estimated, columns:[...],
                            notes} ],
      "indexes":         [ {name, table, unique, method, columns:[...]} ],
      "relations":       [ {type, from_table, from_column, to_table,
                            to_column, value, method, extra} ],
      "properties":      { ... free-form technical metadata ... },
      "notes":           str | None,
    }

Sniffing is by *content* (magic bytes) first and by extension only as a hint,
so a ``.sqlitedb`` / ``.lrcat`` / ``.sdltm`` that is really SQLite is fully
introspected, and a mislabelled file is classified by what it actually is.
"""

from __future__ import annotations

import sqlite3
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

# Reuse the honest-forensic byte-metadata layer (never stores payload).
from ..data.catalog_binary_formats import (
    _ascii_strings,
    _head,
    _magic_ascii,
    _sha256_and_entropy,
)


# --------------------------------------------------------------------------
# small binary helpers
# --------------------------------------------------------------------------
def _u16le(b, o=0):
    return struct.unpack_from("<H", b, o)[0]


def _u16be(b, o=0):
    return struct.unpack_from(">H", b, o)[0]


def _u32le(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def _u32be(b, o=0):
    return struct.unpack_from(">I", b, o)[0]


def _u64le(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


def _u64be(b, o=0):
    return struct.unpack_from(">Q", b, o)[0]


def _size(path: Path) -> Optional[int]:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _read_at(path: Path, offset: int, n: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(n)


def _profile(
    engine: str,
    family: str,
    *,
    structural: bool,
    status: str = "ok",
    encrypted: bool = False,
    store: Optional[Dict[str, Any]] = None,
    tables: Optional[List[Dict[str, Any]]] = None,
    indexes: Optional[List[Dict[str, Any]]] = None,
    relations: Optional[List[Dict[str, Any]]] = None,
    properties: Optional[Dict[str, Any]] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "engine": engine,
        "engine_family": family,
        "structural_parse": bool(structural),
        "likely_encrypted": bool(encrypted),
        "status": status,
        "store": store or {},
        "tables": tables or [],
        "indexes": indexes or [],
        "relations": relations or [],
        "properties": {k: v for k, v in (properties or {}).items() if v is not None},
        "notes": notes,
    }


def _column(
    name: str,
    declared_type: Optional[str] = None,
    *,
    inferred_type: Optional[str] = None,
    nullable: Optional[bool] = None,
    primary_key: bool = False,
    unique: bool = False,
    default: Any = None,
    references_table: Optional[str] = None,
    references_column: Optional[str] = None,
    null_count: Optional[int] = None,
    non_null_count: Optional[int] = None,
    distinct_count: Optional[int] = None,
    minimum: Any = None,
    maximum: Any = None,
    samples: Optional[List[Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "declared_type": declared_type,
        "inferred_type": inferred_type,
        "nullable": nullable,
        "primary_key": primary_key,
        "unique": unique,
        "default": default,
        "references_table": references_table,
        "references_column": references_column,
        "null_count": null_count,
        "non_null_count": non_null_count,
        "distinct_count": distinct_count,
        "minimum": minimum,
        "maximum": maximum,
        "samples": samples or [],
        "extra": extra or {},
    }


def _forensic(
    path: Path,
    engine: str,
    family: str,
    note: Optional[str] = None,
    status: str = "partial",
) -> Dict[str, Any]:
    """Honest byte-level store profile for an opaque/proprietary/encrypted DB.

    Emits real byte metadata only — never a fabricated schema, never payload.
    """
    head = _head(path, 512)
    sha, ent, pr, scanned = _sha256_and_entropy(path)
    size = _size(path)
    props: Dict[str, Any] = {
        "byte_size": size,
        "sha256": sha,
        "hash_scanned_bytes": scanned,
        "hash_is_partial": size is not None and scanned < size,
        "magic_hex": head[:16].hex() if head else None,
        "magic_ascii": _magic_ascii(head) if head else None,
        "shannon_entropy": ent,
        "printable_ratio": pr,
    }
    strings = _ascii_strings(head)
    if strings:
        props["sample_strings"] = strings[:16]
    return _profile(
        engine,
        family,
        structural=False,
        status=status,
        encrypted=ent >= 7.5,
        properties=props,
        notes=note,
    )


# ==========================================================================
# SQLite (and every store that is really SQLite underneath)
# ==========================================================================
_SQLITE_MAGIC = b"SQLite format 3\x00"
# Per-table data-profile is skipped for tables larger than this (row scan cost).
_PROFILE_ROW_CAP = 200_000
_SAMPLE_LIMIT = 5
_MAX_TABLES = 2000
_SQLITE_TEXT_ENCODING = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}


def sqlite_profile(
    path: Path, engine: str = "sqlite", family: str = "relational"
) -> Dict[str, Any]:
    """Full schema + bounded data profile for a SQLite-format-3 store.

    Merges the schema view (tables/views/columns/types/PK/FK/indexes) with a
    DataAnalyzer-style per-column data profile (row/null/distinct/min/max/
    samples) for tables under a row cap — never storing raw payload rows.
    """
    hdr = _read_at(path, 0, 100)
    if not hdr.startswith(_SQLITE_MAGIC):
        raise ValueError("not a SQLite database")
    store: Dict[str, Any] = {}
    try:
        page_size = _u16be(hdr, 16)
        page_size = 65536 if page_size == 1 else page_size
        store["page_size"] = page_size
        store["page_count"] = _u32be(hdr, 28) or None
        store["file_format_write"] = hdr[18]
        store["file_format_read"] = hdr[19]
        enc = _u32be(hdr, 56)
        store["text_encoding"] = _SQLITE_TEXT_ENCODING.get(enc, str(enc))
        store["user_version"] = _u32be(hdr, 60)
        store["schema_cookie"] = _u32be(hdr, 40)
        store["application_id"] = _u32be(hdr, 68)
    except struct.error:
        pass

    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    except Exception as err:  # locked / corrupt header only
        prof = _forensic(
            path, engine, family, note=f"SQLite header valid but connect failed: {err}"
        )
        prof["store"].update(store)
        prof["structural_parse"] = True
        prof["status"] = "partial"
        return prof

    tables: List[Dict[str, Any]] = []
    indexes: List[Dict[str, Any]] = []
    relations: List[Dict[str, Any]] = []
    try:
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        cur = conn.cursor()
        cur.execute(
            "SELECT type, name FROM sqlite_master "
            "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        )
        objs = cur.fetchall()[:_MAX_TABLES]
        store["object_count"] = len(objs)
        for otype, tname in objs:
            trow = _sqlite_table(cur, otype, tname, relations)
            tables.append(trow)
            _sqlite_indexes(cur, tname, indexes)
    finally:
        conn.close()

    return _profile(
        engine,
        family,
        structural=True,
        store=store,
        tables=tables,
        indexes=indexes,
        relations=relations,
        properties={"driver": "sqlite3", "sqlite_lib_version": sqlite3.sqlite_version},
    )


def _q(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


def _sqlite_table(
    cur, otype: str, tname: str, relations: List[Dict[str, Any]]
) -> Dict[str, Any]:
    kind = "view" if otype == "view" else "table"
    cols: List[Dict[str, Any]] = []
    notes = None
    try:
        cur.execute(f"PRAGMA table_info({_q(tname)})")
        info = cur.fetchall()  # cid,name,type,notnull,dflt,pk
    except Exception as err:
        return {
            "name": tname,
            "kind": kind,
            "row_count": None,
            "estimated": False,
            "columns": [],
            "notes": f"table_info failed: {err}",
        }

    pk_names = {c[1] for c in info if c[5]}
    for cid, cname, ctype, notnull, dflt, pk in info:
        cols.append(
            _column(
                str(cname),
                str(ctype) if ctype else None,
                nullable=not bool(notnull),
                primary_key=bool(pk),
                default=dflt,
                inferred_type=_sqlite_affinity(ctype),
            )
        )

    # foreign keys -> relations
    if kind == "table":
        try:
            cur.execute(f"PRAGMA foreign_key_list({_q(tname)})")
            for fk in cur.fetchall():  # id,seq,table,from,to,on_upd,on_del,match
                relations.append(
                    {
                        "type": "foreign_key",
                        "from_table": tname,
                        "from_column": fk[3],
                        "to_table": fk[2],
                        "to_column": fk[4],
                        "value": None,
                        "method": None,
                        "extra": {"on_update": fk[5], "on_delete": fk[6]},
                    }
                )
                for c in cols:
                    if c["name"] == fk[3]:
                        c["references_table"] = fk[2]
                        c["references_column"] = fk[4]
        except Exception:
            pass

    row_count = None
    estimated = False
    try:
        cur.execute(f"SELECT COUNT(*) FROM {_q(tname)}")
        row_count = int(cur.fetchone()[0])
    except Exception as err:
        notes = f"row count failed: {err}"

    # bounded per-column data profile (merges DataAnalyzer behaviour)
    if (
        kind == "table"
        and row_count is not None
        and 0 < row_count <= _PROFILE_ROW_CAP
        and cols
    ):
        _sqlite_profile_columns(cur, tname, cols, row_count)

    return {
        "name": tname,
        "kind": kind,
        "row_count": row_count,
        "estimated": estimated,
        "columns": cols,
        "notes": notes,
        "primary_key": sorted(pk_names) or None,
    }


def _sqlite_affinity(decl: Optional[str]) -> str:
    d = (decl or "").upper()
    if "INT" in d:
        return "integer"
    if any(t in d for t in ("CHAR", "CLOB", "TEXT")):
        return "text"
    if "BLOB" in d or d == "":
        return "blob"
    if any(t in d for t in ("REAL", "FLOA", "DOUB")):
        return "real"
    return "numeric"


def _sqlite_profile_columns(
    cur, tname: str, cols: List[Dict[str, Any]], row_count: int
) -> None:
    """One aggregate pass for null/non-null/distinct/min/max + a small sample."""
    for c in cols:
        col = c["name"]
        try:
            cur.execute(
                f"SELECT COUNT(*) - COUNT({_q(col)}), COUNT({_q(col)}), "
                f"COUNT(DISTINCT {_q(col)}), MIN({_q(col)}), MAX({_q(col)}) "
                f"FROM {_q(tname)}"
            )
            nulls, non_null, distinct, mn, mx = cur.fetchone()
            c["null_count"] = int(nulls) if nulls is not None else None
            c["non_null_count"] = int(non_null) if non_null is not None else None
            c["distinct_count"] = int(distinct) if distinct is not None else None
            c["minimum"] = _clip(mn)
            c["maximum"] = _clip(mx)
            c["unique"] = bool(
                distinct is not None
                and non_null
                and distinct == non_null
                and non_null == row_count
            )
        except Exception:
            continue
        try:
            cur.execute(
                f"SELECT DISTINCT {_q(col)} FROM {_q(tname)} "
                f"WHERE {_q(col)} IS NOT NULL LIMIT {_SAMPLE_LIMIT}"
            )
            c["samples"] = [_clip(r[0]) for r in cur.fetchall()]
        except Exception:
            pass


def _clip(v: Any) -> Any:
    if isinstance(v, bytes):
        return f"<blob {len(v)} bytes>"
    if isinstance(v, str):
        return v[:256]
    return v


def _sqlite_indexes(cur, tname: str, indexes: List[Dict[str, Any]]) -> None:
    try:
        cur.execute(f"PRAGMA index_list({_q(tname)})")
        idx_list = cur.fetchall()  # seq,name,unique,origin,partial
    except Exception:
        return
    for row in idx_list:
        iname, uniq = row[1], bool(row[2])
        cols: List[str] = []
        try:
            cur.execute(f"PRAGMA index_info({_q(iname)})")
            cols = [r[2] for r in cur.fetchall() if r[2] is not None]
        except Exception:
            pass
        indexes.append(
            {
                "name": iname,
                "table": tname,
                "unique": uniq,
                "method": (row[3] if len(row) > 3 else None),
                "columns": cols,
            }
        )


# ==========================================================================
# dBASE / xBase family (.dbf) — fully documented header + field descriptors
# ==========================================================================
_DBF_VERSIONS = {
    0x02: "FoxBASE",
    0x03: "dBASE III+ (no memo)",
    0x04: "dBASE IV (no memo)",
    0x05: "dBASE V (no memo)",
    0x30: "Visual FoxPro",
    0x31: "Visual FoxPro (auto-incr)",
    0x32: "Visual FoxPro (varchar)",
    0x43: "dBASE IV SQL table",
    0x7B: "dBASE IV (with memo)",
    0x83: "dBASE III+ (with memo)",
    0x8B: "dBASE IV (with memo)",
    0x8E: "dBASE IV (with SQL)",
    0xF5: "FoxPro 2.x (with memo)",
    0xFB: "FoxPro (no memo)",
}
_DBF_FIELD_TYPES = {
    "C": "character",
    "N": "numeric",
    "F": "float",
    "D": "date",
    "L": "logical",
    "M": "memo",
    "T": "datetime",
    "I": "integer",
    "Y": "currency",
    "B": "double",
    "G": "general",
    "P": "picture",
    "Q": "varbinary",
    "V": "varchar",
    "W": "blob",
    "@": "timestamp",
    "+": "autoincrement",
    "O": "double",
    "0": "null_flags",
}


def dbase_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 32)
    if len(hdr) < 32:
        raise ValueError("dbf too short")
    version = hdr[0]
    if version not in _DBF_VERSIONS and (version & 0x07) not in (2, 3, 4, 5):
        raise ValueError("not a dBASE table")
    n_records = _u32le(hdr, 4)
    header_size = _u16le(hdr, 8)
    record_size = _u16le(hdr, 10)
    yy, mm, dd = hdr[1], hdr[2], hdr[3]
    last_update = f"{1900 + yy:04d}-{mm:02d}-{dd:02d}" if 1 <= mm <= 12 else None

    # field descriptors: 32 bytes each, from offset 32 until 0x0D terminator
    field_area = _read_at(path, 32, max(0, header_size - 32))
    cols: List[Dict[str, Any]] = []
    off = 0
    while off + 32 <= len(field_area):
        if field_area[off] == 0x0D:
            break
        fd = field_area[off : off + 32]
        raw_name = fd[0:11].split(b"\x00", 1)[0]
        fname = raw_name.decode("ascii", "replace").strip() or f"field_{len(cols) + 1}"
        ftype = chr(fd[11]) if 32 <= fd[11] < 127 else "?"
        flen = fd[16]
        fdec = fd[17]
        flags = fd[18]
        cols.append(
            _column(
                fname,
                ftype,
                inferred_type=_DBF_FIELD_TYPES.get(ftype, "unknown"),
                nullable=bool(flags & 0x02),
                extra={
                    "length": flen,
                    "decimals": fdec,
                    "system_column": bool(flags & 0x01),
                    "autoincrement": bool(flags & 0x0C),
                },
            )
        )
        off += 32

    store = {
        "dbase_version_byte": f"0x{version:02X}",
        "dbase_version": _DBF_VERSIONS.get(version, "xBase variant"),
        "header_size": header_size,
        "record_size": record_size,
        "has_memo": bool(version & 0x80),
        "last_update": last_update,
        "encrypted_flag": bool(hdr[15] & 0x01),
        "mdx_flag": bool(hdr[28]),
        "language_driver": hdr[29],
    }
    table = {
        "name": path.stem,
        "kind": "table",
        "row_count": n_records,
        "estimated": False,
        "columns": cols,
        "notes": None if cols else "no field descriptors",
    }
    return _profile(
        "dbase",
        "relational",
        structural=True,
        store=store,
        tables=[table],
        properties={"field_count": len(cols)},
    )


def dbase_memo_profile(path: Path, ext: str) -> Dict[str, Any]:
    """dBASE/FoxPro memo side-files (.dbt/.fpt/.mb): block store, header only."""
    hdr = _read_at(path, 0, 512)
    store: Dict[str, Any] = {}
    if ext == ".fpt" and len(hdr) >= 8:  # FoxPro memo: big-endian header
        store["next_free_block"] = _u32be(hdr, 0)
        store["block_size"] = _u16be(hdr, 6)
    elif len(hdr) >= 4:  # dBASE .dbt / Paradox .mb
        store["next_free_block"] = _u32le(hdr, 0)
    return _profile(
        "dbase_memo",
        "relational",
        structural=True,
        status="partial",
        store=store,
        notes="memo/BLOB side-file for a dBASE/FoxPro/Paradox table "
        "(payload not stored)",
    )


def dbase_index_profile(path: Path, ext: str) -> Dict[str, Any]:
    """dBASE/FoxPro index side-files (.ndx/.cdx/.px): b-tree header only."""
    hdr = _read_at(path, 0, 512)
    store: Dict[str, Any] = {}
    try:
        if ext == ".ndx" and len(hdr) >= 16:
            store["root_page"] = _u32le(hdr, 0)
            store["page_count"] = _u32le(hdr, 4)
            store["key_length"] = _u16le(hdr, 12)
        elif ext == ".cdx" and len(hdr) >= 12:  # FoxPro compound index (big-endian)
            store["root_node"] = _u32be(hdr, 0)
            store["key_length"] = _u16be(hdr, 10)
    except struct.error:
        pass
    return _profile(
        "dbase_index",
        "relational",
        structural=True,
        status="partial",
        store=store,
        indexes=[
            {
                "name": path.stem,
                "table": None,
                "unique": None,
                "method": "btree",
                "columns": [],
            }
        ],
        notes="index side-file for a dBASE/FoxPro table",
    )


# ==========================================================================
# Berkeley DB (.bdb / .db / wallet) — documented page-0 magic
# ==========================================================================
_BDB_MAGIC = {
    0x00061561: "btree",
    0x00061562: "btree",
    0x00053162: "hash",
    0x00042253: "queue",
    0x00072162: "heap",
    0x00040988: "log",
    0x00060461: "qam",
}


def berkeleydb_profile(
    path: Path, engine: str = "berkeleydb", family: str = "key_value"
) -> Dict[str, Any]:
    page0 = _read_at(path, 0, 72)
    if len(page0) < 20:
        raise ValueError("bdb too short")
    magic = None
    order = None
    subtype = None
    for off in (12,):
        for reader, endian in ((_u32le, "little"), (_u32be, "big")):
            try:
                m = reader(page0, off)
            except struct.error:
                continue
            if m in _BDB_MAGIC:
                magic, order, subtype = m, endian, _BDB_MAGIC[m]
                break
        if magic:
            break
    if magic is None:
        raise ValueError("not a Berkeley DB store")
    rdr = _u32le if order == "little" else _u32be
    version = rdr(page0, 16)
    page_size = rdr(page0, 20) if len(page0) >= 24 else None
    size = _size(path)
    store = {
        "subtype": subtype,
        "byte_order": order,
        "bdb_version": version,
        "page_size": page_size,
        "page_count": (size // page_size) if (page_size and size) else None,
    }
    return _profile(
        engine,
        family,
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": f"Berkeley DB {subtype} — opaque key/value pairs",
            }
        ],
        notes="Berkeley DB access-method store (keys/values are opaque bytes)",
    )


# ==========================================================================
# GNU dbm (.gdbm) — documented magic
# ==========================================================================
_GDBM_MAGIC = {
    0x13579ACD: "gdbm (std)",
    0x13579ACE: "gdbm (0.4)",
    0x13579ACF: "gdbm (64-bit)",
    0x13579ACB: "gdbm (old)",
}


def gdbm_profile(path: Path) -> Dict[str, Any]:
    head = _read_at(path, 0, 8)
    if len(head) < 4:
        raise ValueError("gdbm too short")
    magic = None
    order = None
    for reader, endian in ((_u32le, "little"), (_u32be, "big")):
        m = reader(head, 0)
        if m in _GDBM_MAGIC:
            magic, order = m, endian
            break
    if magic is None:
        raise ValueError("not a GNU dbm store")
    rdr = _u16le if order == "little" else _u16be
    block_size = None
    try:
        block_size = (_u32le if order == "little" else _u32be)(head, 4)
    except struct.error:
        pass
    return _profile(
        "gdbm",
        "key_value",
        structural=True,
        status="partial",
        store={
            "variant": _GDBM_MAGIC[magic],
            "byte_order": order,
            "block_size": block_size,
        },
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "GNU dbm hash store — opaque key/value pairs",
            }
        ],
        notes="GNU dbm key/value store",
    )


# ==========================================================================
# Samba trivial database (.tdb) — documented text magic
# ==========================================================================
def tdb_profile(path: Path) -> Dict[str, Any]:
    head = _read_at(path, 0, 64)
    if not head.startswith(b"TDB file\n"):
        raise ValueError("not a TDB file")
    store: Dict[str, Any] = {}
    try:
        store["tdb_magic"] = f"0x{_u32le(head, 32):08X}"
        store["hash_size"] = _u32le(head, 36)
    except struct.error:
        pass
    return _profile(
        "tdb",
        "key_value",
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "Samba trivial DB — opaque key/value pairs",
            }
        ],
        notes="Samba/ctdb trivial database (key/value)",
    )


# ==========================================================================
# LMDB / libmdbx (.lmdb / .mdbx) — documented meta page
# ==========================================================================
_LMDB_MAGIC = 0xBEEFC0DE
_MDBX_MAGIC = 0xBEEFC0DE  # mdbx shares/derives the constant


def lmdb_profile(path: Path, ext: str) -> Dict[str, Any]:
    # The meta page sits at file start; try common page sizes to locate the magic.
    for page_size in (4096, 8192, 16384, 65536, 512, 1024, 2048):
        page = _read_at(path, 0, min(page_size, 256))
        if len(page) < 32:
            continue
        # page header is 16 bytes (mp_pgno u64 for 64-bit builds); magic follows.
        for magic_off in (16, 8, 12, 20):
            try:
                m = _u32le(page, magic_off)
            except struct.error:
                continue
            if m in (_LMDB_MAGIC, _MDBX_MAGIC):
                store = {"meta_magic": f"0x{m:08X}", "page_size_guess": page_size}
                try:
                    store["format_version"] = _u32le(page, magic_off + 4)
                except struct.error:
                    pass
                engine = "mdbx" if ext == ".mdbx" else "lmdb"
                return _profile(
                    engine,
                    "key_value",
                    structural=True,
                    status="partial",
                    store=store,
                    tables=[
                        {
                            "name": "main",
                            "kind": "tree",
                            "row_count": None,
                            "estimated": False,
                            "columns": [],
                            "notes": "memory-mapped B+tree — opaque key/value pairs",
                        }
                    ],
                    notes="Lightning/libmdbx memory-mapped key/value store",
                )
    raise ValueError("no LMDB/mdbx meta page magic found")


# ==========================================================================
# LevelDB / RocksDB SSTable (.ldb / .leveldb / .sst) — documented footer magic
# ==========================================================================
_LEVELDB_TABLE_MAGIC = 0xDB4775248B80FB57
_LEVELDB_FOOTER = 48
_ROCKSDB_FOOTER = 53  # legacy footer + format byte


def leveldb_sst_profile(path: Path) -> Dict[str, Any]:
    size = _size(path)
    if not size or size < _LEVELDB_FOOTER:
        raise ValueError("sst too short")
    tail = _read_at(path, size - _LEVELDB_FOOTER, _LEVELDB_FOOTER)
    magic = _u64le(tail, _LEVELDB_FOOTER - 8)
    engine = None
    if magic == _LEVELDB_TABLE_MAGIC:
        engine = "leveldb"
    else:
        # RocksDB writes a longer footer; the magic is still in the last 8 bytes.
        if size >= _ROCKSDB_FOOTER:
            tail2 = _read_at(path, size - _ROCKSDB_FOOTER, _ROCKSDB_FOOTER)
            if _u64le(tail2, _ROCKSDB_FOOTER - 8) == _LEVELDB_TABLE_MAGIC:
                engine = "rocksdb"
    if engine is None:
        raise ValueError("no LevelDB/RocksDB table magic in footer")
    return _profile(
        engine,
        "key_value",
        structural=True,
        status="partial",
        store={
            "table_magic": f"0x{_LEVELDB_TABLE_MAGIC:016X}",
            "footer_bytes": _LEVELDB_FOOTER,
            "file_size": size,
        },
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "sorted string table — opaque sorted key/value blocks",
            }
        ],
        notes="LevelDB/RocksDB SSTable (immutable sorted key/value)",
    )


# ==========================================================================
# Redis RDB snapshot (.rdb) — documented header + opcode walk (metadata only)
# ==========================================================================
_RDB_OP_AUX = 0xFA
_RDB_OP_RESIZEDB = 0xFB
_RDB_OP_EXPIRETIME_MS = 0xFC
_RDB_OP_EXPIRETIME = 0xFD
_RDB_OP_SELECTDB = 0xFE
_RDB_OP_EOF = 0xFF
_RDB_OP_MODULE_AUX = 0xF7
_RDB_OP_IDLE = 0xF8
_RDB_OP_FREQ = 0xF9
_RDB_OP_FUNCTION2 = 0xF5


def rdb_profile(path: Path) -> Dict[str, Any]:
    head = _read_at(path, 0, 9)
    if not head.startswith(b"REDIS"):
        raise ValueError("not a Redis RDB snapshot")
    version = head[5:9].decode("ascii", "replace")
    aux: Dict[str, Any] = {}
    databases: List[Dict[str, Any]] = []
    cur_db = {"db": 0, "keys": None, "expires": None}

    with open(path, "rb") as f:
        f.seek(9)
        raw = f.read(1 << 20)  # header region only: aux + RESIZEDB
    i = 0
    n = len(raw)

    def read_len(pos):
        """RDB length encoding; returns (value, new_pos, is_special) or None."""
        if pos >= n:
            return None
        b = raw[pos]
        typ = (b & 0xC0) >> 6
        if typ == 0:
            return (b & 0x3F, pos + 1, False)
        if typ == 1:
            if pos + 1 >= n:
                return None
            return (((b & 0x3F) << 8) | raw[pos + 1], pos + 2, False)
        if typ == 2:
            if b == 0x80:
                if pos + 5 > n:
                    return None
                return (struct.unpack_from(">I", raw, pos + 1)[0], pos + 5, False)
            if b == 0x81:
                if pos + 9 > n:
                    return None
                return (struct.unpack_from(">Q", raw, pos + 1)[0], pos + 9, False)
            return None
        return (b & 0x3F, pos + 1, True)  # special (LZF / int) encoding

    def skip_string(pos):
        r = read_len(pos)
        if r is None:
            return None
        length, npos, special = r
        if special:
            if length in (0, 1, 2):  # int8/16/32
                return npos + (1 << length)
            return None  # LZF-compressed: stop cleanly
        return npos + length

    try:
        while i < n:
            op = raw[i]
            if op == _RDB_OP_AUX:
                kpos = skip_string(i + 1)
                if kpos is None:
                    break
                # capture common aux fields (redis-ver, redis-bits, ...)
                kr = read_len(i + 1)
                key = None
                if kr and not kr[2]:
                    key = raw[kr[1] : kr[1] + kr[0]].decode("ascii", "replace")
                vr = read_len(kpos)
                val = None
                if vr and not vr[2]:
                    val = raw[vr[1] : vr[1] + vr[0]].decode("ascii", "replace")
                    vpos = vr[1] + vr[0]
                else:
                    vpos = skip_string(kpos)
                if key and val is not None:
                    aux[key] = val
                if vpos is None:
                    break
                i = vpos
            elif op == _RDB_OP_SELECTDB:
                r = read_len(i + 1)
                if r is None:
                    break
                if cur_db["keys"] is not None:
                    databases.append(cur_db)
                cur_db = {"db": r[0], "keys": None, "expires": None}
                i = r[1]
            elif op == _RDB_OP_RESIZEDB:
                r1 = read_len(i + 1)
                if r1 is None:
                    break
                r2 = read_len(r1[1])
                if r2 is None:
                    break
                cur_db["keys"] = r1[0]
                cur_db["expires"] = r2[0]
                i = r2[1]
            elif op == _RDB_OP_EOF:
                break
            else:
                # a key/value record or an opcode we don't decode: stop the walk
                # (we only need the header/aux/resizedb metadata region).
                break
        if cur_db["keys"] is not None:
            databases.append(cur_db)
    except (struct.error, IndexError):
        pass

    tables = [
        {
            "name": f"db{d['db']}",
            "kind": "keyspace",
            "row_count": d["keys"],
            "estimated": False,
            "columns": [],
            "notes": f"{d['expires']} keys with TTL" if d.get("expires") else None,
        }
        for d in databases
    ]
    total_keys = sum(d["keys"] for d in databases if d["keys"] is not None) or None
    return _profile(
        "redis",
        "key_value",
        structural=True,
        status="ok" if databases else "partial",
        store={"rdb_version": version, **{f"aux_{k}": v for k, v in aux.items()}},
        tables=tables,
        properties={"database_count": len(databases) or None, "total_keys": total_keys},
        notes="Redis RDB snapshot (keyspace metadata; values not materialised)",
    )


# ==========================================================================
# djb constant database (.cdb) — documented fixed layout (metadata only)
# ==========================================================================
def cdb_profile(path: Path) -> Dict[str, Any]:
    size = _size(path)
    if not size or size < 2048:
        raise ValueError("cdb too short")
    header = _read_at(path, 0, 2048)
    # 256 (position, length) pairs; positions must lie within the file.
    slots = struct.unpack_from("<512I", header, 0)
    for k in range(256):
        pos = slots[2 * k]
        length = slots[2 * k + 1]
        if pos and (pos > size or pos + length * 8 > size + 8):
            raise ValueError("cdb hash tables out of range")
    # walk the record section counting entries (no payload retained)
    count = 0
    end_of_data = (
        min(slots[i] for i in range(0, 512, 2) if slots[i]) if any(slots) else 2048
    )
    with open(path, "rb") as f:
        f.seek(2048)
        pos = 2048
        while pos + 8 <= end_of_data and count < 5_000_000:
            rec = f.read(8)
            if len(rec) < 8:
                break
            klen, dlen = struct.unpack("<II", rec)
            step = klen + dlen
            if step <= 0 or pos + 8 + step > size:
                break
            f.seek(pos + 8 + step)
            pos += 8 + step
            count += 1
    return _profile(
        "cdb",
        "key_value",
        structural=True,
        store={"hash_slots": 256},
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": count,
                "estimated": False,
                "columns": [],
                "notes": "constant (read-only) key/value database",
            }
        ],
        properties={"record_count": count},
        notes="djb constant database (cdb)",
    )


# ==========================================================================
# QlikView data file (.qvd) — XML header prefix (real table + fields + rows)
# ==========================================================================
def qvd_profile(path: Path) -> Dict[str, Any]:
    head = _read_at(path, 0, 1 << 20)
    lo = head.lstrip()
    if not (lo.startswith(b"<?xml") or lo.startswith(b"<QvdTableHeader")):
        raise ValueError("no QVD XML header")
    end = head.find(b"</QvdTableHeader>")
    if end == -1:
        raise ValueError("truncated QVD header")
    xml = head[: end + len(b"</QvdTableHeader>")].decode("utf-8", "replace")
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as err:
        raise ValueError(f"QVD header parse error: {err}")

    def _text(tag):
        el = root.find(tag)
        return el.text if el is not None else None

    table_name = _text("TableName") or path.stem
    no_records = _text("NoOfRecords")
    row_count = int(no_records) if no_records and no_records.isdigit() else None
    cols: List[Dict[str, Any]] = []
    fields = root.find("Fields")
    if fields is not None:
        for fld in fields.findall("QvdFieldHeader"):
            fname = fld.findtext("FieldName") or f"field_{len(cols) + 1}"
            uniq = fld.findtext("NoOfSymbols")
            nnull = fld.findtext("NullCount")
            cols.append(
                _column(
                    fname,
                    inferred_type="qvd_symbol",
                    distinct_count=int(uniq) if uniq and uniq.isdigit() else None,
                    null_count=int(nnull) if nnull and nnull.isdigit() else None,
                    extra={"bit_width": fld.findtext("BitWidth")},
                )
            )
    store = {
        "creator_doc": _text("CreatorDoc"),
        "create_utc_time": _text("CreateUtcTime"),
        "qv_build_no": _text("QvBuildNo"),
    }
    return _profile(
        "qlikview",
        "columnar",
        structural=True,
        store=store,
        tables=[
            {
                "name": table_name,
                "kind": "table",
                "row_count": row_count,
                "estimated": False,
                "columns": cols,
                "notes": None,
            }
        ],
        properties={"field_count": len(cols)},
        notes="QlikView data file (QVD) — header/field metadata",
    )


# ==========================================================================
# Microsoft ESE / JET Blue (.edb / Exchange / Windows) — documented header
# ==========================================================================
_ESE_MAGIC = 0x89ABCDEF


def ese_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 668)
    if len(hdr) < 240 or _u32le(hdr, 4) != _ESE_MAGIC:
        raise ValueError("not an ESE database")
    version = _u32le(hdr, 8)
    file_type = _u32le(hdr, 12) if len(hdr) >= 16 else None
    page_size = _u32le(hdr, 236)
    state = _u32le(hdr, 52) if len(hdr) >= 56 else None
    size = _size(path)
    store = {
        "ese_format_version": version,
        "file_type": file_type,
        "page_size": page_size,
        "page_count": ((size // page_size) - 2) if (page_size and size) else None,
        "db_state": {
            1: "just created",
            2: "dirty shutdown",
            3: "clean shutdown",
            4: "being converted",
            5: "force detach",
        }.get(state, state),
    }
    return _profile(
        "ese",
        "relational",
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "ESE b-tree store (Exchange/AD/Windows.edb) — "
                "table catalogue needs full ESE page decode",
            }
        ],
        notes="Microsoft Extensible Storage Engine database",
    )


# ==========================================================================
# Microsoft Access / Jet / ACE (.mdb / .accdb / .mny) — documented header
# ==========================================================================
def jet_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 40)
    if len(hdr) < 20:
        raise ValueError("jet too short")
    sig = hdr[4:19]
    if b"Standard Jet DB" in sig:
        engine, page_size, kind = "access_jet", 2048, "Jet 3 (Access 97)"
    elif b"Standard ACE DB" in hdr[4:20]:
        engine, page_size, kind = "access_ace", 4096, "ACE (Access 2007+)"
    elif b"Standard Jet DB" in hdr[0:24]:
        engine, page_size, kind = "access_jet", 2048, "Jet"
    else:
        raise ValueError("not an Access/Jet/ACE database")
    version_byte = hdr[0x14]
    jet_ver = {
        0x00: "Jet 3 (Access 97)",
        0x01: "Jet 4 (Access 2000-2003)",
        0x02: "ACE 12 (Access 2007)",
        0x03: "ACE 14 (Access 2010)",
        0x04: "ACE 15 (Access 2013)",
        0x05: "ACE 16 (Access 2016+)",
    }
    if version_byte in (0x01,):
        page_size = 4096
    size = _size(path)
    store = {
        "jet_kind": kind,
        "version_byte": f"0x{version_byte:02X}",
        "jet_version": jet_ver.get(version_byte, kind),
        "page_size": page_size,
        "page_count": (size // page_size) if (page_size and size) else None,
    }
    return _profile(
        engine,
        "relational",
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "Access/Jet catalogue (MSysObjects) needs full "
                "Jet page decode; header identified",
            }
        ],
        notes="Microsoft Access / Jet / ACE database",
    )


# ==========================================================================
# Microsoft Outlook PST/OST (.pst / .ost) — documented NDB header
# ==========================================================================
def pst_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 24)
    if not hdr.startswith(b"!BDN"):
        raise ValueError("not a PST/OST store")
    wver = _u16le(hdr, 10)
    fmt = "ANSI (Outlook 97-2002)" if wver < 0x15 else "Unicode (Outlook 2003+)"
    store = {"ndb_format": fmt, "wVer": wver, "content_type": hdr[8:10].hex()}
    return _profile(
        "outlook_pst",
        "mail_store",
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "Outlook message store — folders/messages need "
                "full NDB (BBT/NBT) decode; header identified",
            }
        ],
        notes="Microsoft Outlook personal/offline store (PST/OST)",
    )


# ==========================================================================
# Outlook Express (.dbx) — documented magic
# ==========================================================================
def dbx_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 16)
    if len(hdr) < 4 or hdr[0:4] != b"\xcf\xad\x12\xfe":
        raise ValueError("not an Outlook Express DBX file")
    return _profile(
        "outlook_express",
        "mail_store",
        structural=True,
        status="partial",
        store={"file_type_byte": f"0x{hdr[4]:02X}" if len(hdr) > 4 else None},
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "Outlook Express message/folder index",
            }
        ],
        notes="Outlook Express mail database (DBX)",
    )


# ==========================================================================
# InnoDB tablespace (.ibd) — FIL/FSP header page (space id, flags, page count)
# ==========================================================================
def innodb_profile(path: Path) -> Dict[str, Any]:
    page = _read_at(path, 0, 100)
    if len(page) < 60:
        raise ValueError("ibd too short")
    # FIL header: offset 4 = page number, 24 = FIL_PAGE_TYPE, 34 = space id.
    page_type = _u16be(page, 24)
    space_id = _u32be(page, 34)
    fsp_flags = _u32be(page, 54)  # FSP_SPACE_FLAGS within FSP header
    # page-size from flags (MySQL 5.7+/8.0): bits encode logical page size.
    ssize = (fsp_flags >> 6) & 0xF
    page_size = (512 << ssize) if ssize else 16384
    size = _size(path)
    if page_type not in (0, 8) and space_id > 0xFFFFFF:
        raise ValueError("not a plausible InnoDB page")
    store = {
        "space_id": space_id,
        "fil_page_type": page_type,
        "fsp_flags": f"0x{fsp_flags:X}",
        "page_size": page_size,
        "page_count": (size // page_size) if (page_size and size) else None,
    }
    return _profile(
        "innodb",
        "relational",
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "InnoDB tablespace — row schema in the data "
                "dictionary/SDI; header identified",
            }
        ],
        notes="MySQL/MariaDB InnoDB tablespace file",
    )


# ==========================================================================
# MySQL MyISAM index (.myi) and FRM table definition (.frm)
# ==========================================================================
def myisam_index_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 32)
    if len(hdr) < 8 or _u16be(hdr, 0) != 0xFEFE:
        raise ValueError("not a MyISAM index (.MYI)")
    return _profile(
        "myisam",
        "relational",
        structural=True,
        status="partial",
        store={"state_header": "MyISAM"},
        tables=[
            {
                "name": path.stem,
                "kind": "index",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": None,
            }
        ],
        notes="MySQL MyISAM index file (companion to .MYD/.frm)",
    )


def frm_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 64)
    if len(hdr) < 4 or hdr[0] != 0xFE or hdr[1] != 0x01:
        raise ValueError("not a MySQL FRM table definition")
    legacy_types = {0: "ISAM", 1: "HEAP", 6: "MyISAM", 9: "InnoDB", 12: "InnoDB"}
    db_type = hdr[3]
    store = {
        "frm_version": hdr[2],
        "legacy_db_type": legacy_types.get(db_type, db_type),
        "io_size": _u16le(hdr, 4) if len(hdr) >= 6 else None,
    }
    return _profile(
        "mysql_frm",
        "relational",
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "table",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "MySQL legacy .frm table definition — full column "
                "list needs the FRM packed-field decoder",
            }
        ],
        notes="MySQL legacy table definition (.frm)",
    )


# ==========================================================================
# Firebird / InterBase (.fdb / .gdb) — page-0 header page
# ==========================================================================
def firebird_profile(path: Path) -> Dict[str, Any]:
    page = _read_at(path, 0, 32)
    if len(page) < 24:
        raise ValueError("firebird too short")
    # header page: pag_type (byte 0) == 1 (HDR); page_size at offset 16 (u16 LE).
    if page[0] != 0x01:
        raise ValueError("not a Firebird/InterBase header page")
    page_size = _u16le(page, 16)
    ods_version = _u16le(page, 18)
    if page_size not in (1024, 2048, 4096, 8192, 16384, 32768):
        raise ValueError("implausible Firebird page size")
    size = _size(path)
    store = {
        "page_size": page_size,
        "ods_version": ods_version,
        "page_count": (size // page_size) if (page_size and size) else None,
    }
    return _profile(
        "firebird",
        "relational",
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "Firebird/InterBase store — RDB$ system tables "
                "need full page decode; header identified",
            }
        ],
        notes="Firebird / InterBase database (.fdb/.gdb)",
    )


# ==========================================================================
# SQL Server MDF/NDF (.mdf / .ndf) — 8 KiB page structure
# ==========================================================================
def mssql_mdf_profile(path: Path) -> Dict[str, Any]:
    size = _size(path)
    if not size or size < 8192:
        raise ValueError("mdf too short")
    page0 = _read_at(path, 0, 96)
    m_type = page0[0]  # page header type byte
    if size % 8192 != 0 or m_type not in range(0, 22):
        raise ValueError("not an 8 KiB SQL Server page file")
    store = {"page_size": 8192, "page_count": size // 8192, "page0_type": m_type}
    return _profile(
        "sqlserver",
        "relational",
        structural=True,
        status="partial",
        store=store,
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "SQL Server data file — schema in system base "
                "tables needs full page decode; layout identified",
            }
        ],
        notes="Microsoft SQL Server data file (MDF/NDF)",
    )


# ==========================================================================
# InfluxDB TSM (.tsm / .tsdb) — documented magic
# ==========================================================================
_TSM_MAGIC = 0x16D116D1


def tsm_profile(path: Path, ext: str) -> Dict[str, Any]:
    head = _read_at(path, 0, 8)
    if len(head) < 5 or _u32be(head, 0) != _TSM_MAGIC:
        raise ValueError("not an InfluxDB TSM file")
    return _profile(
        "influxdb",
        "time_series",
        structural=True,
        status="partial",
        store={"tsm_version": head[4]},
        tables=[
            {
                "name": path.stem,
                "kind": "stream",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "InfluxDB time-structured merge tree (series blocks)",
            }
        ],
        notes="InfluxDB TSM time-series store",
    )


# ==========================================================================
# KeePass (.kdbx / .kdb) — documented signature (crypto header only, no decrypt)
# ==========================================================================
_KDBX_SIG1 = 0x9AA2D903


def keepass_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 12)
    if len(hdr) < 8 or _u32le(hdr, 0) != _KDBX_SIG1:
        raise ValueError("not a KeePass database")
    sig2 = _u32le(hdr, 4)
    variant = {
        0xB54BFB65: "KeePass 1.x (KDB)",
        0xB54BFB66: "KeePass 2.x pre-release",
        0xB54BFB67: "KeePass 2.x (KDBX)",
    }.get(sig2, "KeePass (unknown minor)")
    ver = None
    if len(hdr) >= 12:
        ver = f"{_u16le(hdr, 10)}.{_u16le(hdr, 8)}"
    return _profile(
        "keepass",
        "password_manager",
        structural=True,
        status="partial",
        encrypted=True,
        store={
            "variant": variant,
            "format_version": ver,
            "signature2": f"0x{sig2:08X}",
        },
        notes="KeePass encrypted credential database — encrypted; only the "
        "public format header is read (no entries, no decryption)",
    )


# ==========================================================================
# Realm (.realm) — core file signature
# ==========================================================================
def realm_profile(path: Path) -> Dict[str, Any]:
    head = _read_at(path, 0, 24)
    # Realm Core writes the format info + a "T-DB" signature in the file header.
    if b"T-DB" not in head:
        raise ValueError("no Realm signature")
    off = head.find(b"T-DB")
    fmt = head[off + 4] if len(head) > off + 4 else None
    return _profile(
        "realm",
        "document",
        structural=True,
        status="partial",
        store={"realm_signature_offset": off, "file_format_version": fmt},
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "Realm object store — object schema needs the "
                "Realm core group decoder; header identified",
            }
        ],
        notes="Realm mobile object database",
    )


# ==========================================================================
# WiredTiger (.wt) — text signature
# ==========================================================================
def wiredtiger_profile(path: Path) -> Dict[str, Any]:
    head = _read_at(path, 0, 128)
    if b"WiredTiger" not in head:
        raise ValueError("no WiredTiger signature")
    return _profile(
        "wiredtiger",
        "document",
        structural=True,
        status="partial",
        store={"signature": "WiredTiger"},
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "WiredTiger storage-engine file (MongoDB/standalone)",
            }
        ],
        notes="WiredTiger key/value storage file",
    )


# ==========================================================================
# Kyoto Cabinet (.kch) — magic
# ==========================================================================
def kyotocabinet_profile(path: Path) -> Dict[str, Any]:
    head = _read_at(path, 0, 32)
    if not head.startswith(b"KC"):
        raise ValueError("not a Kyoto Cabinet database")
    return _profile(
        "kyotocabinet",
        "key_value",
        structural=True,
        status="partial",
        store={"library_revision": head[2] if len(head) > 2 else None},
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": "Kyoto Cabinet hash/tree store — opaque key/value",
            }
        ],
        notes="Kyoto Cabinet database",
    )


# ==========================================================================
# Btrieve / Pervasive (.btr) — File Control Record
# ==========================================================================
def btrieve_profile(path: Path) -> Dict[str, Any]:
    hdr = _read_at(path, 0, 16)
    if len(hdr) < 12:
        raise ValueError("btr too short")
    # Btrieve FCR: bytes 8-9 hold the file page size; version-specific magic 0x?.
    # Accept only when a plausible page size and record layout is present.
    page_size = _u16le(hdr, 8)
    if page_size not in (512, 1024, 1536, 2048, 3072, 4096, 8192, 16384):
        raise ValueError("not a Btrieve FCR page size")
    return _profile(
        "btrieve",
        "legacy_isam",
        structural=True,
        status="partial",
        store={"page_size": page_size},
        tables=[
            {
                "name": path.stem,
                "kind": "tree",
                "row_count": None,
                "estimated": False,
                "columns": [],
                "notes": None,
            }
        ],
        notes="Btrieve / Pervasive PSQL ISAM file",
    )


# ==========================================================================
# Content sniffers (magic-first) — order matters
# ==========================================================================
def _sniff(path: Path, ext: str) -> Optional[Dict[str, Any]]:
    head = _read_at(path, 0, 32)
    # 1. SQLite — many "database" exts are SQLite underneath.
    if head.startswith(_SQLITE_MAGIC):
        engine, family = _SQLITE_LABEL.get(ext, ("sqlite", "relational"))
        return sqlite_profile(path, engine=engine, family=family)
    # 2. ESE (offset-4 magic) before Jet (both Microsoft).
    if len(head) >= 8 and _u32le(head, 4) == _ESE_MAGIC:
        return ese_profile(path)
    if b"Standard Jet DB" in head or b"Standard ACE DB" in head:
        return jet_profile(path)
    if head.startswith(b"!BDN"):
        return pst_profile(path)
    if head[0:4] == b"\xcf\xad\x12\xfe":
        return dbx_profile(path)
    if head.startswith(b"REDIS"):
        return rdb_profile(path)
    if head.startswith(b"TDB file\n"):
        return tdb_profile(path)
    if len(head) >= 4 and _u32le(head, 0) == _KDBX_SIG1:
        return keepass_profile(path)
    if len(head) >= 4 and _u32be(head, 0) == _TSM_MAGIC:
        return tsm_profile(path, ext)
    if head.startswith(b"KC"):
        return kyotocabinet_profile(path)
    lo = head.lstrip()[:16]
    if lo.startswith(b"<?xml") or lo.startswith(b"<QvdTableHeader"):
        try:
            return qvd_profile(path)
        except ValueError:
            pass
    for reader in (_u32le, _u32be):  # GDBM / Berkeley DB magics
        try:
            if reader(head, 0) in _GDBM_MAGIC:
                return gdbm_profile(path)
        except (struct.error, ValueError):
            pass
    if len(head) >= 16:
        for reader in (_u32le, _u32be):
            try:
                if reader(head, 12) in _BDB_MAGIC:
                    return berkeleydb_profile(
                        path, *_BDB_LABEL.get(ext, ("berkeleydb", "key_value"))
                    )
            except (struct.error, ValueError):
                pass
    return None


# ext-hint identity for the forensic fallback and family tagging.
# (label, family) — mirrors database.json subdomains, corrected to true engine.
_EXT_IDENTITY: Dict[str, tuple] = {
    ".accdb": ("access_ace", "relational"),
    ".accde": ("access_ace", "relational"),
    ".accdt": ("access_ace", "relational"),
    ".adabas": ("adabas", "legacy_isam"),
    ".bdb": ("berkeleydb", "key_value"),
    ".bmf": ("vulcan_block_model", "geospatial"),
    ".btr": ("btrieve", "legacy_isam"),
    ".cbh": ("chessbase", "document"),
    ".cdb": ("cdb", "key_value"),
    ".cdx": ("foxpro_index", "relational"),
    ".chain": ("blockchain_store", "graph"),
    ".chroma": ("chroma", "vector"),
    ".clickhouse": ("clickhouse", "columnar"),
    ".cub": ("ssas_cube", "analytics_cube"),
    ".dbf": ("dbase", "relational"),
    ".dbm": ("dbm", "key_value"),
    ".dbt": ("dbase_memo", "relational"),
    ".dbx": ("outlook_express", "mail_store"),
    ".dm": ("datamine", "geospatial"),
    ".duckdb": ("duckdb", "columnar"),
    ".edb": ("ese", "relational"),
    ".esds": ("vsam_esds", "legacy_isam"),
    ".essbase": ("essbase", "analytics_cube"),
    ".fdb": ("firebird", "relational"),
    ".ffs_db": ("freefilesync", "key_value"),
    ".fpt": ("foxpro_memo", "relational"),
    ".frm": ("mysql_frm", "relational"),
    ".gdb": ("interbase", "relational"),
    ".gdbm": ("gdbm", "key_value"),
    ".hyper": ("tableau_hyper", "columnar"),
    ".ibd": ("innodb", "relational"),
    ".index-dat": ("ie_urlcache", "key_value"),
    ".kch": ("kyotocabinet", "key_value"),
    ".kdb": ("keepass", "password_manager"),
    ".kdbx": ("keepass", "password_manager"),
    ".ksds": ("vsam_ksds", "legacy_isam"),
    ".ldb": ("leveldb", "key_value"),
    ".leveldb": ("leveldb", "key_value"),
    ".lmdb": ("lmdb", "key_value"),
    ".localstorage": ("webkit_localstorage", "key_value"),
    ".lrcat": ("lightroom_catalog", "relational"),
    ".mb": ("paradox_memo", "relational"),
    ".mdb": ("access_jet", "relational"),
    ".mdbx": ("mdbx", "key_value"),
    ".mdf": ("sqlserver", "relational"),
    ".mny": ("ms_money", "accounting"),
    ".myd": ("myisam", "relational"),
    ".myi": ("myisam", "relational"),
    ".ndf": ("sqlserver", "relational"),
    ".ndx": ("dbase_index", "relational"),
    ".neo4j": ("neo4j", "graph"),
    ".nsf": ("lotus_notes", "document"),
    ".objectbox": ("objectbox", "document"),
    ".opvault": ("onepassword", "password_manager"),
    ".ost": ("outlook_pst", "mail_store"),
    ".otl": ("essbase_outline", "analytics_cube"),
    ".plaso": ("plaso", "forensic_timeline"),
    ".pst": ("outlook_pst", "mail_store"),
    ".px": ("paradox_index", "relational"),
    ".qba": ("quickbooks", "accounting"),
    ".qbm": ("quickbooks", "accounting"),
    ".qbw": ("quickbooks", "accounting"),
    ".qbx": ("quickbooks", "accounting"),
    ".qby": ("quickbooks", "accounting"),
    ".qdf": ("quicken", "accounting"),
    ".qvd": ("qlikview", "columnar"),
    ".rdb": ("redis", "key_value"),
    ".realm": ("realm", "document"),
    ".rpd": ("rapidfile", "legacy_isam"),
    ".rrds": ("vsam_rrds", "legacy_isam"),
    ".sage": ("sage", "accounting"),
    ".sdltm": ("trados_tm", "relational"),
    ".splay": ("kdb_plus", "columnar"),
    ".sqlitedb": ("sqlite", "relational"),
    ".sst": ("leveldb", "key_value"),
    ".tdata": ("telegram", "key_value"),
    ".tdb": ("tdb", "key_value"),
    ".tde": ("tableau_extract", "columnar"),
    ".tsdb": ("influxdb", "time_series"),
    ".tsm": ("influxdb", "time_series"),
    ".vsam": ("vsam", "legacy_isam"),
    ".wallet": ("crypto_wallet", "crypto_wallet"),
    ".wt": ("wiredtiger", "document"),
}

_SQLITE_LABEL: Dict[str, tuple] = {
    ".sqlitedb": ("sqlite", "relational"),
    ".localstorage": ("webkit_localstorage", "key_value"),
    ".lrcat": ("lightroom_catalog", "relational"),
    ".sdltm": ("trados_tm", "relational"),
    ".plaso": ("plaso", "forensic_timeline"),
    ".chroma": ("chroma", "vector"),
    ".ldb": ("chainstate", "key_value"),
}
_BDB_LABEL: Dict[str, tuple] = {
    ".bdb": ("berkeleydb", "key_value"),
    ".wallet": ("bitcoin_wallet", "crypto_wallet"),
}

# ext-hinted structural parsers (no reliable leading magic) tried before forensic.
_EXT_STRUCTURAL = {
    ".dbf": lambda p, e: dbase_profile(p),
    ".dbt": lambda p, e: dbase_memo_profile(p, e),
    ".fpt": lambda p, e: dbase_memo_profile(p, e),
    ".mb": lambda p, e: dbase_memo_profile(p, e),
    ".ndx": lambda p, e: dbase_index_profile(p, e),
    ".cdx": lambda p, e: dbase_index_profile(p, e),
    ".px": lambda p, e: dbase_index_profile(p, e),
    ".lmdb": lambda p, e: lmdb_profile(p, e),
    ".mdbx": lambda p, e: lmdb_profile(p, e),
    ".ldb": lambda p, e: leveldb_sst_profile(p),
    ".leveldb": lambda p, e: leveldb_sst_profile(p),
    ".sst": lambda p, e: leveldb_sst_profile(p),
    ".ibd": lambda p, e: innodb_profile(p),
    ".myi": lambda p, e: myisam_index_profile(p),
    ".frm": lambda p, e: frm_profile(p),
    ".fdb": lambda p, e: firebird_profile(p),
    ".gdb": lambda p, e: firebird_profile(p),
    ".mdf": lambda p, e: mssql_mdf_profile(p),
    ".ndf": lambda p, e: mssql_mdf_profile(p),
    ".mdb": lambda p, e: jet_profile(p),
    ".mny": lambda p, e: jet_profile(p),
    ".realm": lambda p, e: realm_profile(p),
    ".wt": lambda p, e: wiredtiger_profile(p),
    ".btr": lambda p, e: btrieve_profile(p),
    ".cdb": lambda p, e: cdb_profile(p),
    ".bdb": lambda p, e: berkeleydb_profile(p),
    ".wallet": lambda p, e: berkeleydb_profile(p, "bitcoin_wallet", "crypto_wallet"),
    ".dbm": lambda p, e: gdbm_profile(p),
}

# Engines that are, by construction, encrypted credential/wallet stores. The
# forensic fallback marks them encrypted and NEVER attempts decryption.
_ENCRYPTED_HINTS = {".kdb", ".kdbx", ".opvault", ".wallet", ".tdata"}

# One-line honest note for the forensic fallback, per engine family.
_FAMILY_NOTE = {
    "legacy_isam": "legacy/mainframe ISAM data set — no portable on-disk schema; "
    "byte metadata only",
    "analytics_cube": "OLAP cube/outline — proprietary multidimensional store; byte "
    "metadata only",
    "accounting": "proprietary accounting company file — often compressed/encrypted; "
    "byte metadata only",
    "crypto_wallet": "cryptocurrency wallet — encrypted key material; never decrypted, "
    "byte metadata only",
    "password_manager": "encrypted credential vault — never decrypted, byte metadata only",
    "geospatial": "proprietary geoscience/GIS store; byte metadata only",
    "graph": "graph-database store file — engine-internal layout; byte metadata only",
    "vector": "vector index/store — engine-internal layout; byte metadata only",
    "columnar": "columnar analytics extract — engine-internal layout; byte metadata only",
    "document": "document/object store — engine-internal layout; byte metadata only",
    "key_value": "key/value store — opaque keys/values; byte metadata only",
    "time_series": "time-series store — engine-internal layout; byte metadata only",
    "relational": "relational store — on-disk catalogue needs the engine's page "
    "decoder; byte metadata only",
    "forensic_timeline": "forensic timeline store; byte metadata only",
    "mail_store": "mail store — messages need the engine's container decoder; byte "
    "metadata only",
}


def known_exts() -> frozenset:
    """Every extension this module claims (the database.json universe)."""
    return frozenset(_EXT_IDENTITY)


def analyze(path: Path, ext: str) -> Dict[str, Any]:
    """Return a normalised DatabaseProfile for ``path``; never raises.

    Strategy: content magic first (SQLite/ESE/Jet/BDB/GDBM/TDB/Redis/…), then an
    extension-hinted structural parser, then an honest forensic byte profile.
    """
    path = Path(path)
    ext = ext.lower()
    engine, family = _EXT_IDENTITY.get(ext, ("unknown", "unknown"))

    # 1. content sniff (authoritative — beats a wrong/ambiguous extension)
    try:
        prof = _sniff(path, ext)
        if prof is not None:
            return prof
    except (OSError, ValueError, struct.error):
        pass

    # 2. extension-hinted structural parser
    handler = _EXT_STRUCTURAL.get(ext)
    if handler is not None:
        try:
            return handler(path, ext)
        except (OSError, ValueError, struct.error):
            pass

    # 3. honest forensic byte profile (no fabricated structure, no payload)
    note = _FAMILY_NOTE.get(family, "opaque database store; byte metadata only")
    prof = _forensic(path, engine, family, note=note)
    if ext in _ENCRYPTED_HINTS:
        prof["likely_encrypted"] = True
    return prof
