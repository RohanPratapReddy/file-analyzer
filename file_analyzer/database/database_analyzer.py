"""
DatabaseAnalyzer -- one on-disk database *store* per file.

This engine merges the two neighbouring analyzers:

  * SchemaAnalyzer  -> structural view: tables, columns, declared types, keys,
                       relations (foreign keys), indexes.
  * DataAnalyzer    -> profile view: row counts, per-column null/distinct/
                       min/max and bounded samples, plus store-level technical
                       properties -- never the raw payload.

For every database file-format extension catalogued in
``DUMP/tabgen/docs/database.json`` it runs a real, pure-stdlib parser (see
:mod:`.db_formats`): SQLite and everything SQLite-backed is fully introspected
(schema + data profile); dBASE/FoxPro/Paradox, Berkeley DB, GNU dbm, Samba TDB,
LMDB/mdbx, LevelDB/RocksDB SSTables, Redis RDB, djb cdb, QlikView QVD, Microsoft
ESE/Jet/ACE, Outlook PST/OST and DBX, InnoDB/MyISAM/FRM, Firebird/InterBase,
SQL Server MDF/NDF, InfluxDB TSM, KeePass (header only, never decrypted),
Realm, WiredTiger, Kyoto Cabinet and Btrieve get real header/structure parses.
Opaque, proprietary or encrypted stores degrade to an honest forensic byte
profile -- never a fabricated schema, never payload, never decryption.

Output tables (dicts of lists), each row keyed by a stable 1-based id whose
counters are disjoint per entity kind. Each entity row carries a LOCAL
``file_id`` (1-based index into the analyzed file list); :meth:`link_repository`
rewrites it to the repository ``file_details.file_id`` and populates
``database_file_index`` -- exactly like SchemaAnalyzer -- so the layer plugs
straight into ``RepositoryDatabaseGenerator`` beside the schema/data tables.

  database_stores_table    store_id, store_name, engine, engine_family,
                           file_format, format_class, size_bytes, page_size,
                           page_count, encoding, schema_version, app_version,
                           table_count, record_count_total, structural_parse,
                           likely_encrypted, analysis_status, notes,
                           properties(json), file_id
  database_tables_table    table_id, store_id, table_name, table_kind,
                           qualified_name, column_count, row_count, estimated,
                           notes, file_id
  database_columns_table   column_id, table_id, store_id, column_name, ordinal,
                           declared_type, inferred_type, is_nullable,
                           is_primary_key, is_unique, default_value,
                           references_table, references_column, null_count,
                           non_null_count, distinct_count, min_value, max_value,
                           sample_values(json), extra(json), file_id
  database_indexes_table   index_id, store_id, table_id, table_name, index_name,
                           is_unique, method, column_names(json), file_id
  database_relations_table relation_id, store_id, relation_type, from_table,
                           from_column, to_table, to_column, value, method,
                           extra(json), file_id
  database_properties_table property_id, store_id, property_name,
                           property_value, value_type, group_name, file_id
  database_file_index      dbfi_id, file_id, entity_kind, entity_id
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from . import db_formats


class DatabaseAnalyzer:
    """Analyze on-disk database store files into normalized ``database_*`` tables."""

    # entity-kind labels used in database_file_index
    KIND_STORE = "store"
    KIND_TABLE = "table"
    KIND_COLUMN = "column"
    KIND_INDEX = "index"
    KIND_RELATION = "relation"
    KIND_PROPERTY = "property"

    def __init__(
        self,
        file_paths: List[Union[str, Path]],
        dump_file_path: str = "database_analysis.json",
        dump_file_type: str = "memory",
    ):
        self.file_paths = [Path(p) for p in file_paths]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()

        self.database_stores_table: List[Dict[str, Any]] = []
        self.database_tables_table: List[Dict[str, Any]] = []
        self.database_columns_table: List[Dict[str, Any]] = []
        self.database_indexes_table: List[Dict[str, Any]] = []
        self.database_relations_table: List[Dict[str, Any]] = []
        self.database_properties_table: List[Dict[str, Any]] = []
        self.database_file_index: List[Dict[str, Any]] = []

        self._ids = {
            k: 0
            for k in (
                "store",
                "table",
                "column",
                "index",
                "relation",
                "property",
                "dbfi",
            )
        }

    # ------------------------------------------------------------------
    # id helpers
    # ------------------------------------------------------------------
    def _next(self, kind: str) -> int:
        self._ids[kind] += 1
        return self._ids[kind]

    @classmethod
    def _known_exts(cls) -> frozenset:
        return db_formats.known_exts()

    @staticmethod
    def _true_ext(path: Path) -> str:
        """Last-component suffix, lower-cased (mirrors the router's convention)."""
        name = path.name.lower()
        dot = name.rfind(".")
        return name[dot:] if dot > 0 else ""

    # ==================================================================
    # Public API
    # ==================================================================
    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        exts = self._known_exts()
        for local_fid, path in enumerate(self.file_paths, start=1):
            ext = self._true_ext(path)
            if ext not in exts:
                continue
            try:
                profile = db_formats.analyze(path, ext)
            except Exception as err:  # never let one bad file abort the batch
                print(f"Warning: DatabaseAnalyzer failed on {path.name}: {err}")
                continue
            try:
                self._emit_store(path, ext, profile, local_fid)
            except Exception as err:
                print(f"Warning: DatabaseAnalyzer emit failed on {path.name}: {err}")
                continue

        result = self.get_tables()
        if self.dump_file_type != "memory":
            self._export(result)
        return result

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "database_stores_table": self.database_stores_table,
            "database_tables_table": self.database_tables_table,
            "database_columns_table": self.database_columns_table,
            "database_indexes_table": self.database_indexes_table,
            "database_relations_table": self.database_relations_table,
            "database_properties_table": self.database_properties_table,
            "database_file_index": self.database_file_index,
        }

    # ==================================================================
    # Row builders (merge schema structure + data profile)
    # ==================================================================
    def _emit_store(
        self, path: Path, ext: str, profile: Dict[str, Any], local_fid: int
    ) -> None:
        store_meta = profile.get("store") or {}
        tables = profile.get("tables") or []
        store_id = self._next("store")

        total_records = 0
        have_count = False
        for t in tables:
            rc = t.get("row_count")
            if isinstance(rc, int):
                total_records += rc
                have_count = True

        store_row = {
            "store_id": store_id,
            "store_name": path.stem,
            "engine": profile.get("engine") or "unknown",
            "engine_family": profile.get("engine_family") or "unknown",
            "file_format": ext.lstrip("."),
            "format_class": "binary",
            "size_bytes": self._as_int(
                store_meta.get("byte_size")
                or (profile.get("properties") or {}).get("byte_size")
                or self._file_size(path)
            ),
            "page_size": self._as_int(
                store_meta.get("page_size") or store_meta.get("page_size_guess")
            ),
            "page_count": self._as_int(store_meta.get("page_count")),
            "encoding": self._as_text(
                store_meta.get("text_encoding") or store_meta.get("encoding")
            ),
            "schema_version": self._as_text(
                store_meta.get("ods_version")
                or store_meta.get("format_version")
                or store_meta.get("ese_format_version")
                or store_meta.get("jet_version")
                or store_meta.get("dbase_version")
                or store_meta.get("user_version")
            ),
            "app_version": self._as_text(
                store_meta.get("app_version")
                or store_meta.get("qv_build_no")
                or store_meta.get("rdb_version")
                or store_meta.get("bdb_version")
            ),
            "table_count": len(tables),
            "record_count_total": total_records if have_count else None,
            "structural_parse": 1 if profile.get("structural_parse") else 0,
            "likely_encrypted": 1 if profile.get("likely_encrypted") else 0,
            "analysis_status": profile.get("status") or "ok",
            "notes": self._as_text(profile.get("notes")),
            "properties": self._json(profile.get("properties") or {}),
            "file_id": local_fid,
        }
        self.database_stores_table.append(store_row)

        # table_name -> table_id (for indexes/relations back-references)
        name_to_tid: Dict[str, int] = {}
        for t in tables:
            self._emit_table(store_id, t, local_fid, name_to_tid)

        for idx in profile.get("indexes") or []:
            self._emit_index(store_id, idx, local_fid, name_to_tid)

        for rel in profile.get("relations") or []:
            self._emit_relation(store_id, rel, local_fid)

        # store-level technical metadata -> properties (flattened, no payload)
        self._emit_properties(store_id, store_meta, "store", local_fid)
        self._emit_properties(
            store_id, profile.get("properties") or {}, "forensic", local_fid
        )

    def _emit_table(
        self,
        store_id: int,
        t: Dict[str, Any],
        local_fid: int,
        name_to_tid: Dict[str, int],
    ) -> None:
        table_id = self._next("table")
        tname = self._as_text(t.get("name")) or f"table_{table_id}"
        cols = t.get("columns") or []
        self.database_tables_table.append(
            {
                "table_id": table_id,
                "store_id": store_id,
                "table_name": tname,
                "table_kind": self._as_text(t.get("kind")) or "table",
                "qualified_name": self._as_text(t.get("qualified_name")) or tname,
                "column_count": len(cols),
                "row_count": self._as_int(t.get("row_count")),
                "estimated": 1 if t.get("estimated") else 0,
                "notes": self._as_text(t.get("notes")),
                "file_id": local_fid,
            }
        )
        name_to_tid.setdefault(tname, table_id)
        for ordinal, c in enumerate(cols, start=1):
            self._emit_column(store_id, table_id, c, ordinal, local_fid)

    def _emit_column(
        self,
        store_id: int,
        table_id: int,
        c: Dict[str, Any],
        ordinal: int,
        local_fid: int,
    ) -> None:
        column_id = self._next("column")
        self.database_columns_table.append(
            {
                "column_id": column_id,
                "table_id": table_id,
                "store_id": store_id,
                "column_name": self._as_text(c.get("name")) or f"col_{column_id}",
                "ordinal": ordinal,
                "declared_type": self._as_text(c.get("declared_type")),
                "inferred_type": self._as_text(c.get("inferred_type")),
                "is_nullable": self._as_bool_int(c.get("nullable")),
                "is_primary_key": 1 if c.get("primary_key") else 0,
                "is_unique": 1 if c.get("unique") else 0,
                "default_value": self._as_text(c.get("default")),
                "references_table": self._as_text(c.get("references_table")),
                "references_column": self._as_text(c.get("references_column")),
                "null_count": self._as_int(c.get("null_count")),
                "non_null_count": self._as_int(c.get("non_null_count")),
                "distinct_count": self._as_int(c.get("distinct_count")),
                "min_value": self._as_text(c.get("minimum")),
                "max_value": self._as_text(c.get("maximum")),
                "sample_values": self._json(c.get("samples") or []),
                "extra": self._json(c.get("extra") or {}),
                "file_id": local_fid,
            }
        )

    def _emit_index(
        self,
        store_id: int,
        idx: Dict[str, Any],
        local_fid: int,
        name_to_tid: Dict[str, int],
    ) -> None:
        index_id = self._next("index")
        tname = self._as_text(idx.get("table"))
        self.database_indexes_table.append(
            {
                "index_id": index_id,
                "store_id": store_id,
                "table_id": name_to_tid.get(tname) if tname else None,
                "table_name": tname,
                "index_name": self._as_text(idx.get("name")) or f"index_{index_id}",
                "is_unique": self._as_bool_int(idx.get("unique")),
                "method": self._as_text(idx.get("method")),
                "column_names": self._json(idx.get("columns") or []),
                "file_id": local_fid,
            }
        )

    def _emit_relation(
        self, store_id: int, rel: Dict[str, Any], local_fid: int
    ) -> None:
        relation_id = self._next("relation")
        self.database_relations_table.append(
            {
                "relation_id": relation_id,
                "store_id": store_id,
                "relation_type": self._as_text(rel.get("type")) or "relation",
                "from_table": self._as_text(rel.get("from_table")),
                "from_column": self._as_text(rel.get("from_column")),
                "to_table": self._as_text(rel.get("to_table")),
                "to_column": self._as_text(rel.get("to_column")),
                "value": self._as_text(rel.get("value")),
                "method": self._as_text(rel.get("method")),
                "extra": self._json(rel.get("extra") or {}),
                "file_id": local_fid,
            }
        )

    def _emit_properties(
        self, store_id: int, props: Dict[str, Any], group_name: str, local_fid: int
    ) -> None:
        if not isinstance(props, dict):
            return
        for name, value in props.items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                pv = self._json(value)
                vtype = "json"
            elif isinstance(value, bool):
                pv = "true" if value else "false"
                vtype = "bool"
            elif isinstance(value, int):
                pv = str(value)
                vtype = "int"
            elif isinstance(value, float):
                pv = repr(value)
                vtype = "float"
            else:
                pv = str(value)
                vtype = "str"
            self.database_properties_table.append(
                {
                    "property_id": self._next("property"),
                    "store_id": store_id,
                    "property_name": str(name)[:256],
                    "property_value": pv[:2048],
                    "value_type": vtype,
                    "group_name": group_name,
                    "file_id": local_fid,
                }
            )

    # ------------------------------------------------------------------
    # coercion helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _as_int(v: Any) -> Optional[int]:
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, int):
            return v
        if isinstance(v, float) and v.is_integer():
            return int(v)
        return None

    @staticmethod
    def _as_bool_int(v: Any) -> Optional[int]:
        if v is None:
            return None
        return 1 if v else 0

    @staticmethod
    def _as_text(v: Any) -> Optional[str]:
        if v is None:
            return None
        if isinstance(v, str):
            return v[:2048]
        if isinstance(v, (int, float, bool)):
            return str(v)
        return str(v)[:2048]

    @staticmethod
    def _json(v: Any) -> Optional[str]:
        try:
            if v in (None, {}, []):
                return None
        except TypeError:
            pass
        try:
            return json.dumps(v, ensure_ascii=False, default=str)[:8192]
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _file_size(path: Path) -> Optional[int]:
        try:
            return path.stat().st_size
        except OSError:
            return None

    # ==================================================================
    # Repository linkage (mirrors SchemaAnalyzer.link_repository)
    # ==================================================================
    def link_repository(
        self,
        repository_tables: Tuple[
            List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]
        ],
        analyzed_file_paths: Optional[List[Union[str, Path]]] = None,
    ) -> List[Dict[str, Any]]:
        folders, extensions, files = repository_tables
        ext_by_id = {e["extension_id"]: e["extension_name"] for e in extensions}
        folder_by_id = {f["folder_id"]: f["folder_name"] for f in folders}

        repo_by_relpath: Dict[str, int] = {}
        repo_by_basename: Dict[str, List[int]] = {}
        for f in files:
            ext = ext_by_id.get(f.get("file_extension_id"))
            ext = None if ext in (None, "None", "") else ext
            location = f.get("location") or []
            deepest = location[-1] if location else 1
            folder_path = folder_by_id.get(deepest, ".")
            fname = f["file_name"] + (f".{ext}" if ext else "")
            relpath = (
                fname if folder_path in (".", "", None) else f"{folder_path}/{fname}"
            )
            repo_by_relpath.setdefault(relpath, f["file_id"])
            repo_by_basename.setdefault(Path(relpath).name, []).append(f["file_id"])

        analyzed = [Path(p) for p in (analyzed_file_paths or self.file_paths)]
        local_to_repo: Dict[int, Optional[int]] = {}
        for idx, p in enumerate(analyzed, start=1):
            posix = p.as_posix()
            matched = None
            best_len = -1
            for rel, fid in repo_by_relpath.items():
                if posix == rel or posix.endswith("/" + rel):
                    if len(rel) > best_len:
                        best_len = len(rel)
                        matched = fid
            if matched is None:
                cands = repo_by_basename.get(p.name, [])
                if len(cands) == 1:
                    matched = cands[0]
            local_to_repo[idx] = matched

        entity_tables = [
            (self.KIND_STORE, self.database_stores_table, "store_id"),
            (self.KIND_TABLE, self.database_tables_table, "table_id"),
            (self.KIND_COLUMN, self.database_columns_table, "column_id"),
            (self.KIND_INDEX, self.database_indexes_table, "index_id"),
            (self.KIND_RELATION, self.database_relations_table, "relation_id"),
            (self.KIND_PROPERTY, self.database_properties_table, "property_id"),
        ]
        self.database_file_index.clear()
        for kind, rows, id_key in entity_tables:
            for row in rows:
                repo_id = local_to_repo.get(row.get("file_id"))
                row["file_id"] = repo_id
                if repo_id is not None:
                    self.database_file_index.append(
                        {
                            "dbfi_id": self._next("dbfi"),
                            "file_id": repo_id,
                            "entity_kind": kind,
                            "entity_id": row[id_key],
                        }
                    )
        return self.database_file_index

    # ==================================================================
    # export
    # ==================================================================
    def _export(self, result: Dict[str, List[Dict[str, Any]]]) -> None:
        try:
            with open(self.dump_file_path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2, default=str)
        except OSError as err:
            print(f"Warning: DatabaseAnalyzer export failed: {err}")
