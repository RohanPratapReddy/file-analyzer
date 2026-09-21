"""
DocumentAnalyzer -- the parent/super-class of the ``document`` analysis plane.

Every extension of the eight residual *document* content kinds (manifest, query,
makefile, certificate_text, notebook, document, license, diff) is dispatched to
its own child parser class (see :mod:`.parsers`), each stitched to its own
extension set, and the resulting real, structure-aware profile is flattened into
a fully-normalized set of ``document_*`` tables:

    document -> sections -> records -> fields  (+ file-level properties)

  * one **section** row per top-level grouping (an AppCache CACHE/NETWORK block,
    a SQL statement list, a Makefile's variables/rules/directives, a PEM block
    set, a notebook's cells, a diff's per-file hunks, a DEP-5 paragraph set, ...),
  * one **record** row per entry inside a section (a manifest entry, a query
    statement, a make rule, an SSH key, a notebook cell, a diff hunk, a
    copyright line, ...),
  * one **field** row per typed name/value pair on a record.

Honesty contract (identical to the text / config / database planes): content is
sniffed first, an inherently-binary payload degrades to an honest forensic byte
profile with no fabricated records, key / credential material is never decoded
into its secret content (only public structural facts), the raw payload is never
stored, and a partial parse is reported ``partial`` -- never stubbed.

Each entity row carries a LOCAL ``file_id`` (1-based index into the analyzed
file list); :meth:`link_repository` rewrites it to the repository
``file_details.file_id`` and populates ``document_file_index`` -- exactly like
the schema/database/data/config/text/markup layers -- so the plane plugs
straight into ``RepositoryDatabaseGenerator``.

  document_files_table      document_file_id, file_name, extension, content_kind,
                            syntax_family, parse_engine, format_label,
                            detected_via, format_class, size_bytes, encoding,
                            line_count, section_count, record_count, field_count,
                            property_count, analysis_status, notes, file_id
  document_sections_table   document_section_id, document_file_id, section_name,
                            section_path, section_type, ordinal, record_count,
                            notes, file_id
  document_records_table    document_record_id, document_file_id,
                            document_section_id, record_index, record_type,
                            record_label, start_line, end_line, field_count,
                            text_preview, notes, file_id
  document_fields_table     document_field_id, document_record_id,
                            document_file_id, document_section_id, field_name,
                            field_key, field_type, field_value, ordinal, file_id
  document_properties_table property_id, document_file_id, property_name,
                            property_value, value_type, group_name, file_id
  document_file_index       dfi_id, file_id, entity_kind, entity_id
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from . import document_formats


class DocumentAnalyzer:
    """Analyze document-kind files into normalized ``document_*`` tables."""

    KIND_FILE = "file"
    KIND_SECTION = "section"
    KIND_RECORD = "record"
    KIND_FIELD = "field"
    KIND_PROPERTY = "property"

    def __init__(
        self,
        file_paths: List[Union[str, Path]],
        dump_file_path: str = "document_analysis.json",
        dump_file_type: str = "memory",
    ):
        self.file_paths = [Path(p) for p in file_paths]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()

        self.document_files_table: List[Dict[str, Any]] = []
        self.document_sections_table: List[Dict[str, Any]] = []
        self.document_records_table: List[Dict[str, Any]] = []
        self.document_fields_table: List[Dict[str, Any]] = []
        self.document_properties_table: List[Dict[str, Any]] = []
        self.document_file_index: List[Dict[str, Any]] = []

        self._ids = {
            k: 0
            for k in (
                "file",
                "section",
                "record",
                "field",
                "property",
                "dfi",
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
        return document_formats.known_exts()

    @classmethod
    def routing_suffixes(cls) -> Tuple[str, ...]:
        return document_formats.routing_suffixes()

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
                profile = document_formats.analyze(path, ext)
            except Exception as err:  # never let one bad file abort the batch
                print(f"Warning: DocumentAnalyzer failed on {path.name}: {err}")
                continue
            try:
                self._emit_file(path, ext, profile, local_fid)
            except Exception as err:
                print(f"Warning: DocumentAnalyzer emit failed on {path.name}: {err}")
                continue

        result = self.get_tables()
        if self.dump_file_type != "memory":
            self._export(result)
        return result

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "document_files_table": self.document_files_table,
            "document_sections_table": self.document_sections_table,
            "document_records_table": self.document_records_table,
            "document_fields_table": self.document_fields_table,
            "document_properties_table": self.document_properties_table,
            "document_file_index": self.document_file_index,
        }

    # ==================================================================
    # Row builders
    # ==================================================================
    def _emit_file(
        self, path: Path, ext: str, profile: Dict[str, Any], local_fid: int
    ) -> None:
        document_file_id = self._next("file")
        status = self._as_text(profile.get("status")) or "ok"

        file_row = {
            "document_file_id": document_file_id,
            "file_name": path.name,
            "extension": ext.lstrip("."),
            "content_kind": self._as_text(profile.get("kind")),
            "syntax_family": self._as_text(profile.get("family")),
            "parse_engine": self._as_text(profile.get("engine")),
            "format_label": self._as_text(profile.get("format")),
            "detected_via": self._as_text(profile.get("detected_via")),
            "format_class": "binary" if status == "forensic" else "text",
            "size_bytes": self._as_int(profile.get("byte_size")),
            "encoding": self._as_text(profile.get("encoding")),
            "line_count": self._as_int(profile.get("line_count")),
            "section_count": 0,
            "record_count": 0,
            "field_count": 0,
            "property_count": 0,
            "analysis_status": status,
            "notes": self._as_text(profile.get("notes")),
            "file_id": local_fid,
        }
        self.document_files_table.append(file_row)

        # file-level metadata / forensic profile -> properties
        prop_count = 0
        for entry in profile.get("properties") or []:
            if self._emit_property(document_file_id, entry, local_fid):
                prop_count += 1

        sec_count = rec_count = fld_count = 0
        for sec in profile.get("sections") or []:
            section_id = self._emit_section(document_file_id, sec, local_fid)
            sec_count += 1
            local_recs = 0
            for rindex, rec in enumerate(sec.get("records") or []):
                rec_count += 1
                local_recs += 1
                fld_count += self._emit_record(
                    document_file_id, section_id, rindex, rec, local_fid
                )
            self.document_sections_table[-1]["record_count"] = local_recs

        file_row["section_count"] = sec_count
        file_row["record_count"] = rec_count
        file_row["field_count"] = fld_count
        file_row["property_count"] = prop_count

    def _emit_section(self, dfid: int, sec: Dict[str, Any], local_fid: int) -> int:
        section_id = self._next("section")
        self.document_sections_table.append(
            {
                "document_section_id": section_id,
                "document_file_id": dfid,
                "section_name": self._as_text(sec.get("name")),
                "section_path": self._as_text(sec.get("path")),
                "section_type": self._as_text(sec.get("type")),
                "ordinal": self._as_int(sec.get("ordinal")),
                "record_count": 0,
                "notes": self._as_text(sec.get("notes")),
                "file_id": local_fid,
            }
        )
        return section_id

    def _emit_record(
        self,
        dfid: int,
        section_id: int,
        rindex: int,
        rec: Dict[str, Any],
        local_fid: int,
    ) -> int:
        record_id = self._next("record")
        fields = rec.get("fields") or []
        self.document_records_table.append(
            {
                "document_record_id": record_id,
                "document_file_id": dfid,
                "document_section_id": section_id,
                "record_index": rindex,
                "record_type": self._as_text(rec.get("rtype")),
                "record_label": self._as_text(rec.get("label")),
                "start_line": self._as_int(rec.get("start_line")),
                "end_line": self._as_int(rec.get("end_line")),
                "field_count": len(fields),
                "text_preview": self._as_text(rec.get("text")),
                "notes": self._as_text(rec.get("notes")),
                "file_id": local_fid,
            }
        )
        n = 0
        for fld in fields:
            if self._emit_field(dfid, section_id, record_id, fld, local_fid):
                n += 1
        return n

    def _emit_field(
        self,
        dfid: int,
        section_id: int,
        record_id: int,
        fld: Dict[str, Any],
        local_fid: int,
    ) -> bool:
        if not isinstance(fld, dict):
            return False
        self.document_fields_table.append(
            {
                "document_field_id": self._next("field"),
                "document_record_id": record_id,
                "document_file_id": dfid,
                "document_section_id": section_id,
                "field_name": self._as_text(fld.get("name")),
                "field_key": self._as_text(fld.get("key")),
                "field_type": self._as_text(fld.get("type")) or "STRING",
                "field_value": self._as_text(fld.get("value")),
                "ordinal": self._as_int(fld.get("ordinal")),
                "file_id": local_fid,
            }
        )
        return True

    def _emit_property(self, dfid: int, entry: Any, local_fid: int) -> bool:
        if not (isinstance(entry, (list, tuple)) and len(entry) == 3):
            return False
        group_name, name, value = entry
        if value is None:
            return False
        if isinstance(value, (dict, list)):
            pv, vtype = self._json(value), "json"
        elif isinstance(value, bool):
            pv, vtype = ("true" if value else "false"), "bool"
        elif isinstance(value, int):
            pv, vtype = str(value), "int"
        elif isinstance(value, float):
            pv, vtype = repr(value), "float"
        else:
            pv, vtype = str(value), "str"
        if pv is None:
            return False
        self.document_properties_table.append(
            {
                "property_id": self._next("property"),
                "document_file_id": dfid,
                "property_name": str(name)[:256],
                "property_value": pv[:2048],
                "value_type": vtype,
                "group_name": str(group_name)[:128],
                "file_id": local_fid,
            }
        )
        return True

    # ------------------------------------------------------------------
    # coercion helpers (mirror TextualAnalyzer)
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
    def _as_text(v: Any) -> Optional[str]:
        if v is None:
            return None
        if isinstance(v, str):
            return v.replace("\x00", "")[:2048]
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

    # ==================================================================
    # Repository linkage (mirrors TextualAnalyzer.link_repository)
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
            (self.KIND_FILE, self.document_files_table, "document_file_id"),
            (self.KIND_SECTION, self.document_sections_table, "document_section_id"),
            (self.KIND_RECORD, self.document_records_table, "document_record_id"),
            (self.KIND_FIELD, self.document_fields_table, "document_field_id"),
            (self.KIND_PROPERTY, self.document_properties_table, "property_id"),
        ]
        self.document_file_index.clear()
        for kind, rows, id_key in entity_tables:
            for row in rows:
                repo_id = local_to_repo.get(row.get("file_id"))
                row["file_id"] = repo_id
                if repo_id is not None:
                    self.document_file_index.append(
                        {
                            "dfi_id": self._next("dfi"),
                            "file_id": repo_id,
                            "entity_kind": kind,
                            "entity_id": row[id_key],
                        }
                    )
        return self.document_file_index

    # ==================================================================
    # export
    # ==================================================================
    def _export(self, result: Dict[str, List[Dict[str, Any]]]) -> None:
        try:
            with open(self.dump_file_path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2, default=str)
        except OSError as err:
            print(f"Warning: DocumentAnalyzer export failed: {err}")
