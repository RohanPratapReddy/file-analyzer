"""
MarkupAnalyzer -- one markup *file* decomposed into normalized, relational
tables describing the tags/elements/sections present in the file and the
metrics of the content carried within them.

For every extension of the residual *markup* content kind still listed in
``DUMP/tabgen/docs/residual.json`` (HTML/XHTML vocabularies, the ~200 XML
application dialects, OFX SGML, wiki/gemtext/roff/typst/MIF/markdown/lightweight
markups) this engine runs a real, pure-stdlib, structure-aware parser (see
:mod:`.markup_formats`) that decomposes the document into:

    document -> elements (+ attributes + namespaces) -> sections + properties

and flattens it into a fully-normalized set of tables:

  * one **element** row per distinct tag/element name, with the metrics of the
    content *within* that tag: how often it occurs, its min/max nesting depth,
    its child fan-out, how many instances are leaves vs. carry text, the total
    text length, the attribute names it carries, and a sample of its text,
  * one **attribute** row per distinct (element, attribute) pair, with
    occurrence count, distinct-value count, inferred value type, and a sample,
  * one **namespace** row per XML namespace declaration,
  * one **section** row per structural section (the direct children of the XML
    root, or the headings of a non-XML markup) with an outline path,
  * one **property** row per document-level fact (XML declaration, DOCTYPE,
    root element, per-family metadata, honest forensic facts).

Honesty contract (identical to the config / text planes): content is sniffed
first; a gzip-wrapped markup is transparently decompressed; a ZIP-packaged
vocabulary degrades to an honest forensic note (members not extracted here); an
inherently-binary payload degrades to a forensic byte profile with no fabricated
tags; the raw payload is never stored (only names, counts, metrics, short
samples); a partial parse is reported ``partial`` -- never stubbed.

Output tables (dicts of lists), each row keyed by a stable 1-based id whose
counters are disjoint per entity kind. Each entity row carries a LOCAL
``file_id`` (1-based index into the analyzed file list); :meth:`link_repository`
rewrites it to the repository ``file_details.file_id`` and populates
``markup_file_index`` -- exactly like the schema/database/data/config/text
layers -- so the plane plugs straight into ``RepositoryDatabaseGenerator``.

  markup_files_table      markup_file_id, file_name, extension, content_kind,
                          syntax_family, markup_language, dialect_profile,
                          parse_engine, format_label, detected_via, format_class,
                          size_bytes, encoding, line_count, well_formed,
                          root_element, namespace_count, element_count,
                          distinct_element_count, attribute_count,
                          distinct_attribute_count, max_depth, comment_count,
                          pi_count, cdata_count, text_length, section_count,
                          property_count, analysis_status, notes, file_id
  markup_elements_table   markup_element_id, markup_file_id, tag_name,
                          qualified_name, namespace_prefix, namespace_uri,
                          occurrence_count, min_depth, max_depth,
                          total_child_count, max_children, leaf_count,
                          text_bearing_count, total_text_length,
                          distinct_attribute_count, attribute_names, sample_text,
                          is_root, ordinal, file_id
  markup_attributes_table markup_attribute_id, markup_file_id,
                          markup_element_id, element_tag, attribute_name,
                          namespace_prefix, occurrence_count,
                          distinct_value_count, value_type, sample_value,
                          min_length, max_length, file_id
  markup_namespaces_table markup_namespace_id, markup_file_id, prefix, uri,
                          is_default, element_usage_count, file_id
  markup_sections_table   markup_section_id, markup_file_id, section_name,
                          section_type, section_path, depth, ordinal,
                          element_tag, child_count, text_length, title, file_id
  markup_properties_table property_id, markup_file_id, property_name,
                          property_value, value_type, group_name, file_id
  markup_file_index       mfi_id, file_id, entity_kind, entity_id
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from . import markup_formats


class MarkupAnalyzer:
    """Analyze markup files into normalized ``markup_*`` tables."""

    KIND_FILE = "file"
    KIND_ELEMENT = "element"
    KIND_ATTRIBUTE = "attribute"
    KIND_NAMESPACE = "namespace"
    KIND_SECTION = "section"
    KIND_PROPERTY = "property"

    def __init__(
        self,
        file_paths: List[Union[str, Path]],
        dump_file_path: str = "markup_analysis.json",
        dump_file_type: str = "memory",
    ):
        self.file_paths = [Path(p) for p in file_paths]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()

        self.markup_files_table: List[Dict[str, Any]] = []
        self.markup_elements_table: List[Dict[str, Any]] = []
        self.markup_attributes_table: List[Dict[str, Any]] = []
        self.markup_namespaces_table: List[Dict[str, Any]] = []
        self.markup_sections_table: List[Dict[str, Any]] = []
        self.markup_properties_table: List[Dict[str, Any]] = []
        self.markup_file_index: List[Dict[str, Any]] = []

        self._ids = {
            k: 0
            for k in (
                "file",
                "element",
                "attribute",
                "namespace",
                "section",
                "property",
                "mfi",
            )
        }
        # per-file map: element qualified-name -> markup_element_id (so the
        # attribute rows can point at the element row they belong to).
        self._elem_id_by_qname: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # id helpers
    # ------------------------------------------------------------------
    def _next(self, kind: str) -> int:
        self._ids[kind] += 1
        return self._ids[kind]

    @classmethod
    def _known_exts(cls) -> frozenset:
        return markup_formats.known_exts()

    @classmethod
    def routing_suffixes(cls) -> Tuple[str, ...]:
        return markup_formats.routing_suffixes()

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
                profile = markup_formats.analyze(path, ext)
            except Exception as err:  # never let one bad file abort the batch
                print(f"Warning: MarkupAnalyzer failed on {path.name}: {err}")
                continue
            try:
                self._emit_file(path, ext, profile, local_fid)
            except Exception as err:
                print(f"Warning: MarkupAnalyzer emit failed on {path.name}: {err}")
                continue

        result = self.get_tables()
        if self.dump_file_type != "memory":
            self._export(result)
        return result

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "markup_files_table": self.markup_files_table,
            "markup_elements_table": self.markup_elements_table,
            "markup_attributes_table": self.markup_attributes_table,
            "markup_namespaces_table": self.markup_namespaces_table,
            "markup_sections_table": self.markup_sections_table,
            "markup_properties_table": self.markup_properties_table,
            "markup_file_index": self.markup_file_index,
        }

    # ==================================================================
    # Row builders
    # ==================================================================
    def _emit_file(
        self, path: Path, ext: str, profile: Dict[str, Any], local_fid: int
    ) -> None:
        self._elem_id_by_qname = {}
        markup_file_id = self._next("file")
        status = self._as_text(profile.get("status")) or "ok"
        metrics = profile.get("metrics") or {}

        file_row = {
            "markup_file_id": markup_file_id,
            "file_name": path.name,
            "extension": ext.lstrip("."),
            "content_kind": self._as_text(profile.get("kind")),
            "syntax_family": self._as_text(profile.get("family")),
            "markup_language": self._as_text(profile.get("markup_language")),
            "dialect_profile": self._as_text(profile.get("dialect")),
            "parse_engine": self._as_text(profile.get("engine")),
            "format_label": self._as_text(profile.get("format")),
            "detected_via": self._as_text(profile.get("detected_via")),
            "format_class": "binary" if status == "forensic" else "text",
            "size_bytes": self._as_int(profile.get("byte_size")),
            "encoding": self._as_text(profile.get("encoding")),
            "line_count": self._as_int(profile.get("line_count")),
            "well_formed": self._as_bool(profile.get("well_formed")),
            "root_element": self._as_text(profile.get("root_element")),
            "namespace_count": self._as_int(metrics.get("namespace_count")) or 0,
            "element_count": self._as_int(metrics.get("element_count")) or 0,
            "distinct_element_count": self._as_int(
                metrics.get("distinct_element_count")
            )
            or 0,
            "attribute_count": self._as_int(metrics.get("attribute_count")) or 0,
            "distinct_attribute_count": self._as_int(
                metrics.get("distinct_attribute_count")
            )
            or 0,
            "max_depth": self._as_int(metrics.get("max_depth")) or 0,
            "comment_count": self._as_int(metrics.get("comment_count")) or 0,
            "pi_count": self._as_int(metrics.get("pi_count")) or 0,
            "cdata_count": self._as_int(metrics.get("cdata_count")) or 0,
            "text_length": self._as_int(metrics.get("text_length")) or 0,
            "section_count": 0,
            "property_count": 0,
            "analysis_status": status,
            "notes": self._as_text(profile.get("notes")),
            "file_id": local_fid,
        }
        self.markup_files_table.append(file_row)

        for el in profile.get("elements") or []:
            self._emit_element(markup_file_id, el, local_fid)

        attr_count = 0
        for at in profile.get("attributes") or []:
            if self._emit_attribute(markup_file_id, at, local_fid):
                attr_count += 1

        ns_count = 0
        for ns in profile.get("namespaces") or []:
            self._emit_namespace(markup_file_id, ns, local_fid)
            ns_count += 1

        sec_count = 0
        for sec in profile.get("sections") or []:
            self._emit_section(markup_file_id, sec, local_fid)
            sec_count += 1

        prop_count = 0
        for entry in profile.get("properties") or []:
            if self._emit_property(markup_file_id, entry, local_fid):
                prop_count += 1

        file_row["section_count"] = sec_count
        file_row["property_count"] = prop_count
        # keep the counts self-consistent with the child rows actually emitted
        file_row["distinct_attribute_count"] = (
            attr_count or file_row["distinct_attribute_count"]
        )
        file_row["namespace_count"] = ns_count or file_row["namespace_count"]

    def _emit_element(self, mfid: int, el: Dict[str, Any], local_fid: int) -> int:
        element_id = self._next("element")
        qname = self._as_text(el.get("qname")) or self._as_text(el.get("tag"))
        attr_names = el.get("attr_names") or []
        self.markup_elements_table.append(
            {
                "markup_element_id": element_id,
                "markup_file_id": mfid,
                "tag_name": self._as_text(el.get("tag")),
                "qualified_name": qname,
                "namespace_prefix": self._as_text(el.get("ns_prefix")),
                "namespace_uri": self._as_text(el.get("ns_uri")),
                "occurrence_count": self._as_int(el.get("count")) or 0,
                "min_depth": self._as_int(el.get("min_depth")) or 0,
                "max_depth": self._as_int(el.get("max_depth")) or 0,
                "total_child_count": self._as_int(el.get("total_children")) or 0,
                "max_children": self._as_int(el.get("max_children")) or 0,
                "leaf_count": self._as_int(el.get("leaf_count")) or 0,
                "text_bearing_count": self._as_int(el.get("text_count")) or 0,
                "total_text_length": self._as_int(el.get("total_text_len")) or 0,
                "distinct_attribute_count": len(attr_names),
                "attribute_names": ", ".join(str(a) for a in attr_names)[:2048] or None,
                "sample_text": self._as_text(el.get("sample_text")),
                "is_root": self._as_bool(el.get("is_root")),
                "ordinal": self._as_int(el.get("ordinal")),
                "file_id": local_fid,
            }
        )
        if qname is not None and qname not in self._elem_id_by_qname:
            self._elem_id_by_qname[qname] = element_id
        return element_id

    def _emit_attribute(self, mfid: int, at: Dict[str, Any], local_fid: int) -> bool:
        elem_qname = self._as_text(at.get("element_qname")) or self._as_text(
            at.get("element_tag")
        )
        element_id = self._elem_id_by_qname.get(elem_qname)
        self.markup_attributes_table.append(
            {
                "markup_attribute_id": self._next("attribute"),
                "markup_file_id": mfid,
                "markup_element_id": element_id,
                "element_tag": self._as_text(at.get("element_tag")),
                "attribute_name": self._as_text(at.get("name")),
                "namespace_prefix": self._as_text(at.get("ns_prefix")),
                "occurrence_count": self._as_int(at.get("count")) or 0,
                "distinct_value_count": self._as_int(at.get("distinct_values")) or 0,
                "value_type": self._as_text(at.get("value_type")) or "STRING",
                "sample_value": self._as_text(at.get("sample")),
                "min_length": self._as_int(at.get("min_len")) or 0,
                "max_length": self._as_int(at.get("max_len")) or 0,
                "file_id": local_fid,
            }
        )
        return True

    def _emit_namespace(self, mfid: int, ns: Dict[str, Any], local_fid: int) -> int:
        namespace_id = self._next("namespace")
        self.markup_namespaces_table.append(
            {
                "markup_namespace_id": namespace_id,
                "markup_file_id": mfid,
                "prefix": self._as_text(ns.get("prefix")),
                "uri": self._as_text(ns.get("uri")),
                "is_default": self._as_bool(ns.get("is_default")),
                "element_usage_count": self._as_int(ns.get("usage")) or 0,
                "file_id": local_fid,
            }
        )
        return namespace_id

    def _emit_section(self, mfid: int, sec: Dict[str, Any], local_fid: int) -> int:
        section_id = self._next("section")
        self.markup_sections_table.append(
            {
                "markup_section_id": section_id,
                "markup_file_id": mfid,
                "section_name": self._as_text(sec.get("name")),
                "section_type": self._as_text(sec.get("type")),
                "section_path": self._as_text(sec.get("path")),
                "depth": self._as_int(sec.get("depth")) or 0,
                "ordinal": self._as_int(sec.get("ordinal")),
                "element_tag": self._as_text(sec.get("tag")),
                "child_count": self._as_int(sec.get("child_count")) or 0,
                "text_length": self._as_int(sec.get("text_len")) or 0,
                "title": self._as_text(sec.get("title")),
                "file_id": local_fid,
            }
        )
        return section_id

    def _emit_property(self, mfid: int, entry: Any, local_fid: int) -> bool:
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
        self.markup_properties_table.append(
            {
                "property_id": self._next("property"),
                "markup_file_id": mfid,
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
    def _as_bool(v: Any) -> Optional[int]:
        if v is None:
            return None
        return 1 if v else 0

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
            (self.KIND_FILE, self.markup_files_table, "markup_file_id"),
            (self.KIND_ELEMENT, self.markup_elements_table, "markup_element_id"),
            (self.KIND_ATTRIBUTE, self.markup_attributes_table, "markup_attribute_id"),
            (self.KIND_NAMESPACE, self.markup_namespaces_table, "markup_namespace_id"),
            (self.KIND_SECTION, self.markup_sections_table, "markup_section_id"),
            (self.KIND_PROPERTY, self.markup_properties_table, "property_id"),
        ]
        self.markup_file_index.clear()
        for kind, rows, id_key in entity_tables:
            for row in rows:
                repo_id = local_to_repo.get(row.get("file_id"))
                row["file_id"] = repo_id
                if repo_id is not None:
                    self.markup_file_index.append(
                        {
                            "mfi_id": self._next("mfi"),
                            "file_id": repo_id,
                            "entity_kind": kind,
                            "entity_id": row[id_key],
                        }
                    )
        return self.markup_file_index

    # ==================================================================
    # export
    # ==================================================================
    def _export(self, result: Dict[str, List[Dict[str, Any]]]) -> None:
        try:
            with open(self.dump_file_path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2, default=str)
        except OSError as err:
            print(f"Warning: MarkupAnalyzer export failed: {err}")
