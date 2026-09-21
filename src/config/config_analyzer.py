"""
ConfigAnalyzer -- one configuration *file* decomposed into normalized,
relational key/value tables.

For every ``config``-type extension catalogued in
``DUMP/tabgen/docs/residual.json`` (345 extensions, ~57 syntax families) this
engine runs a real, pure-stdlib parser (see :mod:`.config_formats`) that turns
the file into a canonical nested Python object (``dict`` / ``list`` / scalar),
then flattens that tree into a fully-normalized set of tables:

  * one **key** node per position in the config tree (its name + path + parent),
  * one **value** row per key node carrying the typed value
    (``DICT`` / ``LIST`` / ``STRING`` / ``INT`` / ``FLOAT`` / ``BOOL`` /
    ``NULL`` / ``BYTES``) and a link back to its parent key,
  * top-level containers grouped into **sections** (INI ``[section]``, systemd
    unit groups, TOML tables, deb822 stanzas, registry keys, ...).

Honesty contract (identical to :class:`..database.DatabaseAnalyzer`): content is
sniffed first, a binary payload degrades to an honest forensic byte profile with
no fabricated keys, credential digests are redacted, the raw payload is never
stored, and a parse that only partially succeeds is reported as ``partial`` --
never stubbed or invented.

Output tables (dicts of lists), each row keyed by a stable 1-based id whose
counters are disjoint per entity kind. Each entity row carries a LOCAL
``file_id`` (1-based index into the analyzed file list); :meth:`link_repository`
rewrites it to the repository ``file_details.file_id`` and populates
``config_file_index`` -- exactly like the schema/database/data layers -- so the
plane plugs straight into ``RepositoryDatabaseGenerator``.

  config_files_table        config_file_id, file_name, extension, syntax_family,
                            parse_engine, format_label, detected_via,
                            format_class, size_bytes, encoding, root_type,
                            section_count, key_count, value_count,
                            property_count, max_depth, analysis_status, notes,
                            file_id
  config_sections_table     section_id, config_file_id, section_name,
                            section_path, section_type, parent_section_id,
                            key_count, notes, file_id
  config_value_keys_table   config_value_key_id, config_file_id, section_id,
                            config_value_key_name, key_path,
                            config_value_parent_key_id, depth, node_type,
                            child_count, file_id
  config_values_table       config_value_id, config_value_key_id,
                            config_file_id, section_id,
                            config_value_parent_key_id, config_value_type,
                            scalar_value, list_index, is_leaf, file_id
  config_properties_table   property_id, config_file_id, property_name,
                            property_value, value_type, group_name, file_id
  config_file_index         cfi_id, file_id, entity_kind, entity_id
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from . import config_formats


# maximum tree nodes emitted per file (guards pathological/huge configs)
_NODE_BUDGET = 20000


class ConfigAnalyzer:
    """Analyze configuration files into normalized ``config_*`` tables."""

    KIND_FILE = "file"
    KIND_SECTION = "section"
    KIND_KEY = "key"
    KIND_VALUE = "value"
    KIND_PROPERTY = "property"

    def __init__(
        self,
        file_paths: List[Union[str, Path]],
        dump_file_path: str = "config_analysis.json",
        dump_file_type: str = "memory",
    ):
        self.file_paths = [Path(p) for p in file_paths]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()

        self.config_files_table: List[Dict[str, Any]] = []
        self.config_sections_table: List[Dict[str, Any]] = []
        self.config_value_keys_table: List[Dict[str, Any]] = []
        self.config_values_table: List[Dict[str, Any]] = []
        self.config_properties_table: List[Dict[str, Any]] = []
        self.config_file_index: List[Dict[str, Any]] = []

        self._ids = {k: 0 for k in (
            "file", "section", "key", "value", "property", "cfi",
        )}
        self._budget = 0  # per-file remaining node budget
        self._section_rows: Dict[int, Dict[str, Any]] = {}  # section_id -> row

    # ------------------------------------------------------------------
    # id helpers
    # ------------------------------------------------------------------
    def _next(self, kind: str) -> int:
        self._ids[kind] += 1
        return self._ids[kind]

    @classmethod
    def _known_exts(cls) -> frozenset:
        return config_formats.known_exts()

    @classmethod
    def routing_suffixes(cls) -> Tuple[str, ...]:
        return config_formats.routing_suffixes()

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
                profile = config_formats.analyze(path, ext)
            except Exception as err:  # never let one bad file abort the batch
                print(f"Warning: ConfigAnalyzer failed on {path.name}: {err}")
                continue
            try:
                self._emit_file(path, ext, profile, local_fid)
            except Exception as err:
                print(f"Warning: ConfigAnalyzer emit failed on {path.name}: {err}")
                continue

        result = self.get_tables()
        if self.dump_file_type != "memory":
            self._export(result)
        return result

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "config_files_table": self.config_files_table,
            "config_sections_table": self.config_sections_table,
            "config_value_keys_table": self.config_value_keys_table,
            "config_values_table": self.config_values_table,
            "config_properties_table": self.config_properties_table,
            "config_file_index": self.config_file_index,
        }

    # ==================================================================
    # Row builders
    # ==================================================================
    def _emit_file(self, path: Path, ext: str, profile: Dict[str, Any],
                   local_fid: int) -> None:
        config_file_id = self._next("file")
        root = profile.get("root")

        file_row = {
            "config_file_id": config_file_id,
            "file_name": path.name,
            "extension": ext.lstrip("."),
            "syntax_family": self._as_text(profile.get("family")),
            "parse_engine": self._as_text(profile.get("engine")),
            "format_label": self._as_text(profile.get("format")),
            "detected_via": self._as_text(profile.get("detected_via")),
            "format_class": "binary" if profile.get("status") == "forensic" else "text",
            "size_bytes": self._as_int(profile.get("byte_size")),
            "encoding": self._as_text(profile.get("encoding")),
            "root_type": self._node_type(root),
            "section_count": 0,
            "key_count": 0,
            "value_count": 0,
            "property_count": 0,
            "max_depth": 0,
            "analysis_status": self._as_text(profile.get("status")) or "ok",
            "notes": self._as_text(profile.get("notes")),
            "file_id": local_fid,
        }
        self.config_files_table.append(file_row)

        # file-level metadata / forensic profile -> properties
        prop_count = 0
        for entry in (profile.get("properties") or []):
            if self._emit_property(config_file_id, entry, local_fid):
                prop_count += 1

        # flatten the config tree (skip for forensic/None roots)
        self._budget = _NODE_BUDGET
        stats = {"sections": 0, "keys": 0, "values": 0, "max_depth": 0}
        if root is not None or profile.get("status") == "empty":
            self._flatten_root(config_file_id, root, local_fid, stats)

        file_row["section_count"] = stats["sections"]
        file_row["key_count"] = stats["keys"]
        file_row["value_count"] = stats["values"]
        file_row["property_count"] = prop_count
        file_row["max_depth"] = stats["max_depth"]
        if self._budget <= 0:
            file_row["notes"] = ((file_row["notes"] + "; ") if file_row["notes"] else "") \
                + f"tree truncated at {_NODE_BUDGET} nodes"

    def _flatten_root(self, cfg_id: int, root: Any, local_fid: int,
                      stats: Dict[str, int]) -> None:
        # the synthetic root key/value (parent of everything)
        root_key_id = self._emit_key(
            cfg_id, None, "<root>", "<root>", None, 0, root, local_fid, stats)
        self._emit_value(cfg_id, root_key_id, None, None, root, None, local_fid, stats)

        default_section: Optional[int] = None

        def _default() -> int:
            nonlocal default_section
            if default_section is None:
                default_section = self._emit_section(
                    cfg_id, "(root)", "(root)", "root", None, local_fid, stats)
            return default_section

        if isinstance(root, dict):
            for k, v in root.items():
                sec = (self._emit_section(cfg_id, str(k), str(k),
                                          self._sec_type(v), None, local_fid, stats)
                       if isinstance(v, (dict, list)) else _default())
                self._walk(cfg_id, v, str(k), str(k), root_key_id, 1, sec,
                           None, local_fid, stats)
        elif isinstance(root, list):
            for i, v in enumerate(root):
                name = f"[{i}]"
                sec = (self._emit_section(cfg_id, name, name,
                                          self._sec_type(v), None, local_fid, stats)
                       if isinstance(v, (dict, list)) else _default())
                self._walk(cfg_id, v, name, name, root_key_id, 1, sec,
                           i, local_fid, stats)
        # scalar root: already captured by the root key/value pair

    def _walk(self, cfg_id: int, node: Any, name: str, path: str,
              parent_key_id: int, depth: int, section_id: Optional[int],
              list_index: Optional[int], local_fid: int,
              stats: Dict[str, int]) -> None:
        if self._budget <= 0:
            return
        self._budget -= 1
        key_id = self._emit_key(cfg_id, section_id, name, path, parent_key_id,
                                depth, node, local_fid, stats)
        self._emit_value(cfg_id, key_id, parent_key_id, section_id, node,
                         list_index, local_fid, stats)

        if isinstance(node, dict):
            for k, v in node.items():
                if self._budget <= 0:
                    break
                self._walk(cfg_id, v, str(k), f"{path}.{k}", key_id, depth + 1,
                           section_id, None, local_fid, stats)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                if self._budget <= 0:
                    break
                self._walk(cfg_id, v, f"[{i}]", f"{path}[{i}]", key_id,
                           depth + 1, section_id, i, local_fid, stats)

    def _emit_section(self, cfg_id: int, name: str, path: str, sec_type: str,
                      parent_section_id: Optional[int], local_fid: int,
                      stats: Dict[str, int]) -> int:
        section_id = self._next("section")
        self.config_sections_table.append({
            "section_id": section_id,
            "config_file_id": cfg_id,
            "section_name": self._as_text(name),
            "section_path": self._as_text(path),
            "section_type": sec_type,
            "parent_section_id": parent_section_id,
            "key_count": 0,   # filled in as keys attach to this section
            "notes": None,
            "file_id": local_fid,
        })
        stats["sections"] += 1
        self._section_rows[section_id] = self.config_sections_table[-1]
        return section_id

    def _emit_key(self, cfg_id: int, section_id: Optional[int], name: str,
                  path: str, parent_key_id: Optional[int], depth: int,
                  node: Any, local_fid: int, stats: Dict[str, int]) -> int:
        key_id = self._next("key")
        self.config_value_keys_table.append({
            "config_value_key_id": key_id,
            "config_file_id": cfg_id,
            "section_id": section_id,
            "config_value_key_name": self._as_text(name),
            "key_path": self._as_text(path),
            "config_value_parent_key_id": parent_key_id,
            "depth": depth,
            "node_type": self._node_type(node),
            "child_count": self._child_count(node),
            "file_id": local_fid,
        })
        stats["keys"] += 1
        if depth > stats["max_depth"]:
            stats["max_depth"] = depth
        if section_id is not None:
            row = self._section_rows.get(section_id)
            if row is not None:
                row["key_count"] += 1
        return key_id

    def _emit_value(self, cfg_id: int, key_id: int,
                    parent_key_id: Optional[int], section_id: Optional[int],
                    node: Any, list_index: Optional[int], local_fid: int,
                    stats: Dict[str, int]) -> int:
        value_id = self._next("value")
        is_leaf = not isinstance(node, (dict, list))
        self.config_values_table.append({
            "config_value_id": value_id,
            "config_value_key_id": key_id,
            "config_file_id": cfg_id,
            "section_id": section_id,
            "config_value_parent_key_id": parent_key_id,
            "config_value_type": self._value_type(node),
            "scalar_value": self._scalar_text(node) if is_leaf else None,
            "list_index": list_index,
            "is_leaf": 1 if is_leaf else 0,
            "file_id": local_fid,
        })
        stats["values"] += 1
        return value_id

    def _emit_property(self, cfg_id: int, entry: Any, local_fid: int) -> bool:  # noqa: E301
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
        self.config_properties_table.append({
            "property_id": self._next("property"),
            "config_file_id": cfg_id,
            "property_name": str(name)[:256],
            "property_value": pv[:2048],
            "value_type": vtype,
            "group_name": str(group_name)[:128],
            "file_id": local_fid,
        })
        return True

    # ------------------------------------------------------------------
    # node/value typing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _node_type(node: Any) -> str:
        if isinstance(node, dict):
            return "DICT"
        if isinstance(node, list):
            return "LIST"
        return "SCALAR"

    @staticmethod
    def _value_type(node: Any) -> str:
        if isinstance(node, bool):
            return "BOOL"
        if isinstance(node, int):
            return "INT"
        if isinstance(node, float):
            return "FLOAT"
        if isinstance(node, str):
            return "STRING"
        if isinstance(node, bytes):
            return "BYTES"
        if node is None:
            return "NULL"
        if isinstance(node, dict):
            return "DICT"
        if isinstance(node, list):
            return "LIST"
        return "STRING"

    @staticmethod
    def _child_count(node: Any) -> int:
        if isinstance(node, (dict, list)):
            return len(node)
        return 0

    @staticmethod
    def _sec_type(node: Any) -> str:
        if isinstance(node, dict):
            return "mapping"
        if isinstance(node, list):
            return "sequence"
        return "scalar"

    @staticmethod
    def _scalar_text(node: Any) -> Optional[str]:
        if node is None:
            return None
        if isinstance(node, bool):
            return "true" if node else "false"
        if isinstance(node, bytes):
            return node[:64].hex()
        s = node if isinstance(node, str) else str(node)
        s = s.replace("\x00", "")  # NUL padding is not content
        return s[:2048]

    # ------------------------------------------------------------------
    # coercion helpers (mirror DatabaseAnalyzer)
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
    # Repository linkage (mirrors DatabaseAnalyzer.link_repository)
    # ==================================================================
    def link_repository(
        self,
        repository_tables: Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]],
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
            relpath = fname if folder_path in (".", "", None) else f"{folder_path}/{fname}"
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
            (self.KIND_FILE, self.config_files_table, "config_file_id"),
            (self.KIND_SECTION, self.config_sections_table, "section_id"),
            (self.KIND_KEY, self.config_value_keys_table, "config_value_key_id"),
            (self.KIND_VALUE, self.config_values_table, "config_value_id"),
            (self.KIND_PROPERTY, self.config_properties_table, "property_id"),
        ]
        self.config_file_index.clear()
        for kind, rows, id_key in entity_tables:
            for row in rows:
                repo_id = local_to_repo.get(row.get("file_id"))
                row["file_id"] = repo_id
                if repo_id is not None:
                    self.config_file_index.append({
                        "cfi_id": self._next("cfi"), "file_id": repo_id,
                        "entity_kind": kind, "entity_id": row[id_key],
                    })
        return self.config_file_index

    # ==================================================================
    # export
    # ==================================================================
    def _export(self, result: Dict[str, List[Dict[str, Any]]]) -> None:
        try:
            with open(self.dump_file_path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2, default=str)
        except OSError as err:
            print(f"Warning: ConfigAnalyzer export failed: {err}")
