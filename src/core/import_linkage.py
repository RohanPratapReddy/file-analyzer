# Auto-extracted from code_analyzer.py (verbatim class body).
import os
import csv
import json
import re
import ast
import dis
import inspect
import traceback
import subprocess
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

class ImportLinkageAnalyzer:
    """
    Correlates the filesystem tables emitted by ``RepositoryAnalyzer`` with the
    relational code tables emitted by a code analyzer (``PythonCodeAnalyzer`` /
    ``PolyglotCodeAnalyzer`` / ...) to produce a normalized cross-file import
    linkage table:

        import_id, import_name, import_source, alias,
        imported_by_file_id / _name / _type / _location[list],
        imported_to_file_id / _name / _type / _location[list],
        is_external,
        import_value_ids[list], import_value_variable_ids[list],
        import_value_function_ids[list], import_value_class_ids[list]

    Where:
      * ``imported_by_*`` describes the file that CONTAINS the import statement
        (the consumer), resolved via ``symbol_index``.
      * ``imported_to_*`` describes the repository file the import RESOLVES TO
        (the provider/source module). When the import points at a standard-library
        or third-party module with no matching file in the repository, these fields
        are NULL and ``is_external`` is True.
      * ``import_value_*`` are the entity ids projected from the import (variables,
        functions, classes carrying ``source_import_id == import_id``).

    IMPORTANT ID-SPACE NOTE
    -----------------------
    ``symbol_index.file_id`` (assigned per code-analyzer run, starting at 1) is a
    DIFFERENT id space from ``file_details.file_id`` (assigned by RepositoryAnalyzer).
    To emit repository file ids (so downstream foreign keys stay valid) this class
    needs a bridge between the two. Supply ONE of:

      * ``code_file_map``: explicit ``{code_file_id: repository_file_id}`` mapping, or
      * ``analyzed_file_paths``: the ordered list of file paths exactly as the code
        analyzer consumed them (so index ``i`` -> code ``file_id == i + 1``); the
        map is then derived by matching those paths against the repository files.

    If neither is supplied, ``imported_by_file_id`` is left NULL (and its name/type/
    location None) rather than guessing incorrectly.
    """

    def __init__(
        self,
        repository_tables: Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]],
        code_analyzer_tables: Dict[str, List[Dict[str, Any]]],
        analyzed_file_paths: Optional[List[Union[str, Path]]] = None,
        code_file_map: Optional[Dict[int, Optional[int]]] = None,
        dump_file_path: str = "import_linkage.json",
        dump_file_type: str = "memory",
    ):
        self.folders, self.extensions, self.files = repository_tables
        self.code_tables = code_analyzer_tables
        self.analyzed_file_paths = [Path(p) for p in (analyzed_file_paths or [])]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()

        # Fast lookups over the repository tables.
        self._ext_name_by_id: Dict[int, str] = {
            e["extension_id"]: e["extension_name"] for e in self.extensions
        }
        self._folder_name_by_id: Dict[int, str] = {
            f["folder_id"]: f["folder_name"] for f in self.folders
        }
        self._file_by_id: Dict[int, Dict[str, Any]] = {
            f["file_id"]: f for f in self.files
        }

        # Reconstructed relative paths & basename buckets for path matching.
        self._repo_by_relpath: Dict[str, int] = {}
        self._repo_by_basename: Dict[str, List[int]] = {}
        # Dotted-module -> repository file_id, for imported_to resolution.
        self._module_index: Dict[str, int] = {}

        self._build_repository_indexes()

        # Resolve the code<->repo file id bridge.
        self.code_file_map: Dict[int, Optional[int]] = dict(code_file_map or {})
        if not self.code_file_map and self.analyzed_file_paths:
            self.code_file_map = self._derive_code_file_map()

        self.linkage_table: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Repository index construction
    # ------------------------------------------------------------------
    def _clean_ext(self, ext: Optional[str]) -> Optional[str]:
        if ext is None or ext in ("None", ""):
            return None
        return ext

    def _file_relpath(self, file_row: Dict[str, Any]) -> str:
        """Reconstruct a file's posix relative path from repository metadata."""
        ext = self._clean_ext(self._ext_name_by_id.get(file_row.get("file_extension_id")))
        location = file_row.get("location") or []
        deepest_folder = location[-1] if location else 1
        folder_path = self._folder_name_by_id.get(deepest_folder, ".")
        fname = file_row["file_name"] + (f".{ext}" if ext else "")
        if folder_path in (".", "", None):
            return fname
        return f"{folder_path}/{fname}"

    def _build_repository_indexes(self):
        for f in self.files:
            relpath = self._file_relpath(f)
            self._repo_by_relpath.setdefault(relpath, f["file_id"])
            self._repo_by_basename.setdefault(Path(relpath).name, []).append(f["file_id"])

            # Build dotted-module candidates for imported_to resolution.
            location = f.get("location") or []
            deepest_folder = location[-1] if location else 1
            folder_path = self._folder_name_by_id.get(deepest_folder, ".")
            parts = [] if folder_path in (".", "", None) else folder_path.split("/")
            stem = f["file_name"]

            if stem == "__init__":
                module_parts = parts  # package import resolves to the folder
            else:
                module_parts = parts + [stem]

            # Register progressively-shorter suffixes so both fully-qualified and
            # bare module references resolve (e.g. "src.pipeline.host", "pipeline.host", "host").
            for i in range(len(module_parts)):
                dotted = ".".join(module_parts[i:])
                if dotted:
                    self._module_index.setdefault(dotted, f["file_id"])

    def _derive_code_file_map(self) -> Dict[int, Optional[int]]:
        """
        Map code-analyzer file_ids (index+1 of analyzed_file_paths) to repository
        file_ids by matching reconstructed relative paths, then falling back to a
        unique basename match. Ambiguous / unmatched entries map to None.
        """
        mapping: Dict[int, Optional[int]] = {}
        for idx, p in enumerate(self.analyzed_file_paths, start=1):
            posix = p.as_posix()
            matched: Optional[int] = None

            # 1. Longest-suffix relative-path match (most specific wins).
            best_len = -1
            for rel, fid in self._repo_by_relpath.items():
                if posix == rel or posix.endswith("/" + rel):
                    if len(rel) > best_len:
                        best_len = len(rel)
                        matched = fid

            # 2. Fallback: unique basename match.
            if matched is None:
                candidates = self._repo_by_basename.get(p.name, [])
                if len(candidates) == 1:
                    matched = candidates[0]

            mapping[idx] = matched
        return mapping

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------
    def _import_kind_id(self) -> Optional[int]:
        for row in self.code_tables.get("kind_reference", []):
            if row.get("kind_name") == "import":
                return row.get("kind_id")
        return 1  # conventional default

    def _build_import_to_code_file(self) -> Dict[int, int]:
        """Map import_id -> code-analyzer file_id via symbol_index."""
        import_kind = self._import_kind_id()
        result: Dict[int, int] = {}
        for sym in self.code_tables.get("symbol_index", []):
            if sym.get("kind_id") == import_kind:
                # First occurrence wins (an import is recorded once per statement).
                result.setdefault(sym.get("target_entity_id"), sym.get("file_id"))
        return result

    def _repo_file_meta(self, repo_file_id: Optional[int]) -> Tuple[Optional[str], Optional[str], List[int]]:
        """Return (file_name, file_type/extension, location[list]) for a repo file id."""
        if repo_file_id is None:
            return None, None, []
        f = self._file_by_id.get(repo_file_id)
        if not f:
            return None, None, []
        ext = self._clean_ext(self._ext_name_by_id.get(f.get("file_extension_id")))
        return f.get("file_name"), ext, list(f.get("location") or [])

    def _resolve_imported_to(self, import_source: Optional[str]) -> Optional[int]:
        """Resolve an import source string to a repository file id, or None if external."""
        if not import_source:
            return None
        # Normalize relative-import leading dots and whitespace.
        src = import_source.strip().lstrip(".")
        comps = [c for c in src.split(".") if c]
        if not comps:
            return None
        # Try full dotted path, then progressively drop trailing components which are
        # likely imported symbol names rather than module path segments.
        for cut in range(len(comps), 0, -1):
            dotted = ".".join(comps[:cut])
            if dotted in self._module_index:
                return self._module_index[dotted]
        return None

    def _value_ids_for_import(self, import_id: int) -> Tuple[List[int], List[int], List[int]]:
        """Collect (variable_ids, function_ids, class_ids) projected from an import."""
        var_ids = [
            v["variable_id"] for v in self.code_tables.get("variables_table", [])
            if v.get("source_import_id") == import_id
        ]
        fn_ids = [
            fn["function_id"] for fn in self.code_tables.get("functions_table", [])
            if fn.get("source_import_id") == import_id
        ]
        cls_ids = [
            c["class_id"] for c in self.code_tables.get("classes_table", [])
            if c.get("source_import_id") == import_id
        ]
        return var_ids, fn_ids, cls_ids

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(self) -> List[Dict[str, Any]]:
        self.linkage_table.clear()
        import_to_code_file = self._build_import_to_code_file()

        linkage_id = 1
        for imp in self.code_tables.get("imports_table", []):
            import_id = imp.get("import_id")

            # imported_by: file that contains the import statement.
            code_file_id = import_to_code_file.get(import_id)
            imported_by_repo_id = self.code_file_map.get(code_file_id) if code_file_id is not None else None
            by_name, by_type, by_location = self._repo_file_meta(imported_by_repo_id)

            # imported_to: repository file the import resolves to (if local).
            imported_to_repo_id = self._resolve_imported_to(imp.get("import_source"))
            to_name, to_type, to_location = self._repo_file_meta(imported_to_repo_id)

            var_ids, fn_ids, cls_ids = self._value_ids_for_import(import_id)

            self.linkage_table.append({
                "linkage_id": linkage_id,
                "import_id": import_id,
                "import_name": imp.get("import_name"),
                "import_source": imp.get("import_source"),
                "alias": imp.get("alias"),
                "imported_by_file_id": imported_by_repo_id,
                "imported_by_file_name": by_name,
                "imported_by_file_type": by_type,
                "imported_by_file_location": by_location,
                "imported_to_file_id": imported_to_repo_id,
                "imported_to_file_name": to_name,
                "imported_to_file_type": to_type,
                "imported_to_file_location": to_location,
                "is_external": imported_to_repo_id is None,
                "import_value_ids": var_ids + fn_ids + cls_ids,
                "import_value_variable_ids": var_ids,
                "import_value_function_ids": fn_ids,
                "import_value_class_ids": cls_ids,
            })
            linkage_id += 1

        if self.dump_file_type != "memory":
            self._export()
        return self.linkage_table

    def get_table(self) -> List[Dict[str, Any]]:
        return self.linkage_table

    def _export(self):
        out_path = Path(self.dump_file_path)
        if self.dump_file_type == "json":
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({"import_linkage_table": self.linkage_table}, f, indent=4)
            print(f"Exported import linkage to JSON: {out_path}")
        elif self.dump_file_type in ["yml", "yaml"]:
            import yaml
            with open(out_path, "w", encoding="utf-8") as f:
                yaml.dump({"import_linkage_table": self.linkage_table}, f, sort_keys=False)
            print(f"Exported import linkage to YAML: {out_path}")
        elif self.dump_file_type in ["csv", "tsv"] and self.linkage_table:
            delimiter = "\t" if self.dump_file_type == "tsv" else ","
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(self.linkage_table[0].keys()), delimiter=delimiter)
                writer.writeheader()
                writer.writerows(self.linkage_table)
            print(f"Exported import linkage to {self.dump_file_type.upper()}: {out_path}")
