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

class BaseCodeAnalyzer:
    """
    Abstract relational base engine managing normalized entity stores,
    ID generation sequences, symbol indexing, Mermaid flowcharts, introspection
    reflection metadata tables, and exporters.
    """

    def __init__(
            self,
            file_paths: Optional[List[Union[str, Path]]] = None,
            dump_file_path: str = "code_analysis.json",
            dump_file_type: str = "json",
            language_name: str = "generic"
    ):
        self.file_paths = [Path(p).resolve() for p in (file_paths or [])]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()
        self.language_name = language_name

        self.kind_reference = [
            {"kind_id": 1, "kind_name": "import"},
            {"kind_id": 2, "kind_name": "variable"},
            {"kind_id": 3, "kind_name": "function"},
            {"kind_id": 4, "kind_name": "class/struct/interface"},
            {"kind_id": 5, "kind_name": "tensor_member/field"},
            {"kind_id": 6, "kind_name": "arg/parameter"},
            {"kind_id": 7, "kind_name": "introspection_metadata"},
        ]
        self.kind_lookup = {item["kind_name"]: item["kind_id"] for item in self.kind_reference}

        # Relational Stores
        self.symbol_index: List[Dict[str, Any]] = []
        self.imports_table: List[Dict[str, Any]] = []
        self.variables_table: List[Dict[str, Any]] = []
        self.functions_table: List[Dict[str, Any]] = []
        self.classes_table: List[Dict[str, Any]] = []
        self.args_table: List[Dict[str, Any]] = []
        self.tensor_members_table: List[Dict[str, Any]] = []
        self.outputs_table: List[Dict[str, Any]] = []
        self.introspection_metadata_table: List[Dict[str, Any]] = []
        self.temp_kind_details: List[Dict[str, Any]] = []

        # Auto-increment Counters
        self._symbol_counter = 1
        self._import_counter = 1
        self._var_counter = 1
        self._func_counter = 1
        self._class_counter = 1
        self._arg_counter = 1
        self._member_counter = 1
        self._output_counter = 1
        self._metadata_counter = 1
        self._temp_kind_counter = 1

        self._class_registry: Dict[str, int] = {}

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "kind_reference": self.kind_reference,
            "symbol_index": self.symbol_index,
            "imports_table": self.imports_table,
            "variables_table": self.variables_table,
            "functions_table": self.functions_table,
            "classes_table": self.classes_table,
            "args_table": self.args_table,
            "tensor_members_table": self.tensor_members_table,
            "outputs_table": self.outputs_table,
            "introspection_metadata_table": self.introspection_metadata_table,
            "temp_kind_details": self.temp_kind_details,
        }

    def _record_symbol(self, file_id: int, kind_name: str, target_id: int):
        sym_id = self._symbol_counter
        self._symbol_counter += 1
        self.symbol_index.append({
            "symbol_id": sym_id,
            "file_id": file_id,
            "kind_id": self.kind_lookup.get(kind_name, 0),
            "target_entity_id": target_id,
        })

    def record_introspection_metadata(
        self,
        file_id: int,
        entity_id: int,
        entity_type: str,
        inspection_source: str,
        bytecode_or_ast_dump: Optional[str] = None,
        runtime_decorators_or_attributes: Optional[Dict[str, Any]] = None,
        callstack_or_frame_trace: Optional[str] = None,
        structural_properties: Optional[Dict[str, Any]] = None
    ):
        """Records rich introspection information directly linked to an analyzed entity."""
        m_id = self._metadata_counter
        self._metadata_counter += 1
        self.introspection_metadata_table.append({
            "metadata_id": m_id,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "language": self.language_name,
            "inspection_source": inspection_source,
            "bytecode_or_ast_dump": bytecode_or_ast_dump,
            "runtime_decorators_or_attributes": json.dumps(runtime_decorators_or_attributes or {}),
            "callstack_or_frame_trace": callstack_or_frame_trace,
            "structural_properties": json.dumps(structural_properties or {})
        })
        self._record_symbol(file_id, "introspection_metadata", m_id)

    def _build_temp_kind_details_table(self):
        """
        Builds the unified temp_kind_details table grouping entities and
        constructing execution and reference pipeline Mermaid flowcharts:
        `{id}{type} --> {id}{type}`
        """
        self.temp_kind_details.clear()
        self._temp_kind_counter = 1

        categories = [
            ("variables", "variable", [v["variable_id"] for v in self.variables_table if not v.get("is_imported")]),
            ("imported_variables", "variable", [v["variable_id"] for v in self.variables_table if v.get("is_imported")]),
            ("functions", "function", [f["function_id"] for f in self.functions_table if not f.get("is_imported")]),
            ("imported_functions", "function", [f["function_id"] for f in self.functions_table if f.get("is_imported")]),
            ("classes", "class", [c["class_id"] for c in self.classes_table if not c.get("is_imported")]),
            ("imported_classes", "class", [c["class_id"] for c in self.classes_table if c.get("is_imported")]),
            ("arguments", "arg", [a["args_id"] for a in self.args_table]),
            ("weights_and_buffers", "tensor_member", [m["member_id"] for m in self.tensor_members_table]),
            ("introspection_metadata", "metadata", [m["metadata_id"] for m in self.introspection_metadata_table]),
        ]

        # Generate Mermaid Flowchart edges representing relational links (computed once).
        edges = set()

        # Map imports to derived items
        for imp in self.imports_table:
            imp_node = f"{imp['import_id']}import"
            for var in self.variables_table:
                if var.get("source_import_id") == imp["import_id"]:
                    edges.add(f"    {imp_node} --> {var['variable_id']}variable")
            for func in self.functions_table:
                if func.get("source_import_id") == imp["import_id"]:
                    edges.add(f"    {imp_node} --> {func['function_id']}function")
            for cls in self.classes_table:
                if cls.get("source_import_id") == imp["import_id"]:
                    edges.add(f"    {imp_node} --> {cls['class_id']}class")

        # Map functions to arguments, outputs, and parent classes
        for func in self.functions_table:
            f_node = f"{func['function_id']}function"
            for aid in func.get("args_ids", []):
                edges.add(f"    {aid}arg --> {f_node}")
            for oid in func.get("function_outputs_ids", []):
                edges.add(f"    {f_node} --> {oid}output")
            if func.get("class_id"):
                edges.add(f"    {func['class_id']}class --> {f_node}")

        # Map classes to members, attributes, and base classes
        for cls in self.classes_table:
            c_node = f"{cls['class_id']}class"
            for pid in cls.get("parent_class_ids", []):
                edges.add(f"    {pid}class --> {c_node}")
            for mid in cls.get("method_ids", []):
                edges.add(f"    {c_node} --> {mid}function")
            for aid in cls.get("attr_ids", []):
                edges.add(f"    {c_node} --> {aid}arg")
            for tid in cls.get("tensor_member_ids", []):
                edges.add(f"    {c_node} --> {tid}tensor_member")

        # Map entities to their introspection metadata
        for meta in self.introspection_metadata_table:
            edges.add(f"    {meta['entity_id']}{meta['entity_type']} --> {meta['metadata_id']}metadata")

        for kind_name, kind_type, target_ids in categories:
            if not target_ids and "imported" in kind_name:
                continue

            mermaid_lines = ["```mermaid", "flowchart TD"]
            if edges:
                mermaid_lines.extend(sorted(list(edges))[:45])  # Cap for optimal scannability
            else:
                mermaid_lines.append("    None[No Pipeline Linkages Available]")
            mermaid_lines.append("```")

            self.temp_kind_details.append({
                "temp_kind_id": self._temp_kind_counter,
                "kind_type": kind_type,
                "kind_name": kind_name,
                "kind_function_ids": [fid for fid in target_ids if kind_type == "function"],
                "kind_args_ids": [aid for aid in target_ids if kind_type == "arg"],
                "kind_class_ids": [cid for cid in target_ids if kind_type == "class"],
                "kind_variables_ids": [vid for vid in target_ids if kind_type == "variable"],
                "kind_tensor_member_ids": [mid for mid in target_ids if kind_type == "tensor_member"],
                "pipeline_flowchart": "\n".join(mermaid_lines)
            })
            self._temp_kind_counter += 1

    def export(self):
        dump_type = self.dump_file_type
        if dump_type == "memory":
            return

        self._build_temp_kind_details_table()
        out_path = Path(self.dump_file_path)
        tables = self.get_tables()

        if dump_type == "json":
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(tables, f, indent=4)
            print(f"Exported code analysis to JSON: {out_path}")

        elif dump_type in ["yml", "yaml"]:
            import yaml
            with open(out_path, "w", encoding="utf-8") as f:
                yaml.dump(tables, f, sort_keys=False)
            print(f"Exported code analysis to YAML: {out_path}")

        elif dump_type in ["csv", "tsv"]:
            delimiter = "\t" if dump_type == "tsv" else ","
            ext = "tsv" if dump_type == "tsv" else "csv"
            base_dir = out_path.parent
            base_name = out_path.stem

            for tbl_name, rows in tables.items():
                if not rows:
                    continue
                file_dest = base_dir / f"{base_name}_{tbl_name}.{ext}"
                with open(file_dest, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()), delimiter=delimiter)
                    writer.writeheader()
                    writer.writerows(rows)
            print(f"Exported tables to {ext.upper()} in {base_dir}")

        elif dump_type == "xlsx":
            import pandas as pd
            with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
                for tbl_name, rows in tables.items():
                    # Flatten list/dict values for Excel cells
                    cleaned = [{k: (str(v) if isinstance(v, (list, dict)) else v) for k, v in r.items()} for r in rows]
                    pd.DataFrame(cleaned).to_excel(writer, sheet_name=tbl_name[:31], index=False)
            print(f"Exported analysis to Excel: {out_path}")
