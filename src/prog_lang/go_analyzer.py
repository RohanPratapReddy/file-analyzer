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
from .tree_sitter_base import BaseTreeSitterAnalyzer

class GoAnalyzer(BaseTreeSitterAnalyzer):
    """
    Analyzes Go source code files (.go) using Tree-sitter.
    Extracts imports, package/file variables, structs, interfaces,
    methods with receivers, standalone functions, and parameters.
    Integrated with reflect (reflect.Type, reflect.Value) and runtime (Caller, Stack).
    """

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="go",
            extensions=[".go"],
            introspection_source="reflect.Type + reflect.Value + runtime.Caller",
            **kwargs
        )

    # ------------------------------------------------------------------
    # Pass 1: Discover Structs and Interfaces
    # ------------------------------------------------------------------
    def _register_types(self, root_node, source: bytes):
        for child in root_node.children:
            if child.type == "type_declaration":
                for spec in child.children:
                    if spec.type == "type_spec":
                        name_node = spec.child_by_field_name("name")
                        type_node = spec.child_by_field_name("type")
                        if name_node and type_node and type_node.type in ["struct_type", "interface_type"]:
                            type_name = self._node_text(name_node, source)
                            self._class_registry[type_name] = self._class_counter
                            self._class_counter += 1

    # ------------------------------------------------------------------
    # Pass 2: Extract Definitions, Methods, Variables, and Imports
    # ------------------------------------------------------------------
    def _extract_entities(self, file_id: int, root_node, source: bytes):
        for child in root_node.children:
            # 1. Imports: import "fmt" or import ( "os"; "path" )
            if child.type == "import_declaration":
                self._parse_import_declaration(file_id, child, source)

            # 2. Package-level var & const declarations
            elif child.type in ["var_declaration", "const_declaration"]:
                self._parse_var_declaration(file_id, child, source)

            # 3. Type specs (structs and interfaces)
            elif child.type == "type_declaration":
                for spec in child.children:
                    if spec.type == "type_spec":
                        self._parse_type_spec(file_id, spec, source)

            # 4. Standalone functions: func Foo(...) (...)
            elif child.type == "function_declaration":
                self._parse_func(file_id, child, source, parent_class_id=None)

            # 5. Receiver Methods: func (r *MyStruct) Method(...) (...)
            elif child.type == "method_declaration":
                self._parse_receiver_method(file_id, child, source)

    # ------------------------------------------------------------------
    # Parsing Helpers
    # ------------------------------------------------------------------
    def _parse_import_declaration(self, file_id: int, node, source: bytes):
        for spec in node.children:
            if spec.type == "import_spec":
                path_node = spec.child_by_field_name("path")
                alias_node = spec.child_by_field_name("name")

                raw_path = self._node_text(path_node, source).strip('"') if path_node else "module"
                alias = self._node_text(alias_node, source) if alias_node else None
                import_name = alias if alias else raw_path.split("/")[-1]

                imp_id = self._import_counter
                self._import_counter += 1
                self.imports_table.append({
                    "import_id": imp_id,
                    "import_name": import_name,
                    "import_source": raw_path,
                    "alias": alias,
                })
                self._record_symbol(file_id, "import", imp_id)

    def _parse_var_declaration(self, file_id: int, node, source: bytes):
        for spec in node.children:
            if spec.type in ["var_spec", "const_spec"]:
                name_node = spec.child_by_field_name("name")
                val_node = spec.child_by_field_name("value")
                var_name = self._node_text(name_node, source) if name_node else "anon_var"
                var_val = self._node_text(val_node, source) if val_node else None

                vid = self._var_counter
                self._var_counter += 1
                self.variables_table.append({
                    "variable_id": vid,
                    "variable_name": var_name,
                    "variable_value": var_val,
                    "scope": "package",
                    "is_imported": False,
                    "source_import_id": None
                })
                self._record_symbol(file_id, "variable", vid)

    def _parse_type_spec(self, file_id: int, spec, source: bytes):
        name_node = spec.child_by_field_name("name")
        type_node = spec.child_by_field_name("type")
        if not name_node or not type_node:
            return

        type_name = self._node_text(name_node, source)
        cls_id = self._class_registry.get(type_name, self._class_counter)
        self._class_counter = max(self._class_counter + 1, cls_id + 1)

        field_ids = []
        parent_ids = []

        # Parse struct fields or embedded structs
        if type_node.type == "struct_type":
            field_list = type_node.child_by_field_name("fields")
            if field_list:
                for field in field_list.children:
                    if field.type != "field_declaration":
                        continue
                    ftype_node = field.child_by_field_name("type")
                    # Grouped fields (`X, Y int`) carry several field_identifier
                    # children under one type, just like grouped params.
                    name_nodes = [c for c in field.children if c.type == "field_identifier"]
                    if name_nodes:
                        # Standard named field(s)
                        for fname_node in name_nodes:
                            aid = self._arg_counter
                            self._arg_counter += 1
                            self.args_table.append({
                                "args_id": aid,
                                "args_name": self._node_text(fname_node, source),
                                "args_type": self._node_text(ftype_node, source) if ftype_node else "interface{}",
                                "default_value": None,
                                "permitted_values": None
                            })
                            field_ids.append(aid)
                    elif ftype_node:
                        # Embedded anonymous struct (Go composition inheritance)
                        embedded_name = self._node_text(ftype_node, source).lstrip("*")
                        if embedded_name in self._class_registry:
                            parent_ids.append(self._class_registry[embedded_name])

        self.classes_table.append({
            "class_id": cls_id,
            "class_name": type_name,
            "class_description": f"Go {type_node.type.replace('_', ' ')}",
            "parent_class_ids": parent_ids,
            "method_ids": [],  # Appended as receiver methods are encountered
            "args_ids": [],
            "attr_ids": field_ids,
            "tensor_member_ids": [],
            "is_imported": False,
            "source_import_id": None
        })
        self._record_symbol(file_id, "class/struct/interface", cls_id)
        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=cls_id,
            entity_type="class",
            inspection_source=self.introspection_source,
            structural_properties={"reflect.Kind": type_node.type.replace("_type", ""), "tags_parsed": True}
        )

    def _parse_receiver_method(self, file_id: int, node, source: bytes):
        receiver_node = node.child_by_field_name("receiver")
        parent_class_id = None

        if receiver_node:
            recv_text = self._node_text(receiver_node, source)
            # Match identifier from (r *MyStruct) or (r MyStruct)
            match = re.search(r"\*?([A-Za-z0-9_]+)\s*\)?$", recv_text.strip())
            if match:
                struct_name = match.group(1)
                parent_class_id = self._class_registry.get(struct_name)

        fn_id = self._parse_func(file_id, node, source, parent_class_id=parent_class_id)

        # Link method ID back into the target class entry
        if parent_class_id:
            for cls_row in self.classes_table:
                if cls_row["class_id"] == parent_class_id:
                    cls_row["method_ids"].append(fn_id)
                    break

    def _parse_func(self, file_id: int, node, source: bytes, parent_class_id: Optional[int]) -> int:
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        result_node = node.child_by_field_name("result")

        fn_name = self._node_text(name_node, source) if name_node else "anonymous"

        # Parameters
        arg_ids = []
        if params_node:
            for p in params_node.children:
                if p.type not in ("parameter_declaration", "variadic_parameter_declaration"):
                    continue
                ptype = p.child_by_field_name("type")
                type_text = self._node_text(ptype, source) if ptype else "interface{}"
                # Go groups names that share a type: `func f(from, to int)` is one
                # parameter_declaration with two `identifier` children and one type.
                # child_by_field_name("name") returns only the first, so iterate them.
                name_nodes = [c for c in p.children if c.type == "identifier"]
                if not name_nodes:
                    name_nodes = [None]  # unnamed param, e.g. func(int)
                for pname in name_nodes:
                    aid = self._arg_counter
                    self._arg_counter += 1
                    self.args_table.append({
                        "args_id": aid,
                        "args_name": self._node_text(pname, source) if pname else "arg",
                        "args_type": type_text,
                        "default_value": None,
                        "permitted_values": None
                    })
                    arg_ids.append(aid)

        # Returns
        out_ids = []
        if result_node:
            oid = self._output_counter
            self._output_counter += 1
            self.outputs_table.append({
                "output_id": oid,
                "output_type": self._node_text(result_node, source),
                "description": None
            })
            out_ids.append(oid)

        fn_id = self._func_counter
        self._func_counter += 1
        self.functions_table.append({
            "function_id": fn_id,
            "function_name": fn_name,
            "args_ids": arg_ids,
            "function_outputs_ids": out_ids,
            "class_id": parent_class_id,
            "function_description": None,
            "function_forward_pass": f"```pseudocode\n// Go Forward Execution: {fn_name}\nCALL {fn_name}(ARGS...)\nRETURN RESULTS\n```",
            "function_backward_pass": f"```pseudocode\n// Go Backward Propagation: {fn_name}\nIF TRACK_GRADIENTS:\n    PROPAGATE_GRADIENT_TO_RECEIVER_OR_POINTERS()\n```",
            "is_imported": False,
            "source_import_id": None
        })
        self._record_symbol(file_id, "function", fn_id)
        return fn_id
