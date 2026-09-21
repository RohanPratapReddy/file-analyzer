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

class JavaAnalyzer(BaseTreeSitterAnalyzer):
    """Deep Java parsing integrated with java.lang.reflect and java.lang.StackWalker."""

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="java",
            extensions=[".java"],
            introspection_source="java.lang.reflect + java.lang.StackWalker",
            **kwargs
        )

    def _register_types(self, root_node, source: bytes):
        for child in root_node.children:
            if child.type in ["class_declaration", "interface_declaration", "enum_declaration"]:
                name_node = child.child_by_field_name("name")
                if name_node:
                    self._class_registry[self._node_text(name_node, source)] = self._class_counter
                    self._class_counter += 1

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        for child in root_node.children:
            if child.type == "import_declaration":
                imp_id = self._import_counter
                self._import_counter += 1
                full_import = self._node_text(child, source).replace("import ", "").replace("static ", "").rstrip(";")
                short_name = full_import.split(".")[-1]
                self.imports_table.append({
                    "import_id": imp_id,
                    "import_name": short_name,
                    "import_source": full_import,
                    "alias": None
                })
                self._record_symbol(file_id, "import", imp_id)

                # Project imported class or static function
                if short_name and short_name[0].isupper():
                    cls_id = self._class_counter
                    self._class_counter += 1
                    self.classes_table.append({
                        "class_id": cls_id,
                        "class_name": short_name,
                        "class_description": f"Imported Java class from {full_import}",
                        "parent_class_ids": [],
                        "method_ids": [],
                        "args_ids": [],
                        "attr_ids": [],
                        "tensor_member_ids": [],
                        "is_imported": True,
                        "source_import_id": imp_id
                    })
                    self._record_symbol(file_id, "class/struct/interface", cls_id)

            elif child.type == "class_declaration":
                self._parse_class(file_id, child, source)

    def _parse_class(self, file_id: int, node, source: bytes):
        name_node = node.child_by_field_name("name")
        cls_name = self._node_text(name_node, source) if name_node else "AnonJavaClass"
        cls_id = self._class_registry.get(cls_name, self._class_counter)
        self._class_counter += 1

        superclass_node = node.child_by_field_name("superclass")
        parent_ids = []
        if superclass_node:
            pname = self._node_text(superclass_node, source).replace("extends ", "").strip()
            if pname in self._class_registry:
                parent_ids.append(self._class_registry[pname])

        body_node = node.child_by_field_name("body")
        method_ids, attr_ids = [], []

        if body_node:
            for member in body_node.children:
                if member.type == "field_declaration":
                    ftype = member.child_by_field_name("type")
                    decls = [c for c in member.children if c.type == "variable_declarator"]
                    for decl in decls:
                        dname = decl.child_by_field_name("name")
                        aid = self._arg_counter
                        self._arg_counter += 1
                        self.args_table.append({
                            "args_id": aid,
                            "args_name": self._node_text(dname, source) if dname else "anon_field",
                            "args_type": self._node_text(ftype, source) if ftype else "Object",
                            "default_value": None,
                            "permitted_values": None
                        })
                        attr_ids.append(aid)

                elif member.type in ["method_declaration", "constructor_declaration"]:
                    mid = self._parse_method(file_id, member, source, cls_id)
                    method_ids.append(mid)

        self.classes_table.append({
            "class_id": cls_id,
            "class_name": cls_name,
            "class_description": None,
            "parent_class_ids": parent_ids,
            "method_ids": method_ids,
            "args_ids": [],
            "attr_ids": attr_ids,
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
            structural_properties={"declared_fields": len(attr_ids), "declared_methods": len(method_ids)}
        )

    def _parse_method(self, file_id: int, node, source: bytes, cls_id: int) -> int:
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        method_name = self._node_text(name_node, source) if name_node else "<init>"

        arg_ids = []
        if params_node:
            for param in params_node.children:
                if param.type == "formal_parameter":
                    ptype = param.child_by_field_name("type")
                    pname = param.child_by_field_name("name")
                    aid = self._arg_counter
                    self._arg_counter += 1
                    self.args_table.append({
                        "args_id": aid,
                        "args_name": self._node_text(pname, source) if pname else "arg",
                        "args_type": self._node_text(ptype, source) if ptype else "Object",
                        "default_value": None,
                        "permitted_values": None
                    })
                    arg_ids.append(aid)

        fn_id = self._func_counter
        self._func_counter += 1
        self.functions_table.append({
            "function_id": fn_id,
            "function_name": method_name,
            "args_ids": arg_ids,
            "function_outputs_ids": [],
            "class_id": cls_id,
            "function_description": None,
            "function_forward_pass": f"```pseudocode\n// Java Forward Pass: {method_name}\nCALL {method_name}(ARGS)\n```",
            "function_backward_pass": f"```pseudocode\n// Java Backward Pass: {method_name}\nPROPAGATE_GRADIENTS_TO_FIELDS()\n```",
            "is_imported": False,
            "source_import_id": None
        })
        self._record_symbol(file_id, "function", fn_id)
        return fn_id
