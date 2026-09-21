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

class RustAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep Rust parsing integrated with std::any / std::backtrace / bevy_reflect.

    Extracts `use` imports, free functions (`function_item`), constants and
    statics (`const_item` / `static_item` -> variables), type definitions
    (`struct_item` / `enum_item` / `union_item` / `trait_item` / `type_item` ->
    classes), and methods declared in `impl` blocks (attached to the impl'd
    type). Nested `mod` blocks are recursed into so their items are captured too.
    """

    _TYPE_KINDS = ("struct_item", "enum_item", "union_item", "trait_item", "type_item")

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="rust",
            extensions=[".rs"],
            introspection_source="std::any::TypeId + std::backtrace::Backtrace + bevy_reflect",
            **kwargs
        )
        # class_id -> classes_table row, so impl blocks can append method ids
        # to a type declared elsewhere in the same file.
        self._rust_rows_by_id: Dict[int, Dict[str, Any]] = {}

    # -------- pass 1: register every declared type name --------
    def _register_types(self, root_node, source: bytes):
        self._rust_register(root_node, source)

    def _rust_register(self, container, source: bytes):
        for child in container.children:
            if child.type in self._TYPE_KINDS:
                name_node = child.child_by_field_name("name")
                if name_node:
                    name = self._node_text(name_node, source)
                    if name and name not in self._class_registry:
                        self._class_registry[name] = self._class_counter
                        self._class_counter += 1
            elif child.type == "mod_item":
                body = child.child_by_field_name("body")
                if body:
                    self._rust_register(body, source)

    # -------- pass 2: extract entities --------
    def _extract_entities(self, file_id: int, root_node, source: bytes):
        # Anchor the file itself so import-linkage / temp_kind have a module node.
        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=file_id,
            entity_type="module",
            inspection_source=self.introspection_source,
            structural_properties={"file": "<rust module>"},
        )
        deferred_impls: List[Any] = []
        self._rust_extract(file_id, root_node, source, deferred_impls)
        # impls are processed last so methods can attach to types declared
        # anywhere in the file (source order is not guaranteed impl-after-type).
        for impl_node in deferred_impls:
            self._rust_impl(file_id, impl_node, source)

    def _rust_extract(self, file_id: int, container, source: bytes, deferred_impls: List[Any]):
        for child in container.children:
            ctype = child.type
            if ctype == "use_declaration":
                imp_id = self._import_counter
                self._import_counter += 1
                imp_text = self._node_text(child, source).replace("use ", "").rstrip(";")
                self.imports_table.append({
                    "import_id": imp_id,
                    "import_name": imp_text.split("::")[-1],
                    "import_source": imp_text,
                    "alias": None,
                })
                self._record_symbol(file_id, "import", imp_id)
            elif ctype == "function_item":
                self._rust_function(file_id, child, source, class_id=None)
            elif ctype in ("const_item", "static_item"):
                self._rust_const(file_id, child, source)
            elif ctype in self._TYPE_KINDS:
                self._rust_type(file_id, child, source)
            elif ctype == "impl_item":
                deferred_impls.append(child)
            elif ctype == "mod_item":
                body = child.child_by_field_name("body")
                if body:
                    self._rust_extract(file_id, body, source, deferred_impls)

    def _rust_function(self, file_id: int, node, source: bytes, class_id: Optional[int]) -> int:
        name_node = node.child_by_field_name("name")
        fn_name = self._node_text(name_node, source) if name_node else "anon_fn"

        arg_ids: List[int] = []
        params = node.child_by_field_name("parameters")
        if params:
            for pc in params.children:
                if pc.type != "parameter":
                    continue  # self_parameter / variadic are not named args
                pat = pc.child_by_field_name("pattern")
                typ = pc.child_by_field_name("type")
                aid = self._arg_counter
                self._arg_counter += 1
                self.args_table.append({
                    "args_id": aid,
                    "args_name": self._node_text(pat, source) if pat else "arg",
                    "args_type": self._node_text(typ, source) if typ else "Any",
                    "default_value": None,
                    "permitted_values": None,
                })
                arg_ids.append(aid)

        output_ids: List[int] = []
        rt = node.child_by_field_name("return_type")
        if rt:
            oid = self._output_counter
            self._output_counter += 1
            self.outputs_table.append({
                "output_id": oid,
                "output_type": self._node_text(rt, source),
                "description": None,
            })
            output_ids.append(oid)

        fn_id = self._func_counter
        self._func_counter += 1
        self.functions_table.append({
            "function_id": fn_id,
            "function_name": fn_name,
            "args_ids": arg_ids,
            "function_outputs_ids": output_ids,
            "class_id": class_id,
            "function_description": None,
            "function_forward_pass": f"```pseudocode\n// Rust Forward Pass: {fn_name}\nRESULT = {fn_name}(ARGS...)\nRETURN RESULT\n```",
            "function_backward_pass": f"```pseudocode\n// Rust Backward Pass: {fn_name}\nPROPAGATE_GRADIENTS()\n```",
            "is_imported": False,
            "source_import_id": None,
        })
        self._record_symbol(file_id, "function", fn_id)
        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=fn_id,
            entity_type="function",
            inspection_source=self.introspection_source,
            structural_properties={"params": len(arg_ids), "has_return": bool(output_ids)},
        )
        return fn_id

    def _rust_const(self, file_id: int, node, source: bytes):
        name_node = node.child_by_field_name("name")
        val_node = node.child_by_field_name("value")
        var_id = self._var_counter
        self._var_counter += 1
        self.variables_table.append({
            "variable_id": var_id,
            "variable_name": self._node_text(name_node, source) if name_node else "anon_const",
            "variable_value": self._node_text(val_node, source) if val_node else None,
            "scope": "module",
            "is_imported": False,
            "source_import_id": None,
        })
        self._record_symbol(file_id, "variable", var_id)

    def _rust_type(self, file_id: int, node, source: bytes):
        name_node = node.child_by_field_name("name")
        cls_name = self._node_text(name_node, source) if name_node else "AnonRustType"
        cls_id = self._class_registry.get(cls_name, self._class_counter)
        if cls_name not in self._class_registry:
            self._class_registry[cls_name] = cls_id
            self._class_counter += 1

        attr_ids: List[int] = []
        method_ids: List[int] = []
        body = node.child_by_field_name("body")
        if body:
            for member in body.children:
                if member.type == "field_declaration":
                    fname = member.child_by_field_name("name")
                    ftype = member.child_by_field_name("type")
                    aid = self._arg_counter
                    self._arg_counter += 1
                    self.args_table.append({
                        "args_id": aid,
                        "args_name": self._node_text(fname, source) if fname else "field",
                        "args_type": self._node_text(ftype, source) if ftype else "Any",
                        "default_value": None,
                        "permitted_values": None,
                    })
                    attr_ids.append(aid)
                elif member.type == "enum_variant":
                    vname = member.child_by_field_name("name")
                    aid = self._arg_counter
                    self._arg_counter += 1
                    self.args_table.append({
                        "args_id": aid,
                        "args_name": self._node_text(vname, source) if vname else "variant",
                        "args_type": "EnumVariant",
                        "default_value": None,
                        "permitted_values": None,
                    })
                    attr_ids.append(aid)
                elif member.type == "function_item":
                    # trait method signatures / default methods
                    mid = self._rust_function(file_id, member, source, class_id=cls_id)
                    method_ids.append(mid)

        row = {
            "class_id": cls_id,
            "class_name": cls_name,
            "class_description": f"Rust {node.type.replace('_item', '')}",
            "parent_class_ids": [],
            "method_ids": method_ids,
            "args_ids": [],
            "attr_ids": attr_ids,
            "tensor_member_ids": [],
            "is_imported": False,
            "source_import_id": None,
        }
        self.classes_table.append(row)
        self._rust_rows_by_id[cls_id] = row
        self._record_symbol(file_id, "class/struct/interface", cls_id)
        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=cls_id,
            entity_type="class",
            inspection_source=self.introspection_source,
            structural_properties={"fields": len(attr_ids), "methods": len(method_ids)},
        )

    def _rust_impl(self, file_id: int, node, source: bytes):
        type_node = node.child_by_field_name("type")
        type_name = self._node_text(type_node, source) if type_node else None
        cls_id = self._class_registry.get(type_name) if type_name else None

        # impl on a type not declared in this file (e.g. an external/generic
        # type): materialize a class row so its methods still attach somewhere.
        if cls_id is None and type_name:
            cls_id = self._class_counter
            self._class_counter += 1
            self._class_registry[type_name] = cls_id
            row = {
                "class_id": cls_id,
                "class_name": type_name,
                "class_description": "Rust impl target",
                "parent_class_ids": [],
                "method_ids": [],
                "args_ids": [],
                "attr_ids": [],
                "tensor_member_ids": [],
                "is_imported": False,
                "source_import_id": None,
            }
            self.classes_table.append(row)
            self._rust_rows_by_id[cls_id] = row
            self._record_symbol(file_id, "class/struct/interface", cls_id)

        body = node.child_by_field_name("body")
        if not body:
            return
        for member in body.children:
            if member.type == "function_item":
                mid = self._rust_function(file_id, member, source, class_id=cls_id)
                row = self._rust_rows_by_id.get(cls_id)
                if row is not None:
                    row["method_ids"].append(mid)
