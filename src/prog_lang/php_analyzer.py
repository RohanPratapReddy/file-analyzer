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

class PhpAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep PHP parsing integrated with ReflectionClass / ReflectionFunction.
    Extracts `use` imports, top-level const/`$var` (variables), class/interface
    /trait/enum declarations (classes) with extends/implements, properties,
    methods and constants, plus standalone functions.
    """

    _TYPE_DECLS = ("class_declaration", "interface_declaration",
                   "trait_declaration", "enum_declaration")

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="php",
            extensions=[".php"],
            introspection_source="ReflectionClass + ReflectionFunction + debug_backtrace()",
            **kwargs
        )

    def _register_types(self, root_node, source: bytes):
        self._php_register(root_node, source)

    def _php_register(self, container, source: bytes):
        for child in container.children:
            if child.type in self._TYPE_DECLS:
                n = child.child_by_field_name("name")
                if n:
                    self._ts_register_class(self._node_text(n, source))
            elif child.type == "namespace_definition":
                body = child.child_by_field_name("body")
                if body is not None:
                    self._php_register(body, source)

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._php_walk(file_id, root_node, source)

    def _php_walk(self, file_id, container, source):
        for child in container.children:
            t = child.type
            if t == "namespace_use_declaration":
                self._php_use(file_id, child, source)
            elif t == "const_declaration":
                self._php_const(file_id, child, source)
            elif t == "expression_statement":
                self._php_expr(file_id, child, source)
            elif t in self._TYPE_DECLS:
                self._php_type(file_id, child, source)
            elif t == "function_definition":
                self._php_function(file_id, child, source, None)
            elif t == "namespace_definition":
                body = child.child_by_field_name("body")
                if body is not None:
                    self._php_walk(file_id, body, source)

    def _php_use(self, file_id, node, source: bytes):
        for c in node.named_children:
            if c.type == "namespace_use_clause":
                nm, alias = None, None
                for cc in c.named_children:
                    if cc.type in ("qualified_name", "name", "namespace_name"):
                        nm = self._node_text(cc, source)
                    elif cc.type == "namespace_aliasing_clause":
                        a = cc.child_by_field_name("name") or (
                            cc.named_children[-1] if cc.named_children else None)
                        alias = self._node_text(a, source) if a else None
                if nm:
                    self._ts_add_import(file_id, nm.split("\\")[-1], nm, alias)

    def _php_const(self, file_id, node, source: bytes):
        for c in node.named_children:
            if c.type == "const_element":
                kids = c.named_children
                if kids:
                    nm = self._node_text(kids[0], source)
                    val = self._node_text(kids[-1], source) if len(kids) > 1 else None
                    self._ts_add_variable(file_id, nm, val, scope="module")

    def _php_expr(self, file_id, node, source: bytes):
        for c in node.named_children:
            if c.type == "assignment_expression":
                left = c.child_by_field_name("left")
                right = c.child_by_field_name("right")
                if left is not None and left.type == "variable_name":
                    self._ts_add_variable(
                        file_id, self._node_text(left, source).lstrip("$"),
                        self._node_text(right, source) if right else None, scope="module")

    def _php_bases(self, node, source: bytes):
        parent_ids = []
        for c in node.named_children:
            if c.type in ("base_clause", "class_interface_clause"):
                for t in c.named_children:
                    if t.type in ("name", "qualified_name"):
                        nm = self._node_text(t, source)
                        if nm in self._class_registry:
                            parent_ids.append(self._class_registry[nm])
        return parent_ids

    def _php_params(self, params, source: bytes):
        arg_ids = []
        if params is None:
            return arg_ids
        for p in params.named_children:
            if p.type in ("simple_parameter", "variadic_parameter",
                          "property_promotion_parameter"):
                nn = p.child_by_field_name("name")
                tt = p.child_by_field_name("type")
                dv = p.child_by_field_name("default_value")
                arg_ids.append(self._ts_add_arg(
                    self._node_text(nn, source).lstrip("$") if nn else "arg",
                    self._node_text(tt, source) if tt else None,
                    self._node_text(dv, source) if dv else None))
        return arg_ids

    def _php_props(self, node, source: bytes):
        ids = []
        tt = node.child_by_field_name("type")
        type_text = self._node_text(tt, source) if tt else None
        for c in node.named_children:
            if c.type == "property_element":
                vn = c.child_by_field_name("name") or (
                    c.named_children[0] if c.named_children else None)
                if vn is not None:
                    ids.append(self._ts_add_arg(
                        self._node_text(vn, source).lstrip("$"), type_text))
        return ids

    def _php_function(self, file_id, node, source: bytes, class_id):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "function"
        arg_ids = self._php_params(node.child_by_field_name("parameters"), source)
        out = []
        rt = node.child_by_field_name("return_type")
        if rt is not None:
            out = [self._ts_add_output(self._node_text(rt, source))]
        return self._ts_add_function(file_id, name, arg_ids, out, class_id=class_id)

    def _php_type(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        name = self._node_text(name_node, source)
        cls_id = self._class_registry.get(name, self._class_counter)
        parent_ids = self._php_bases(node, source)
        method_ids, attr_ids = [], []
        body = node.child_by_field_name("body") or self._child_of(node, "declaration_list")
        if node.type == "enum_declaration" and body is not None:
            for m in body.named_children:
                if m.type == "enum_case":
                    mn = m.child_by_field_name("name") or self._child_of(m, "name")
                    attr_ids.append(self._ts_add_arg(
                        self._node_text(mn, source) if mn else "case", "enum_case"))
        elif body is not None:
            for m in body.named_children:
                mt = m.type
                if mt == "method_declaration":
                    method_ids.append(self._php_function(file_id, m, source, cls_id))
                elif mt == "property_declaration":
                    attr_ids.extend(self._php_props(m, source))
                elif mt == "const_declaration":
                    self._php_const(file_id, m, source)
        self._ts_add_class(file_id, name,
                           description=f"php {node.type.replace('_declaration', '')}",
                           parent_ids=parent_ids, method_ids=method_ids, attr_ids=attr_ids)
