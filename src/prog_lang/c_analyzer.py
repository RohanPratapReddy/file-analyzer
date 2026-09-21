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

class CAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep C parsing integrated with libunwind / libdwarf. Extracts `#include`
    directives (imports), `#define` macros and top-level declarations
    (variables), struct/union/enum specifiers and typedefs (classes), and
    function definitions/prototypes with their parameters and return type.
    """

    # struct/union/enum for C; CppAnalyzer adds class_specifier.
    _RECORD_KINDS = ("struct_specifier", "union_specifier", "enum_specifier")
    _NAME_LEAVES = ("identifier", "field_identifier", "type_identifier",
                    "qualified_identifier", "operator_name", "destructor_name")

    def __init__(self, lang_key="c", extensions=None, introspection_source=None, **kwargs):
        super().__init__(
            lang_key=lang_key,
            extensions=extensions or [".c", ".h"],
            introspection_source=introspection_source or "libunwind + execinfo.h backtrace() + libdwarf",
            **kwargs
        )

    # -------- pass 1: register record/typedef type names --------
    def _register_types(self, root_node, source: bytes):
        self._c_register(root_node, source)

    def _c_register(self, container, source: bytes):
        for child in container.children:
            t = child.type
            if t in self._RECORD_KINDS:
                n = child.child_by_field_name("name")
                if n:
                    self._ts_register_class(self._node_text(n, source))
            elif t == "type_definition":
                d = child.child_by_field_name("declarator")
                if d is not None and d.type == "type_identifier":
                    self._ts_register_class(self._node_text(d, source))
            elif t == "declaration":
                ft = child.child_by_field_name("type")
                if ft is not None and ft.type in self._RECORD_KINDS:
                    n = ft.child_by_field_name("name")
                    if n:
                        self._ts_register_class(self._node_text(n, source))
            elif t in ("namespace_definition", "linkage_specification"):
                body = child.child_by_field_name("body")
                if body is not None:
                    self._c_register(body, source)
            elif t == "template_declaration":
                self._c_register(child, source)
            elif t in ("preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif"):
                self._c_register(child, source)

    # -------- pass 2: extract entities --------
    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._c_walk(file_id, root_node, source, class_id=None)

    def _c_walk(self, file_id, container, source, class_id):
        for child in container.children:
            t = child.type
            if t == "preproc_include":
                self._c_include(file_id, child, source)
            elif t in ("preproc_def", "preproc_function_def"):
                n = child.child_by_field_name("name")
                if n:
                    self._ts_add_variable(file_id, self._node_text(n, source), None, scope="macro")
            elif t in self._RECORD_KINDS:
                self._c_record(file_id, child, source)
            elif t == "type_definition":
                self._c_typedef(file_id, child, source)
            elif t == "function_definition":
                self._c_function(file_id, child, source, class_id)
            elif t == "declaration":
                self._c_declaration(file_id, child, source)
            elif t in ("namespace_definition", "linkage_specification"):
                body = child.child_by_field_name("body")
                if body is not None:
                    self._c_walk(file_id, body, source, class_id)
            elif t == "template_declaration":
                for c in child.named_children:
                    if c.type in self._RECORD_KINDS:
                        self._c_record(file_id, c, source)
                    elif c.type == "function_definition":
                        self._c_function(file_id, c, source, class_id)
                    elif c.type == "declaration":
                        self._c_declaration(file_id, c, source)
            elif t in ("preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif"):
                self._c_walk(file_id, child, source, class_id)

    # -------- helpers --------
    def _c_include(self, file_id, node, source: bytes):
        target = None
        for c in node.named_children:
            if c.type in ("system_lib_string", "string_literal"):
                target = self._node_text(c, source).strip('<>"')
                break
        if target is None:
            target = self._node_text(node, source).replace("#include", "").strip().strip('<>"')
        self._ts_add_import(file_id, target.split("/")[-1], target)

    def _c_decl_name(self, node, source: bytes):
        if node is None:
            return None
        if node.type in self._NAME_LEAVES:
            return self._node_text(node, source)
        d = node.child_by_field_name("declarator")
        if d is not None:
            return self._c_decl_name(d, source)
        for c in node.named_children:
            r = self._c_decl_name(c, source)
            if r:
                return r
        return None

    def _c_has_func_declarator(self, node):
        while node is not None:
            if node.type == "function_declarator":
                return True
            node = node.child_by_field_name("declarator")
        return False

    def _c_func_sig(self, declarator, source: bytes):
        fd = declarator
        while fd is not None and fd.type != "function_declarator":
            fd = fd.child_by_field_name("declarator")
        if fd is None:
            return (self._c_decl_name(declarator, source) or "func", [])
        name = self._c_decl_name(fd.child_by_field_name("declarator"), source) or "func"
        return (name, self._c_params(fd.child_by_field_name("parameters"), source))

    def _c_params(self, param_list, source: bytes):
        arg_ids = []
        if param_list is None:
            return arg_ids
        for p in param_list.named_children:
            if p.type == "parameter_declaration":
                t = p.child_by_field_name("type")
                d = p.child_by_field_name("declarator")
                type_text = self._node_text(t, source) if t else None
                name = self._c_decl_name(d, source) if d else None
                if name is None and (type_text in ("void", None)):
                    continue  # `(void)` / unnamed empty
                arg_ids.append(self._ts_add_arg(name or "arg", type_text))
            elif p.type == "variadic_parameter":
                arg_ids.append(self._ts_add_arg("...", "variadic"))
        return arg_ids

    def _c_bases(self, node, source: bytes):
        parent_ids = []
        for c in node.named_children:
            if c.type == "base_class_clause":
                for t in c.named_children:
                    if t.type in ("type_identifier", "qualified_identifier", "template_type"):
                        nm = self._node_text(t, source).split("<")[0].strip()
                        if nm in self._class_registry:
                            parent_ids.append(self._class_registry[nm])
        return parent_ids

    def _c_function(self, file_id, node, source: bytes, class_id=None):
        declarator = node.child_by_field_name("declarator")
        rtype = node.child_by_field_name("type")
        name, arg_ids = self._c_func_sig(declarator, source)
        out = [self._ts_add_output(self._node_text(rtype, source))] if rtype else []
        return self._ts_add_function(file_id, name, arg_ids, out, class_id=class_id)

    def _c_record(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return None  # anonymous (captured via its typedef, if any)
        name = self._node_text(name_node, source)
        cls_id = self._class_registry.get(name, self._class_counter)
        parent_ids = self._c_bases(node, source)
        method_ids, attr_ids = [], []
        body = node.child_by_field_name("body")
        if node.type == "enum_specifier":
            if body is not None:
                for e in body.named_children:
                    if e.type == "enumerator":
                        en = e.child_by_field_name("name")
                        attr_ids.append(self._ts_add_arg(
                            self._node_text(en, source) if en else "e", "enumerator"))
        elif body is not None:
            for member in body.named_children:
                if member.type == "field_declaration":
                    decl = member.child_by_field_name("declarator")
                    ftype = member.child_by_field_name("type")
                    if decl is not None and self._c_has_func_declarator(decl):
                        mname, arg_ids = self._c_func_sig(decl, source)
                        out = [self._ts_add_output(self._node_text(ftype, source))] if ftype else []
                        method_ids.append(self._ts_add_function(file_id, mname, arg_ids, out, class_id=cls_id))
                    else:
                        fname = self._c_decl_name(decl, source) if decl else None
                        attr_ids.append(self._ts_add_arg(
                            fname or "field", self._node_text(ftype, source) if ftype else None))
                elif member.type == "function_definition":
                    method_ids.append(self._c_function(file_id, member, source, cls_id))
        kind = node.type.replace("_specifier", "")
        self._ts_add_class(file_id, name, description=f"{self.lang_key} {kind}",
                           parent_ids=parent_ids, method_ids=method_ids, attr_ids=attr_ids)
        return cls_id

    def _c_typedef(self, file_id, node, source: bytes):
        d = node.child_by_field_name("declarator")
        name = self._node_text(d, source) if d is not None and d.type == "type_identifier" else None
        ftype = node.child_by_field_name("type")
        attr_ids = []
        if (ftype is not None and ftype.type in self._RECORD_KINDS
                and ftype.type != "enum_specifier"):
            body = ftype.child_by_field_name("body")
            if body is not None:
                for member in body.named_children:
                    if member.type == "field_declaration":
                        decl = member.child_by_field_name("declarator")
                        t = member.child_by_field_name("type")
                        fname = self._c_decl_name(decl, source) if decl else None
                        attr_ids.append(self._ts_add_arg(
                            fname or "field", self._node_text(t, source) if t else None))
        if name:
            self._ts_add_class(file_id, name, description=f"{self.lang_key} typedef",
                               attr_ids=attr_ids)

    def _c_declaration(self, file_id, node, source: bytes):
        ftype = node.child_by_field_name("type")
        # `struct X { ... };` / `enum E { ... };` wrapped in a declaration
        if ftype is not None and ftype.type in self._RECORD_KINDS \
                and ftype.child_by_field_name("body") is not None:
            if ftype.child_by_field_name("name") is not None:
                self._c_record(file_id, ftype, source)
        type_text = self._node_text(ftype, source) if ftype else None
        decls = [c for c in node.named_children
                 if c.type in ("init_declarator", "identifier", "pointer_declarator",
                               "array_declarator", "function_declarator",
                               "reference_declarator")]
        for decl in decls:
            if self._c_has_func_declarator(decl):
                mname, arg_ids = self._c_func_sig(decl, source)
                out = [self._ts_add_output(type_text)] if type_text else []
                self._ts_add_function(file_id, mname, arg_ids, out)
            else:
                name = self._c_decl_name(decl, source)
                val = None
                if decl.type == "init_declarator":
                    v = decl.child_by_field_name("value")
                    val = self._node_text(v, source) if v else None
                if name:
                    self._ts_add_variable(file_id, name, val, scope="module")

class CppAnalyzer(CAnalyzer):
    """
    C++ on top of the C engine: adds `class` specifiers, base-class inheritance,
    in-class methods, `namespace` recursion and `template` unwrapping. Integrates
    RTTI <typeinfo>, std::stacktrace and Boost.Describe.
    """

    _RECORD_KINDS = ("class_specifier", "struct_specifier",
                     "union_specifier", "enum_specifier")

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="cpp",
            extensions=[".cpp", ".hpp", ".cc", ".cxx"],
            introspection_source="<typeinfo> (RTTI) + std::stacktrace + Boost.Describe",
            **kwargs
        )
