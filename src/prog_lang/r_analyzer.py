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

class RAnalyzer(BaseTreeSitterAnalyzer):
    """
    R parsing integrated with attributes()/environment() reflection. Extracts
    library()/require()/source() calls (imports), top-level `<-`/`=` bindings
    (functions when the RHS is a `function(...)`, variables otherwise).

    NOTE: no tree_sitter_r wheel exists for CPython 3.14, so at runtime this
    analyzer cleanly degrade-skips; the logic below is exercised where a wheel
    is available (<=3.13).
    """

    _IMPORT_FUNCS = ("library", "require", "requireNamespace", "source", "loadNamespace")
    _ASSIGN_NODES = ("binary_operator", "left_assignment", "equals_assignment",
                     "super_assignment", "right_assignment")

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="r",
            extensions=[".r", ".R"],
            introspection_source="attributes() + environment() + sys.calls()",
            **kwargs
        )

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._r_walk(file_id, root_node, source)

    def _r_walk(self, file_id, node, source: bytes):
        for child in node.children:
            t = child.type
            if t == "call":
                self._r_call(file_id, child, source)
            elif t in self._ASSIGN_NODES:
                self._r_assign(file_id, child, source)
            elif t in ("program", "braced_expression", "expression", "{"):
                self._r_walk(file_id, child, source)

    def _r_call(self, file_id, node, source: bytes):
        fn = node.child_by_field_name("function") or (
            node.named_children[0] if node.named_children else None)
        if fn is None:
            return
        fname = self._node_text(fn, source)
        if fname in self._IMPORT_FUNCS:
            args = node.child_by_field_name("arguments")
            target = None
            if args is not None:
                for a in args.named_children:
                    txt = self._node_text(a, source).strip().strip('"\'')
                    if txt:
                        target = txt.split("=")[-1].strip().strip('"\'')
                        break
            if target:
                self._ts_add_import(file_id, target, target)

    def _r_assign(self, file_id, node, source: bytes):
        lhs = node.child_by_field_name("lhs") or node.child_by_field_name("name")
        rhs = node.child_by_field_name("rhs") or node.child_by_field_name("value")
        if lhs is None or rhs is None:
            nk = list(node.named_children)
            if len(nk) >= 2:
                lhs = lhs or nk[0]
                rhs = rhs or nk[-1]
        if lhs is None:
            return
        name = self._node_text(lhs, source)
        if rhs is not None and rhs.type == "function_definition":
            arg_ids = []
            params = rhs.child_by_field_name("parameters")
            if params is not None:
                for p in params.named_children:
                    if p.type in ("parameter", "default_parameter"):
                        pn = p.child_by_field_name("name") or (
                            p.named_children[0] if p.named_children else None)
                        dv = p.child_by_field_name("default") or p.child_by_field_name("value")
                        arg_ids.append(self._ts_add_arg(
                            self._node_text(pn, source) if pn else "arg", None,
                            self._node_text(dv, source) if dv else None))
            self._ts_add_function(file_id, name, arg_ids, [])
        else:
            self._ts_add_variable(file_id, name,
                                  self._node_text(rhs, source) if rhs else None, scope="module")
