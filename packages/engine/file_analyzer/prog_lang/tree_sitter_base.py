# Auto-extracted from code_analyzer.py (verbatim class body).
from typing import Any, Dict, List, Optional

from ._tree_sitter import get_parser
from .base_code_analyzer import BaseCodeAnalyzer


class BaseTreeSitterAnalyzer(BaseCodeAnalyzer):
    """
    Base for Tree-sitter parsers supporting forward/backward pass generation,
    imported symbols, and per-language reflection/introspection metadata.
    """

    def __init__(
        self,
        lang_key: str,
        extensions: List[str],
        introspection_source: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(language_name=lang_key, **kwargs)
        self.lang_key = lang_key
        self.extensions = extensions
        self.introspection_source = introspection_source
        if get_parser is None:
            raise ImportError(
                "tree-sitter-languages is required. Run: pip install tree-sitter-languages"
            )
        self.parser = get_parser(lang_key)

    def _node_text(self, node, source: bytes) -> str:
        return (
            source[node.start_byte : node.end_byte]
            .decode("utf-8", errors="ignore")
            .strip()
        )

    def _child_of(self, node, *types):
        """First direct child whose ``type`` is in ``types`` (or None)."""
        if node is None:
            return None
        for c in node.children:
            if c.type in types:
                return c
        return None

    def _children_of(self, node, *types):
        """All direct children whose ``type`` is in ``types``."""
        if node is None:
            return []
        return [c for c in node.children if c.type in types]

    # ------------------------------------------------------------------
    # Shared relational row builders.
    #
    # The concrete language analyzers below differ only in how they walk
    # their grammar's AST; the rows they emit are identical in shape. These
    # helpers centralise id allocation, symbol indexing and the default
    # forward/backward pseudocode so each analyzer stays focused on tree
    # traversal. (JavaAnalyzer / RustAnalyzer / GoAnalyzer predate these and
    # inline the same logic; they are left untouched.)
    # ------------------------------------------------------------------
    def _ts_add_import(self, file_id, import_name, import_source, alias=None):
        imp_id = self._import_counter
        self._import_counter += 1
        self.imports_table.append(
            {
                "import_id": imp_id,
                "import_name": import_name,
                "import_source": import_source,
                "alias": alias,
            }
        )
        self._record_symbol(file_id, "import", imp_id)
        return imp_id

    def _ts_add_variable(
        self,
        file_id,
        name,
        value=None,
        scope="module",
        is_imported=False,
        source_import_id=None,
    ):
        vid = self._var_counter
        self._var_counter += 1
        self.variables_table.append(
            {
                "variable_id": vid,
                "variable_name": name,
                "variable_value": value,
                "scope": scope,
                "is_imported": is_imported,
                "source_import_id": source_import_id,
            }
        )
        self._record_symbol(file_id, "variable", vid)
        return vid

    def _ts_add_arg(self, name, arg_type=None, default_value=None):
        aid = self._arg_counter
        self._arg_counter += 1
        self.args_table.append(
            {
                "args_id": aid,
                "args_name": name,
                "args_type": arg_type,
                "default_value": default_value,
                "permitted_values": None,
            }
        )
        return aid

    def _ts_add_output(self, output_type, description=None):
        oid = self._output_counter
        self._output_counter += 1
        self.outputs_table.append(
            {
                "output_id": oid,
                "output_type": output_type,
                "description": description,
            }
        )
        return oid

    def _ts_add_function(
        self,
        file_id,
        name,
        arg_ids=None,
        output_ids=None,
        class_id=None,
        description=None,
        forward=None,
        backward=None,
        is_imported=False,
        source_import_id=None,
    ):
        fn_id = self._func_counter
        self._func_counter += 1
        lang = getattr(self, "lang_key", self.language_name)
        self.functions_table.append(
            {
                "function_id": fn_id,
                "function_name": name,
                "args_ids": arg_ids or [],
                "function_outputs_ids": output_ids or [],
                "class_id": class_id,
                "function_description": description,
                "function_forward_pass": (
                    forward
                    if forward is not None
                    else f"```pseudocode\n// {lang} forward pass: {name}\nRESULT = {name}(ARGS...)\nRETURN RESULT\n```"
                ),
                "function_backward_pass": (
                    backward
                    if backward is not None
                    else f"```pseudocode\n// {lang} backward pass: {name}\nPROPAGATE_GRADIENTS()\n```"
                ),
                "is_imported": is_imported,
                "source_import_id": source_import_id,
            }
        )
        self._record_symbol(file_id, "function", fn_id)
        return fn_id

    def _ts_register_class(self, name):
        """Pass-1: reserve a class id for a declared type name."""
        if name and name not in self._class_registry:
            self._class_registry[name] = self._class_counter
            self._class_counter += 1
        return self._class_registry.get(name)

    def _ts_add_class(
        self,
        file_id,
        name,
        description=None,
        parent_ids=None,
        method_ids=None,
        attr_ids=None,
        is_imported=False,
        source_import_id=None,
        introspect=True,
    ):
        cls_id = self._class_registry.get(name)
        if cls_id is None:
            cls_id = self._class_counter
            self._class_counter += 1
            if name:
                self._class_registry[name] = cls_id
        emitted = getattr(self, "_emitted_class_rows", None)
        if emitted is None:
            emitted = self._emitted_class_rows = {}
        if cls_id in emitted:
            # The same class id is being emitted again: a forward declaration
            # plus its definition, a template primary plus a specialization, or
            # any other redeclaration sharing the registered name. Merge the new
            # members into the existing row instead of inserting a duplicate
            # primary key (which the normalized schema rejects).
            row = emitted[cls_id]

            def _union(dst, src):
                for x in src or []:
                    if x not in dst:
                        dst.append(x)

            _union(row["parent_class_ids"], parent_ids)
            _union(row["method_ids"], method_ids)
            _union(row["attr_ids"], attr_ids)
            if description and not row.get("class_description"):
                row["class_description"] = description
            return cls_id
        row = {
            "class_id": cls_id,
            "class_name": name,
            "class_description": description,
            "parent_class_ids": parent_ids or [],
            "method_ids": method_ids or [],
            "args_ids": [],
            "attr_ids": attr_ids or [],
            "tensor_member_ids": [],
            "is_imported": is_imported,
            "source_import_id": source_import_id,
        }
        self.classes_table.append(row)
        emitted[cls_id] = row
        self._record_symbol(file_id, "class/struct/interface", cls_id)
        if introspect:
            self.record_introspection_metadata(
                file_id=file_id,
                entity_id=cls_id,
                entity_type="class",
                inspection_source=self.introspection_source
                or getattr(self, "lang_key", "generic"),
                structural_properties={
                    "declared_fields": len(attr_ids or []),
                    "declared_methods": len(method_ids or []),
                },
            )
        return cls_id

    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        exts = {e.lower() for e in self.extensions}
        valid_files = [
            p for p in self.file_paths if p.suffix.lower() in exts and p.exists()
        ]

        for file_id, file_path in enumerate(valid_files, start=1):
            source = file_path.read_bytes()
            tree = self.parser.parse(source)
            self._register_types(tree.root_node, source)

        for file_id, file_path in enumerate(valid_files, start=1):
            source = file_path.read_bytes()
            tree = self.parser.parse(source)
            self._extract_entities(file_id, tree.root_node, source)

        self._build_temp_kind_details_table()
        self.export()
        return self.get_tables()

    def _register_types(self, root_node, source: bytes):
        pass

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        pass
