# Auto-extracted from code_analyzer.py (verbatim class body).
from .tree_sitter_base import BaseTreeSitterAnalyzer


class SwiftAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep Swift parsing integrated with Mirror(reflecting:). Extracts `import`
    module declarations, top-level let/var (variables), class/struct/enum
    /protocol/extension declarations (classes) with inheritance, stored
    properties, enum cases and methods, plus standalone functions.
    """

    _TYPE_DECLS = (
        "class_declaration",
        "protocol_declaration",
        "enum_declaration",
        "struct_declaration",
        "extension_declaration",
    )
    _TYPE_NODES = (
        "user_type",
        "type_identifier",
        "optional_type",
        "array_type",
        "dictionary_type",
        "tuple_type",
    )

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="swift",
            extensions=[".swift"],
            introspection_source="Mirror(reflecting:) + Thread.callStackSymbols",
            **kwargs,
        )

    def _register_types(self, root_node, source: bytes):
        self._sw_register(root_node, source)

    def _sw_register(self, container, source: bytes):
        for child in container.children:
            if child.type in self._TYPE_DECLS:
                n = child.child_by_field_name("name") or self._child_of(
                    child, "type_identifier"
                )
                if n is not None:
                    self._ts_register_class(self._node_text(n, source))
                body = self._child_of(
                    child, "class_body", "enum_class_body", "protocol_body"
                )
                if body is not None:
                    self._sw_register(body, source)

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._sw_walk(file_id, root_node, source, class_id=None)

    def _sw_walk(self, file_id, container, source, class_id):
        for child in container.children:
            t = child.type
            if t == "import_declaration":
                self._sw_import(file_id, child, source)
            elif t == "property_declaration":
                if class_id is None:
                    self._sw_property_var(file_id, child, source)
            elif t in self._TYPE_DECLS:
                self._sw_type(file_id, child, source)
            elif t == "function_declaration":
                self._sw_function(file_id, child, source, class_id)

    def _sw_import(self, file_id, node, source: bytes):
        ident = self._child_of(node, "identifier")
        target = (
            self._node_text(ident, source)
            if ident
            else self._node_text(node, source).replace("import", "").strip()
        )
        self._ts_add_import(file_id, target.split(".")[-1], target)

    def _sw_name_of_pattern(self, node, source: bytes):
        pat = self._child_of(node, "pattern")
        if pat is not None:
            si = self._child_of(pat, "simple_identifier") or pat
            return self._node_text(si, source)
        si = self._child_of(node, "simple_identifier")
        return self._node_text(si, source) if si else None

    def _sw_type_annotation(self, node, source: bytes):
        ta = self._child_of(node, "type_annotation")
        if ta is None:
            return None
        ut = self._child_of(ta, *self._TYPE_NODES)
        return (
            self._node_text(ut, source)
            if ut
            else self._node_text(ta, source).lstrip(":").strip()
        )

    def _sw_property_var(self, file_id, node, source: bytes):
        name = self._sw_name_of_pattern(node, source)
        self._ts_add_variable(file_id, name or "var", None, scope="module")

    def _sw_attr(self, node, source: bytes):
        name = self._sw_name_of_pattern(node, source)
        return [
            self._ts_add_arg(name or "attr", self._sw_type_annotation(node, source))
        ]

    def _sw_first_type_id(self, node, source: bytes):
        if node.type == "type_identifier":
            return self._node_text(node, source)
        for c in node.children:
            r = self._sw_first_type_id(c, source)
            if r:
                return r
        return None

    def _sw_return_type(self, node, source: bytes):
        after = False
        for c in node.children:
            if c.type in ("parameter", ")"):
                after = True
                continue
            if after and c.type in self._TYPE_NODES:
                return self._node_text(c, source)
        return None

    def _sw_function(self, file_id, node, source: bytes, class_id):
        name_node = self._child_of(node, "simple_identifier")
        name = self._node_text(name_node, source) if name_node else "func"
        arg_ids = []
        for p in self._children_of(node, "parameter"):
            sids = self._children_of(p, "simple_identifier")
            pname = self._node_text(sids[-1], source) if sids else "arg"
            arg_ids.append(self._ts_add_arg(pname, self._sw_type_annotation(p, source)))
        out = []
        rt = self._sw_return_type(node, source)
        if rt:
            out = [self._ts_add_output(rt)]
        return self._ts_add_function(file_id, name, arg_ids, out, class_id=class_id)

    def _sw_init(self, file_id, node, source: bytes, class_id):
        arg_ids = []
        for p in self._children_of(node, "parameter"):
            sids = self._children_of(p, "simple_identifier")
            pname = self._node_text(sids[-1], source) if sids else "arg"
            arg_ids.append(self._ts_add_arg(pname, self._sw_type_annotation(p, source)))
        return self._ts_add_function(file_id, "init", arg_ids, [], class_id=class_id)

    def _sw_type(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name") or self._child_of(
            node, "type_identifier"
        )
        if name_node is None:
            return
        name = self._node_text(name_node, source)
        cls_id = self._class_registry.get(name, self._class_counter)
        parent_ids = []
        for c in node.children:
            if c.type == "inheritance_specifier":
                nm = self._sw_first_type_id(c, source)
                if nm and nm in self._class_registry:
                    parent_ids.append(self._class_registry[nm])
        method_ids, attr_ids = [], []
        body = self._child_of(node, "class_body", "enum_class_body", "protocol_body")
        if body is not None:
            for m in body.named_children:
                if m.type in ("function_declaration", "protocol_function_declaration"):
                    method_ids.append(self._sw_function(file_id, m, source, cls_id))
                elif m.type == "init_declaration":
                    method_ids.append(self._sw_init(file_id, m, source, cls_id))
                elif m.type == "property_declaration":
                    attr_ids.extend(self._sw_attr(m, source))
                elif m.type == "enum_entry":
                    for si in self._children_of(m, "simple_identifier"):
                        attr_ids.append(
                            self._ts_add_arg(self._node_text(si, source), "enum_case")
                        )
        self._ts_add_class(
            file_id,
            name,
            description=f"swift {node.type.replace('_declaration', '')}",
            parent_ids=parent_ids,
            method_ids=method_ids,
            attr_ids=attr_ids,
        )
