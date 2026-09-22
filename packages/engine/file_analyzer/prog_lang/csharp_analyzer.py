# Auto-extracted from code_analyzer.py (verbatim class body).
from .tree_sitter_base import BaseTreeSitterAnalyzer


class CSharpAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep C# parsing integrated with System.Reflection / System.Diagnostics.
    Extracts `using` directives (imports), namespace-nested class/struct/record
    /interface/enum declarations (classes) with base lists, fields, properties,
    methods and constructors, plus top-level function-like members.
    """

    _TYPE_DECLS = (
        "class_declaration",
        "struct_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "record_struct_declaration",
    )

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="c_sharp",
            extensions=[".cs"],
            introspection_source="System.Reflection.TypeInfo + System.Diagnostics.StackTrace",
            **kwargs,
        )

    def _register_types(self, root_node, source: bytes):
        self._cs_register(root_node, source)

    def _cs_register(self, container, source: bytes):
        for child in container.children:
            if child.type in self._TYPE_DECLS:
                n = child.child_by_field_name("name")
                if n:
                    self._ts_register_class(self._node_text(n, source))
                body = child.child_by_field_name("body")
                if body is not None:
                    self._cs_register(body, source)
            elif child.type in (
                "namespace_declaration",
                "file_scoped_namespace_declaration",
            ):
                body = child.child_by_field_name("body")
                self._cs_register(body if body is not None else child, source)

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._cs_walk(file_id, root_node, source)

    def _cs_walk(self, file_id, container, source):
        for child in container.children:
            t = child.type
            if t == "using_directive":
                self._cs_using(file_id, child, source)
            elif t in self._TYPE_DECLS:
                self._cs_type(file_id, child, source)
            elif t in ("namespace_declaration", "file_scoped_namespace_declaration"):
                body = child.child_by_field_name("body")
                self._cs_walk(file_id, body if body is not None else child, source)

    def _cs_using(self, file_id, node, source: bytes):
        n = node.child_by_field_name("name")
        target = (
            self._node_text(n, source)
            if n
            else self._node_text(node, source)
            .replace("using", "")
            .strip()
            .rstrip(";")
            .strip()
        )
        alias = None
        aliased = node.child_by_field_name("alias") or node.child_by_field_name(
            "aliased_type"
        )
        if aliased is not None and n is not None:
            alias = self._node_text(aliased, source)
        self._ts_add_import(file_id, target.split(".")[-1], target, alias)

    def _cs_bases(self, node, source: bytes):
        parent_ids = []
        for c in node.named_children:
            if c.type == "base_list":
                for t in c.named_children:
                    nm = self._node_text(t, source).split("<")[0].strip()
                    if nm in self._class_registry:
                        parent_ids.append(self._class_registry[nm])
        return parent_ids

    def _cs_params(self, params, source: bytes):
        arg_ids = []
        if params is None:
            return arg_ids
        for p in params.named_children:
            if p.type == "parameter":
                pn = p.child_by_field_name("name")
                pt = p.child_by_field_name("type")
                arg_ids.append(
                    self._ts_add_arg(
                        self._node_text(pn, source) if pn else "arg",
                        self._node_text(pt, source) if pt else None,
                    )
                )
        return arg_ids

    def _cs_method(self, file_id, node, source: bytes, class_id, ctor=False):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "ctor"
        arg_ids = self._cs_params(node.child_by_field_name("parameters"), source)
        out = []
        if not ctor:
            rt = node.child_by_field_name("returns") or node.child_by_field_name("type")
            if rt is not None:
                out = [self._ts_add_output(self._node_text(rt, source))]
        return self._ts_add_function(file_id, name, arg_ids, out, class_id=class_id)

    def _cs_fields(self, node, source: bytes):
        ids = []
        vd = self._child_of(node, "variable_declaration")
        if vd is None:
            return ids
        t = vd.child_by_field_name("type")
        type_text = self._node_text(t, source) if t else None
        for c in vd.named_children:
            if c.type == "variable_declarator":
                nn = c.child_by_field_name("name") or self._child_of(c, "identifier")
                ids.append(
                    self._ts_add_arg(
                        self._node_text(nn, source) if nn else "field", type_text
                    )
                )
        return ids

    def _cs_type(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        name = self._node_text(name_node, source)
        cls_id = self._class_registry.get(name, self._class_counter)
        parent_ids = self._cs_bases(node, source)
        method_ids, attr_ids = [], []
        body = node.child_by_field_name("body")
        if node.type == "enum_declaration":
            if body is not None:
                for m in body.named_children:
                    if m.type == "enum_member_declaration":
                        mn = m.child_by_field_name("name") or self._child_of(
                            m, "identifier"
                        )
                        attr_ids.append(
                            self._ts_add_arg(
                                self._node_text(mn, source) if mn else "member",
                                "enum_member",
                            )
                        )
        elif body is not None:
            for m in body.named_children:
                mt = m.type
                if mt == "method_declaration":
                    method_ids.append(self._cs_method(file_id, m, source, cls_id))
                elif mt == "constructor_declaration":
                    method_ids.append(
                        self._cs_method(file_id, m, source, cls_id, ctor=True)
                    )
                elif mt == "field_declaration":
                    attr_ids.extend(self._cs_fields(m, source))
                elif mt == "property_declaration":
                    pn = m.child_by_field_name("name")
                    pt = m.child_by_field_name("type")
                    attr_ids.append(
                        self._ts_add_arg(
                            self._node_text(pn, source) if pn else "prop",
                            self._node_text(pt, source) if pt else None,
                        )
                    )
                elif mt in self._TYPE_DECLS:
                    self._cs_type(file_id, m, source)
        self._ts_add_class(
            file_id,
            name,
            description=f"c_sharp {node.type.replace('_declaration', '')}",
            parent_ids=parent_ids,
            method_ids=method_ids,
            attr_ids=attr_ids,
        )
