# Auto-extracted from code_analyzer.py (verbatim class body).
from .tree_sitter_base import BaseTreeSitterAnalyzer


class ScalaAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep Scala parsing integrated with scala.reflect. Extracts import
    declarations, top-level val/var (variables), class/trait/object/enum
    definitions (classes) with extends/with supertypes, case-class/class
    parameters and body val/var (attributes), member defs (methods), and
    standalone defs (functions).
    """

    _TYPE_DECLS = (
        "class_definition",
        "trait_definition",
        "object_definition",
        "enum_definition",
    )
    _VAL_DECLS = (
        "val_definition",
        "var_definition",
        "val_declaration",
        "var_declaration",
    )

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="scala",
            extensions=[".scala", ".sc"],
            introspection_source="scala.reflect.runtime.universe + scala.quoted",
            **kwargs,
        )

    def _register_types(self, root_node, source: bytes):
        self._sc_register(root_node, source)

    def _sc_register(self, container, source: bytes):
        for child in container.children:
            if child.type in self._TYPE_DECLS:
                n = child.child_by_field_name("name")
                if n is not None:
                    self._ts_register_class(self._node_text(n, source))
                body = child.child_by_field_name("body")
                if body is not None:
                    self._sc_register(body, source)
            elif child.type == "package_clause":
                body = child.child_by_field_name("body")
                if body is not None:
                    self._sc_register(body, source)

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._sc_walk(file_id, root_node, source, class_id=None)

    def _sc_walk(self, file_id, container, source, class_id):
        for child in container.children:
            t = child.type
            if t == "import_declaration":
                self._sc_import(file_id, child, source)
            elif t in self._VAL_DECLS:
                if class_id is None:
                    self._sc_value(file_id, child, source, "module")
            elif t in ("function_definition", "function_declaration"):
                self._sc_function(file_id, child, source, class_id)
            elif t in self._TYPE_DECLS:
                self._sc_type(file_id, child, source)
            elif t == "package_clause":
                body = child.child_by_field_name("body")
                if body is not None:
                    self._sc_walk(file_id, body, source, class_id)

    def _sc_import(self, file_id, node, source: bytes):
        txt = self._node_text(node, source).replace("import", "").strip()
        base = txt.split("{")[0].strip().rstrip(".")
        short = base.split(".")[-1] if base else txt
        self._ts_add_import(file_id, short, txt)

    def _sc_value(self, file_id, node, source: bytes, scope):
        pat = node.child_by_field_name("pattern") or node.child_by_field_name("name")
        name = self._node_text(pat, source) if pat is not None else None
        if name is None:
            ident = self._child_of(node, "identifier")
            name = self._node_text(ident, source) if ident else "val"
        v = node.child_by_field_name("value")
        self._ts_add_variable(
            file_id, name, self._node_text(v, source) if v else None, scope=scope
        )

    def _sc_function(self, file_id, node, source: bytes, class_id):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "def"
        arg_ids = []
        # A def may have several `parameters` clauses (curried defs); a
        # `type_parameters` ([A]) clause is NOT a value-parameter clause and is
        # skipped. child_by_field_name("parameters") is unreliable here (it can
        # resolve to type_parameters), so iterate the named children directly.
        for params in self._children_of(node, "parameters"):
            for p in params.named_children:
                if p.type in ("parameter", "class_parameter"):
                    pn = p.child_by_field_name("name")
                    pt = p.child_by_field_name("type")
                    arg_ids.append(
                        self._ts_add_arg(
                            self._node_text(pn, source) if pn else "arg",
                            self._node_text(pt, source) if pt else None,
                        )
                    )
        out = []
        rt = node.child_by_field_name("return_type")
        if rt is not None:
            out = [self._ts_add_output(self._node_text(rt, source))]
        return self._ts_add_function(file_id, name, arg_ids, out, class_id=class_id)

    def _sc_parents(self, node, name, source: bytes):
        parent_ids = []
        skip = ("class_parameters", "template_body", "type_parameters", "identifier")

        def rec(n):
            for c in n.children:
                if c.type in skip:
                    continue
                if c.type == "type_identifier":
                    nm = self._node_text(c, source)
                    if nm != name and nm in self._class_registry:
                        pid = self._class_registry[nm]
                        if pid not in parent_ids:
                            parent_ids.append(pid)
                else:
                    rec(c)

        rec(node)
        return parent_ids

    def _sc_attr(self, node, source: bytes):
        pat = node.child_by_field_name("pattern") or node.child_by_field_name("name")
        name = None
        if pat is not None:
            name = self._node_text(pat, source)
        else:
            ident = self._child_of(node, "identifier")
            name = self._node_text(ident, source) if ident else None
        t = node.child_by_field_name("type")
        return [
            self._ts_add_arg(name or "attr", self._node_text(t, source) if t else None)
        ]

    def _sc_type(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        name = self._node_text(name_node, source)
        cls_id = self._class_registry.get(name, self._class_counter)
        parent_ids = self._sc_parents(node, name, source)
        method_ids, attr_ids = [], []
        cps = node.child_by_field_name("class_parameters") or self._child_of(
            node, "class_parameters"
        )
        if cps is not None:
            for p in cps.named_children:
                if p.type in ("class_parameter", "parameter"):
                    pn = p.child_by_field_name("name")
                    pt = p.child_by_field_name("type")
                    attr_ids.append(
                        self._ts_add_arg(
                            self._node_text(pn, source) if pn else "param",
                            self._node_text(pt, source) if pt else None,
                        )
                    )
        body = node.child_by_field_name("body") or self._child_of(node, "template_body")
        if body is not None:
            for m in body.named_children:
                if m.type in ("function_definition", "function_declaration"):
                    method_ids.append(self._sc_function(file_id, m, source, cls_id))
                elif m.type in self._VAL_DECLS:
                    attr_ids.extend(self._sc_attr(m, source))
        self._ts_add_class(
            file_id,
            name,
            description=f"scala {node.type.replace('_definition', '')}",
            parent_ids=parent_ids,
            method_ids=method_ids,
            attr_ids=attr_ids,
        )
