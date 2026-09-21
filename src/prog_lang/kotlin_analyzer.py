# Auto-extracted from code_analyzer.py (verbatim class body).
from .tree_sitter_base import BaseTreeSitterAnalyzer


class KotlinAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep Kotlin parsing integrated with kotlin.reflect (KClass). Extracts import
    headers, top-level val/var (variables), class/object declarations (classes)
    with delegation supertypes, primary-constructor `val`/`var` params and body
    properties (attributes), member functions (methods), and top-level functions.
    """

    _TYPE_DECLS = ("class_declaration", "object_declaration")
    _KT_TYPES = ("user_type", "nullable_type", "function_type")

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="kotlin",
            extensions=[".kt", ".kts"],
            introspection_source="kotlin.reflect.KClass + java.lang.reflect Interop",
            **kwargs,
        )

    # This grammar names things `identifier` (not simple_identifier), imports as
    # `import`, supertypes under `delegation_specifiers`; some bodies parse under
    # ERROR recovery nodes, which are transparently unwrapped below.
    _NAME_LEAVES = ("identifier", "type_identifier", "simple_identifier")

    def _kt_name_node(self, node):
        return self._child_of(node, *self._NAME_LEAVES)

    def _kt_deep(self, node, typ):
        if node.type == typ:
            return node
        for c in node.children:
            r = self._kt_deep(c, typ)
            if r is not None:
                return r
        return None

    def _kt_members(self, body):
        """Body members, unwrapping ERROR recovery wrappers this grammar emits."""
        for m in body.named_children:
            if m.type == "ERROR":
                for mm in m.named_children:
                    yield mm
            else:
                yield m

    def _register_types(self, root_node, source: bytes):
        self._kt_register(root_node, source)

    def _kt_register(self, container, source: bytes):
        for child in container.children:
            if child.type in self._TYPE_DECLS:
                n = self._kt_name_node(child)
                if n is not None:
                    self._ts_register_class(self._node_text(n, source))
                body = self._child_of(child, "class_body", "enum_class_body")
                if body is not None:
                    self._kt_register(body, source)
            elif child.type == "ERROR":
                self._kt_register(child, source)

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._kt_walk(file_id, root_node, source, class_id=None)

    def _kt_walk(self, file_id, container, source, class_id, in_error=False):
        for child in container.children:
            t = child.type
            if t in ("import", "import_header"):
                self._kt_import(file_id, child, source)
            elif t == "property_declaration":
                if class_id is None:
                    self._kt_property_var(file_id, child, source)
            elif t in self._TYPE_DECLS:
                self._kt_type(file_id, child, source)
            elif t == "function_declaration":
                # Inside a recovery node a `function_declaration` is usually an
                # interface/abstract member the grammar failed to attach to its
                # owner; don't surface it as a spurious top-level function.
                if not in_error:
                    self._kt_function(file_id, child, source, class_id)
            elif t == "ERROR":
                # This grammar frequently collapses trailing top-level
                # declarations (interfaces especially) into a single ERROR
                # recovery node; walk into it to salvage real declarations.
                self._kt_walk(file_id, child, source, class_id, in_error=True)

    def _kt_import(self, file_id, node, source: bytes):
        parts = [
            c for c in node.children if c.type in ("qualified_identifier", "identifier")
        ]
        if not parts:
            return
        target = self._node_text(parts[0], source)
        alias = self._node_text(parts[1], source) if len(parts) > 1 else None
        self._ts_add_import(file_id, target.split(".")[-1], target, alias)

    def _kt_var_name(self, node, source: bytes):
        vd = self._child_of(node, "variable_declaration")
        if vd is not None:
            n = self._kt_name_node(vd)
            if n is not None:
                return n
        return self._kt_name_node(node)

    def _kt_property_var(self, file_id, node, source: bytes):
        n = self._kt_var_name(node, source)
        self._ts_add_variable(
            file_id, self._node_text(n, source) if n else "var", None, scope="module"
        )

    def _kt_class_prop(self, node, source: bytes):
        vd = self._child_of(node, "variable_declaration") or node
        n = self._kt_name_node(vd)
        t = self._child_of(vd, *self._KT_TYPES)
        return [
            self._ts_add_arg(
                self._node_text(n, source) if n else "prop",
                self._node_text(t, source) if t else None,
            )
        ]

    def _kt_super_name(self, ds, source: bytes):
        ut = self._kt_deep(ds, "user_type")
        if ut is None:
            return None
        idn = self._child_of(ut, "identifier", "type_identifier")
        if idn is not None:
            return self._node_text(idn, source)
        return self._node_text(ut, source).split("<")[0].split(".")[-1].strip()

    def _kt_bases(self, node, source: bytes):
        parent_ids = []
        for cont in self._children_of(node, "delegation_specifiers"):
            for ds in self._children_of(cont, "delegation_specifier"):
                nm = self._kt_super_name(ds, source)
                if nm and nm in self._class_registry:
                    parent_ids.append(self._class_registry[nm])
        return parent_ids

    def _kt_return_type(self, node):
        seen = False
        for c in node.children:
            if c.type == "function_value_parameters":
                seen = True
                continue
            if seen and c.type in self._KT_TYPES:
                return c
        return None

    def _kt_function(self, file_id, node, source: bytes, class_id):
        name_node = self._kt_name_node(node)
        name = self._node_text(name_node, source) if name_node else "fun"
        arg_ids = []
        params = self._child_of(node, "function_value_parameters")
        if params is not None:
            for p in params.named_children:
                if p.type in ("parameter", "class_parameter"):
                    pn = self._kt_name_node(p)
                    pt = self._child_of(p, *self._KT_TYPES)
                    arg_ids.append(
                        self._ts_add_arg(
                            self._node_text(pn, source) if pn else "arg",
                            self._node_text(pt, source) if pt else None,
                        )
                    )
        out = []
        rt = self._kt_return_type(node)
        if rt is not None:
            out = [self._ts_add_output(self._node_text(rt, source))]
        return self._ts_add_function(file_id, name, arg_ids, out, class_id=class_id)

    def _kt_type(self, file_id, node, source: bytes):
        name_node = self._kt_name_node(node)
        if name_node is None:
            return
        name = self._node_text(name_node, source)
        cls_id = self._class_registry.get(name, self._class_counter)
        parent_ids = self._kt_bases(node, source)
        method_ids, attr_ids = [], []
        pc = self._child_of(node, "primary_constructor")
        if pc is not None:
            cps = self._child_of(pc, "class_parameters")
            if cps is not None:
                for p in cps.named_children:
                    if p.type == "class_parameter":
                        pn = self._kt_name_node(p)
                        pt = self._child_of(p, *self._KT_TYPES)
                        attr_ids.append(
                            self._ts_add_arg(
                                self._node_text(pn, source) if pn else "param",
                                self._node_text(pt, source) if pt else None,
                            )
                        )
        body = self._child_of(node, "class_body", "enum_class_body")
        if body is not None:
            for m in self._kt_members(body):
                if m.type == "function_declaration":
                    method_ids.append(self._kt_function(file_id, m, source, cls_id))
                elif m.type == "property_declaration":
                    attr_ids.extend(self._kt_class_prop(m, source))
                elif m.type == "enum_entry":
                    en = self._kt_name_node(m)
                    attr_ids.append(
                        self._ts_add_arg(
                            self._node_text(en, source) if en else "entry", "enum_entry"
                        )
                    )
                elif m.type in self._TYPE_DECLS:
                    self._kt_type(file_id, m, source)
        self._ts_add_class(
            file_id,
            name,
            description=f"kotlin {node.type.replace('_declaration', '')}",
            parent_ids=parent_ids,
            method_ids=method_ids,
            attr_ids=attr_ids,
        )
