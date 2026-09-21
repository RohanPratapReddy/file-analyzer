# Auto-extracted from code_analyzer.py (verbatim class body).
from .tree_sitter_base import BaseTreeSitterAnalyzer


class RubyAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep Ruby parsing integrated with Method#parameters / TracePoint. Extracts
    require/require_relative/load (imports), top-level constant assignments
    (variables), classes (with `<` superclass, methods, and attr_* accessors as
    attributes), modules (as classes), and standalone methods (functions).
    """

    _IMPORT_METHODS = ("require", "require_relative", "load", "autoload")

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="ruby",
            extensions=[".rb", ".rake"],
            introspection_source="Method#parameters + TracePoint + caller_locations",
            **kwargs,
        )

    def _rb_body(self, node):
        b = node.child_by_field_name("body")
        if b is not None:
            return b
        return self._child_of(node, "body_statement")

    def _register_types(self, root_node, source: bytes):
        self._rb_register(root_node, source)

    def _rb_register(self, container, source: bytes):
        for child in container.children:
            if child.type in ("class", "module"):
                n = child.child_by_field_name("name")
                if n:
                    self._ts_register_class(self._node_text(n, source))
                body = self._rb_body(child)
                if body is not None:
                    self._rb_register(body, source)

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._rb_walk(file_id, root_node, source, class_id=None)

    def _rb_walk(self, file_id, container, source, class_id):
        for child in container.children:
            t = child.type
            if t == "call":
                self._rb_call(file_id, child, source)
            elif t == "assignment":
                self._rb_assignment(file_id, child, source, class_id)
            elif t in ("class", "module"):
                self._rb_class(file_id, child, source)
            elif t in ("method", "singleton_method"):
                self._rb_method(file_id, child, source, class_id)

    def _rb_string(self, node, source: bytes):
        sc = self._child_of(node, "string_content")
        if sc is not None:
            return self._node_text(sc, source)
        return self._node_text(node, source).strip("\"'")

    def _rb_call(self, file_id, node, source: bytes):
        m = node.child_by_field_name("method")
        if m is None:
            return
        mname = self._node_text(m, source)
        if mname in self._IMPORT_METHODS:
            args = node.child_by_field_name("arguments")
            target = None
            if args is not None:
                for a in args.named_children:
                    if a.type in ("string", "simple_symbol"):
                        target = self._rb_string(a, source).lstrip(":")
                        break
            if target:
                self._ts_add_import(file_id, target.split("/")[-1], target)

    def _rb_assignment(self, file_id, node, source: bytes, class_id):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None:
            return
        if left.type in (
            "constant",
            "identifier",
            "global_variable",
            "instance_variable",
            "class_variable",
        ):
            self._ts_add_variable(
                file_id,
                self._node_text(left, source),
                self._node_text(right, source) if right else None,
                scope="module" if class_id is None else "class",
            )

    def _rb_param(self, p, source: bytes):
        if p.type == "identifier":
            return self._ts_add_arg(self._node_text(p, source))
        nn = p.child_by_field_name("name")
        default = None
        if p.type == "optional_parameter":
            v = p.child_by_field_name("value")
            default = self._node_text(v, source) if v else None
        return self._ts_add_arg(
            self._node_text(nn, source) if nn else self._node_text(p, source),
            p.type,
            default,
        )

    def _rb_method(self, file_id, node, source: bytes, class_id=None):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "method"
        params = node.child_by_field_name("parameters")
        arg_ids = []
        if params is not None:
            for p in params.named_children:
                arg_ids.append(self._rb_param(p, source))
        return self._ts_add_function(file_id, name, arg_ids, [], class_id=class_id)

    def _rb_class(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        name = self._node_text(name_node, source)
        cls_id = self._class_registry.get(name, self._class_counter)
        parent_ids = []
        sc = node.child_by_field_name("superclass")
        if sc is not None:
            for c in sc.named_children:
                nm = self._node_text(c, source)
                if nm in self._class_registry:
                    parent_ids.append(self._class_registry[nm])
        method_ids, attr_ids = [], []
        body = self._rb_body(node)
        if body is not None:
            for m in body.named_children:
                if m.type in ("method", "singleton_method"):
                    method_ids.append(self._rb_method(file_id, m, source, cls_id))
                elif m.type == "call":
                    mm = m.child_by_field_name("method")
                    if mm is not None and self._node_text(mm, source).startswith(
                        "attr_"
                    ):
                        args = m.child_by_field_name("arguments")
                        if args is not None:
                            for a in args.named_children:
                                if a.type in ("simple_symbol", "symbol"):
                                    attr_ids.append(
                                        self._ts_add_arg(
                                            self._node_text(a, source).lstrip(":"),
                                            "attribute",
                                        )
                                    )
                    else:
                        self._rb_call(file_id, m, source)
                elif m.type in ("class", "module"):
                    self._rb_class(file_id, m, source)
        self._ts_add_class(
            file_id,
            name,
            description=f"ruby {node.type}",
            parent_ids=parent_ids,
            method_ids=method_ids,
            attr_ids=attr_ids,
        )
