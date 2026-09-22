# Auto-extracted from code_analyzer.py (verbatim class body).
from .tree_sitter_base import BaseTreeSitterAnalyzer


class ElixirAnalyzer(BaseTreeSitterAnalyzer):
    """
    Elixir parsing integrated with Module.__info__/1. Elixir's grammar is
    macro-uniform (nearly everything is a `call`), so this walks calls by their
    leading identifier: `defmodule` → class (its `def`/`defp` bodies become
    methods, `@attrs` become attributes), `import`/`alias`/`require`/`use` →
    imports, and top-level `def`/`defp` → functions.
    """

    _DEFMODULE = ("defmodule",)
    _DEF = ("def", "defp", "defmacro", "defmacrop")
    _IMPORTS = ("import", "alias", "require", "use")

    def __init__(self, **kwargs):
        super().__init__(
            lang_key="elixir",
            extensions=[".ex", ".exs"],
            introspection_source="Module.__info__/1 + Code.fetch_docs/1 + Process.info/2",
            **kwargs,
        )

    def _ex_call_name(self, call, source: bytes):
        if call.child_count and call.children[0].type == "identifier":
            return self._node_text(call.children[0], source)
        return None

    def _ex_args(self, call):
        return self._child_of(call, "arguments")

    def _ex_do_block(self, call):
        return self._child_of(call, "do_block")

    def _ex_module_name(self, call, source: bytes):
        args = self._ex_args(call)
        a = self._child_of(args, "alias") if args is not None else None
        if a is None:
            a = self._child_of(call, "alias")
        return self._node_text(a, source) if a is not None else None

    def _register_types(self, root_node, source: bytes):
        self._ex_walk_register(root_node, source)

    def _ex_walk_register(self, node, source: bytes):
        for child in node.children:
            if (
                child.type == "call"
                and self._ex_call_name(child, source) in self._DEFMODULE
            ):
                mod = self._ex_module_name(child, source)
                if mod:
                    self._ts_register_class(mod)
            self._ex_walk_register(child, source)

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        self._ex_walk(file_id, root_node, source, class_id=None)

    def _ex_walk(self, file_id, node, source: bytes, class_id):
        for child in node.children:
            if child.type == "call":
                self._ex_call(file_id, child, source, class_id)
            elif child.type == "unary_operator":
                self._ex_attr(file_id, child, source, class_id)
            else:
                self._ex_walk(file_id, child, source, class_id)

    def _ex_call(self, file_id, call, source: bytes, class_id):
        name = self._ex_call_name(call, source)
        if name in self._DEFMODULE:
            mod = self._ex_module_name(call, source)
            cls_id = (
                self._class_registry.get(mod, self._class_counter)
                if mod
                else self._class_counter
            )
            method_ids, attr_ids = [], []
            do = self._ex_do_block(call)
            if do is not None:
                for c in do.children:
                    self._ex_collect(file_id, c, source, cls_id, method_ids, attr_ids)
            if mod:
                self._ts_add_class(
                    file_id,
                    mod,
                    description="elixir module",
                    method_ids=method_ids,
                    attr_ids=attr_ids,
                )
            return
        if name in self._DEF:
            self._ex_def(file_id, call, source, class_id)
            return
        if name in self._IMPORTS:
            self._ex_import(file_id, call, source)
            return
        do = self._ex_do_block(call)
        if do is not None:
            self._ex_walk(file_id, do, source, class_id)

    def _ex_collect(self, file_id, node, source: bytes, cls_id, method_ids, attr_ids):
        if node.type == "call":
            nm = self._ex_call_name(node, source)
            if nm in self._DEF:
                method_ids.append(self._ex_def(file_id, node, source, cls_id))
            elif nm in self._IMPORTS:
                self._ex_import(file_id, node, source)
            elif nm in self._DEFMODULE:
                self._ex_call(file_id, node, source, cls_id)
            else:
                do = self._ex_do_block(node)
                if do is not None:
                    for c in do.children:
                        self._ex_collect(
                            file_id, c, source, cls_id, method_ids, attr_ids
                        )
        elif node.type == "unary_operator":
            aid = self._ex_attr(file_id, node, source, cls_id, as_attr=True)
            if aid is not None:
                attr_ids.append(aid)
        else:
            for c in node.children:
                self._ex_collect(file_id, c, source, cls_id, method_ids, attr_ids)

    def _ex_head_params(self, head, source: bytes):
        """Given a `def` head (a `call` like `add(a, b)`), return (name, arg_ids)."""
        fname = self._ex_call_name(head, source) or "func"
        arg_ids = []
        hargs = self._ex_args(head)
        if hargs is not None:
            for p in hargs.named_children:
                arg_ids.append(self._ts_add_arg(self._node_text(p, source), p.type))
        return fname, arg_ids

    def _ex_def(self, file_id, call, source: bytes, class_id):
        args = self._ex_args(call)
        head = (
            args.named_children[0]
            if (args is not None and args.named_children)
            else None
        )
        fname, arg_ids = "func", []
        if head is not None:
            if head.type == "call":
                fname, arg_ids = self._ex_head_params(head, source)
            elif head.type == "identifier":
                fname = self._node_text(head, source)
            elif head.type == "binary_operator":
                left = head.child_by_field_name("left") or (
                    head.named_children[0] if head.named_children else None
                )
                if left is not None and left.type == "call":
                    fname, arg_ids = self._ex_head_params(left, source)
        return self._ts_add_function(file_id, fname, arg_ids, [], class_id=class_id)

    def _ex_import(self, file_id, call, source: bytes):
        args = self._ex_args(call)
        if args is not None and args.named_children:
            target = self._node_text(args.named_children[0], source)
            if target:
                self._ts_add_import(file_id, target.split(".")[-1], target)

    def _ex_attr(self, file_id, node, source: bytes, class_id, as_attr=False):
        if not self._node_text(node, source).startswith("@"):
            return None
        operand = None
        for c in node.children:
            if c.is_named and c.type != "@":
                operand = c
                break
        aname, aval = None, None
        if operand is not None:
            if operand.type == "call":
                aname = self._ex_call_name(operand, source)
                oa = self._ex_args(operand)
                if oa is not None and oa.named_children:
                    aval = self._node_text(oa.named_children[0], source)
            elif operand.type == "identifier":
                aname = self._node_text(operand, source)
        if aname is None:
            return None
        if as_attr:
            return self._ts_add_arg(aname, "module_attribute", aval)
        self._ts_add_variable(file_id, "@" + aname, aval, scope="module_attribute")
        return None
