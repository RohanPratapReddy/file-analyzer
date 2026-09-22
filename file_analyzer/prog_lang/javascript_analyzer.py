# Auto-extracted from code_analyzer.py (verbatim class body).
from .tree_sitter_base import BaseTreeSitterAnalyzer


class _SingleChild:
    """Tiny adapter so a single AST node can be fed to an ``_extract_entities``
    method that iterates ``root_node.children`` (used to unwrap ``export`` and to
    delegate one node to a superclass extractor)."""

    __slots__ = ("children",)

    def __init__(self, node):
        self.children = [node]


class JavaScriptAnalyzer(BaseTreeSitterAnalyzer):
    """
    Deep JavaScript parsing integrated with Reflect / Object property
    descriptors. Extracts ES-module imports, top-level const/let/var (function
    expressions and arrow functions bound to a name are recorded as functions,
    everything else as variables), standalone functions, and classes with their
    extends chain, methods and fields.
    """

    _FUNC_VALUE_TYPES = (
        "arrow_function",
        "function",
        "function_expression",
        "generator_function",
    )

    def __init__(self, lang_key="javascript", extensions=None, **kwargs):
        super().__init__(
            lang_key=lang_key,
            extensions=extensions or [".js", ".jsx", ".mjs"],
            introspection_source="Reflect + Object.getOwnPropertyDescriptor + console.trace",
            **kwargs,
        )

    def _register_types(self, root_node, source: bytes):
        for child in root_node.children:
            if child.type == "class_declaration":
                name_node = child.child_by_field_name("name")
                if name_node:
                    self._ts_register_class(self._node_text(name_node, source))

    # ---- shared param extraction for JS + TS ----
    def _js_params(self, params_node, source: bytes):
        arg_ids = []
        if not params_node:
            return arg_ids
        for p in params_node.named_children:
            if p.type == "identifier":
                arg_ids.append(self._ts_add_arg(self._node_text(p, source)))
            elif p.type in ("required_parameter", "optional_parameter"):
                pat = p.child_by_field_name("pattern") or p.child_by_field_name("name")
                tnode = p.child_by_field_name("type")
                ttext = (
                    self._node_text(tnode, source).lstrip(":").strip()
                    if tnode
                    else None
                )
                arg_ids.append(
                    self._ts_add_arg(
                        self._node_text(pat, source) if pat else "arg", ttext
                    )
                )
            elif p.type == "assignment_pattern":
                left = p.child_by_field_name("left")
                right = p.child_by_field_name("right")
                arg_ids.append(
                    self._ts_add_arg(
                        self._node_text(left, source) if left else "arg",
                        None,
                        self._node_text(right, source) if right else None,
                    )
                )
            elif p.type in ("rest_pattern", "object_pattern", "array_pattern"):
                arg_ids.append(self._ts_add_arg(self._node_text(p, source)))
        return arg_ids

    def _js_return_type(self, node, source: bytes):
        """TS return type annotation, if present, becomes a single output row."""
        rt = node.child_by_field_name("return_type")
        if rt:
            return [
                self._ts_add_output(self._node_text(rt, source).lstrip(":").strip())
            ]
        return []

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        for child in root_node.children:
            t = child.type
            if t == "import_statement":
                self._js_import(file_id, child, source)
            elif t in ("lexical_declaration", "variable_declaration"):
                self._js_declaration(file_id, child, source)
            elif t == "function_declaration":
                self._js_function(file_id, child, source)
            elif t == "class_declaration":
                self._js_class(file_id, child, source)
            elif t == "export_statement":
                # unwrap `export ...` and process the declaration it wraps
                decl = child.child_by_field_name("declaration")
                if decl is None:
                    for c in child.named_children:
                        if c.type in (
                            "class_declaration",
                            "function_declaration",
                            "lexical_declaration",
                            "variable_declaration",
                        ):
                            decl = c
                            break
                if decl is not None:
                    self._extract_entities(file_id, _SingleChild(decl), source)
                else:
                    self._js_export_default_anon(file_id, child, source)

    def _js_export_default_anon(self, file_id, export_node, source: bytes):
        """`export default <anonymous function/arrow/class>` — the module's
        default entry point (e.g. a k6 VU function, an EdgeWorker handler).
        There is no name to bind, so record it under the name `default`."""
        for c in export_node.named_children:
            if c.type in (
                "function_expression",
                "arrow_function",
                "generator_function",
                "async_function",
            ):
                arg_ids = self._js_params(c.child_by_field_name("parameters"), source)
                out_ids = self._js_return_type(c, source)
                self._ts_add_function(
                    file_id,
                    "default",
                    arg_ids,
                    out_ids,
                    description="default export function",
                )
                return
            if c.type in ("class", "class_expression"):
                self._ts_add_class(
                    file_id, "default", description="default export class"
                )
                return

    def _js_import(self, file_id, node, source: bytes):
        src_node = node.child_by_field_name("source")
        source_str = (
            self._node_text(src_node, source).strip("\"'") if src_node else "module"
        )
        clause = None
        for c in node.named_children:
            if c.type == "import_clause":
                clause = c
                break
        if clause is None:
            self._ts_add_import(file_id, source_str.split("/")[-1], source_str)
            return
        for c in clause.named_children:
            if c.type == "identifier":  # default import
                self._ts_add_import(file_id, self._node_text(c, source), source_str)
            elif c.type == "namespace_import":  # import * as ns
                ident = c.named_children[-1] if c.named_children else None
                self._ts_add_import(
                    file_id,
                    self._node_text(ident, source) if ident else "*",
                    source_str,
                    alias="*",
                )
            elif c.type == "named_imports":
                for spec in c.named_children:
                    if spec.type == "import_specifier":
                        name_n = spec.child_by_field_name("name")
                        alias_n = spec.child_by_field_name("alias")
                        self._ts_add_import(
                            file_id,
                            (
                                self._node_text(alias_n, source)
                                if alias_n
                                else (
                                    self._node_text(name_n, source) if name_n else "?"
                                )
                            ),
                            source_str,
                            alias=self._node_text(alias_n, source) if alias_n else None,
                        )

    def _js_declaration(self, file_id, node, source: bytes):
        for decl in node.named_children:
            if decl.type != "variable_declarator":
                continue
            name_node = decl.child_by_field_name("name")
            name = self._node_text(name_node, source) if name_node else "anon"
            value = decl.child_by_field_name("value")
            if value is not None and value.type in self._FUNC_VALUE_TYPES:
                arg_ids = self._js_params(
                    value.child_by_field_name("parameters"), source
                )
                out_ids = self._js_return_type(value, source)
                self._ts_add_function(file_id, name, arg_ids, out_ids)
            else:
                self._ts_add_variable(
                    file_id,
                    name,
                    self._node_text(value, source) if value else None,
                    scope="module",
                )

    def _js_function(self, file_id, node, source: bytes, class_id=None):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "anonymous"
        arg_ids = self._js_params(node.child_by_field_name("parameters"), source)
        out_ids = self._js_return_type(node, source)
        return self._ts_add_function(file_id, name, arg_ids, out_ids, class_id=class_id)

    def _js_class(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "AnonClass"
        cls_id = self._class_registry.get(name, self._class_counter)

        parent_ids = []
        heritage = None
        for c in node.named_children:
            if c.type == "class_heritage":
                heritage = c
                break
        if heritage is not None:
            for ident in self._collect_heritage_names(heritage, source):
                if ident in self._class_registry:
                    parent_ids.append(self._class_registry[ident])

        method_ids, attr_ids = [], []
        body = node.child_by_field_name("body")
        if body is not None:
            for member in body.named_children:
                if member.type == "method_definition":
                    mname_n = member.child_by_field_name("name")
                    mname = self._node_text(mname_n, source) if mname_n else "method"
                    arg_ids = self._js_params(
                        member.child_by_field_name("parameters"), source
                    )
                    out_ids = self._js_return_type(member, source)
                    method_ids.append(
                        self._ts_add_function(
                            file_id, mname, arg_ids, out_ids, class_id=cls_id
                        )
                    )
                elif member.type in ("field_definition", "public_field_definition"):
                    fn_n = member.child_by_field_name("name")
                    tnode = member.child_by_field_name("type")
                    ttext = (
                        self._node_text(tnode, source).lstrip(":").strip()
                        if tnode
                        else None
                    )
                    attr_ids.append(
                        self._ts_add_arg(
                            self._node_text(fn_n, source) if fn_n else "field", ttext
                        )
                    )

        self._ts_add_class(
            file_id,
            name,
            description=f"{self.lang_key} class",
            parent_ids=parent_ids,
            method_ids=method_ids,
            attr_ids=attr_ids,
        )

    def _collect_heritage_names(self, heritage, source: bytes):
        """extends/implements target names from a class_heritage node (JS + TS)."""
        names = []
        for c in heritage.named_children:
            if c.type in ("extends_clause", "implements_clause"):
                for t in c.named_children:
                    if t.type in ("identifier", "type_identifier", "generic_type"):
                        names.append(self._node_text(t, source).split("<")[0])
            elif c.type in ("identifier", "type_identifier"):
                names.append(self._node_text(c, source))
        return names


class TypeScriptAnalyzer(JavaScriptAnalyzer):
    """
    TypeScript on top of the JS engine: adds interface, type-alias and enum
    declarations, typed parameters and return types, and the extends/implements
    split in class heritage. Integrates reflect-metadata / ts-morph.
    """

    def __init__(self, **kwargs):
        super().__init__(lang_key="typescript", extensions=[".ts", ".tsx"], **kwargs)
        self.introspection_source = (
            "reflect-metadata (design:paramtypes) + ts-morph compile-time AST"
        )

    def _register_types(self, root_node, source: bytes):
        for child in root_node.children:
            self._ts_register_decl(child, source)

    def _ts_register_decl(self, child, source: bytes):
        """Register a type name for stable class_id linkage, unwrapping the
        ambient (`declare ...`) and `export` wrappers that .d.ts files use."""
        t = child.type
        if t in (
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "type_alias_declaration",
            "internal_module",
        ):
            name_node = child.child_by_field_name("name")
            if name_node:
                self._ts_register_class(self._node_text(name_node, source))
        elif t in (
            "ambient_declaration",
            "export_statement",
            "statement_block",
            "expression_statement",
        ):
            for c in child.named_children:
                self._ts_register_decl(c, source)

    def _extract_entities(self, file_id: int, root_node, source: bytes):
        for child in root_node.children:
            t = child.type
            if t == "interface_declaration":
                self._ts_interface(file_id, child, source)
            elif t == "type_alias_declaration":
                name_node = child.child_by_field_name("name")
                if name_node:
                    self._ts_add_class(
                        file_id,
                        self._node_text(name_node, source),
                        description="TypeScript type alias",
                    )
            elif t == "enum_declaration":
                self._ts_enum(file_id, child, source)
            elif t == "ambient_declaration":
                # `declare function/class/namespace/module ...` (.d.ts core):
                # unwrap and re-dispatch each inner declaration.
                for c in child.named_children:
                    self._extract_entities(file_id, _SingleChild(c), source)
            elif t == "function_signature":
                # bodyless `declare function f(...): T;`
                self._ts_function_signature(file_id, child, source)
            elif t in ("internal_module", "module"):
                # `namespace X { ... }` / `declare module "x" { ... }`
                self._ts_namespace(file_id, child, source)
            elif t == "statement_block":
                # `declare global { ... }` augmentation body: recurse in.
                self._extract_entities(file_id, child, source)
            elif t == "expression_statement":
                # a bare `namespace X { ... }` in a block parses as an
                # expression statement wrapping an internal_module.
                for c in child.named_children:
                    if c.type in ("internal_module", "module"):
                        self._ts_namespace(file_id, c, source)
            elif t == "export_statement":
                decl = child.child_by_field_name("declaration")
                if decl is None:
                    for c in child.named_children:
                        if c.type.endswith("_declaration") or c.type in (
                            "function_signature",
                            "internal_module",
                            "module",
                        ):
                            decl = c
                            break
                if decl is not None:
                    self._extract_entities(file_id, _SingleChild(decl), source)
                else:
                    self._js_export_default_anon(file_id, child, source)
            else:
                # imports, const/let/var, function_declaration, class_declaration
                super()._extract_entities(file_id, _SingleChild(child), source)

    def _ts_sig_return(self, node, source: bytes):
        """Return-type of a bodyless signature is a trailing `type_annotation`
        direct child (there is no `return_type` field as on real functions)."""
        for c in node.named_children:
            if c.type == "type_annotation":
                return [
                    self._ts_add_output(self._node_text(c, source).lstrip(":").strip())
                ]
        return []

    def _ts_function_signature(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "declared"
        arg_ids = self._js_params(node.child_by_field_name("parameters"), source)
        out_ids = self._ts_sig_return(node, source)
        self._ts_add_function(file_id, name, arg_ids, out_ids)

    def _ts_namespace(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else None
        body = None
        for c in node.named_children:
            if name is None and c.type == "string":
                name = self._node_text(c, source)
            elif c.type == "statement_block":
                body = c
        if name:
            name = name.strip("\"'")  # `declare module "x"` -> x
        if name:
            self._ts_add_class(file_id, name, description="TypeScript namespace")
        if body is not None:
            # nested declarations (functions, consts, further namespaces) become
            # module-scoped rows — the container itself is already recorded above.
            self._extract_entities(file_id, body, source)

    def _ts_interface(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "AnonInterface"
        cls_id = self._class_registry.get(name, self._class_counter)
        method_ids, attr_ids = [], []
        body = node.child_by_field_name("body")
        if body is not None:
            for member in body.named_children:
                if member.type == "method_signature":
                    mname_n = member.child_by_field_name("name")
                    mname = self._node_text(mname_n, source) if mname_n else "method"
                    arg_ids = self._js_params(
                        member.child_by_field_name("parameters"), source
                    )
                    out_ids = self._js_return_type(member, source)
                    method_ids.append(
                        self._ts_add_function(
                            file_id, mname, arg_ids, out_ids, class_id=cls_id
                        )
                    )
                elif member.type == "property_signature":
                    fn_n = member.child_by_field_name("name")
                    tnode = member.child_by_field_name("type")
                    ttext = (
                        self._node_text(tnode, source).lstrip(":").strip()
                        if tnode
                        else None
                    )
                    attr_ids.append(
                        self._ts_add_arg(
                            self._node_text(fn_n, source) if fn_n else "prop", ttext
                        )
                    )
        self._ts_add_class(
            file_id,
            name,
            description="TypeScript interface",
            method_ids=method_ids,
            attr_ids=attr_ids,
        )

    def _ts_enum(self, file_id, node, source: bytes):
        name_node = node.child_by_field_name("name")
        name = self._node_text(name_node, source) if name_node else "AnonEnum"
        attr_ids = []
        body = node.child_by_field_name("body")
        if body is not None:
            for member in body.named_children:
                if member.type in ("property_identifier", "enum_assignment"):
                    if member.type == "enum_assignment":
                        nm = member.child_by_field_name("name")
                        label = (
                            self._node_text(nm, source)
                            if nm
                            else self._node_text(member, source)
                        )
                    else:
                        label = self._node_text(member, source)
                    attr_ids.append(self._ts_add_arg(label, "EnumMember"))
        self._ts_add_class(
            file_id, name, description="TypeScript enum", attr_ids=attr_ids
        )
