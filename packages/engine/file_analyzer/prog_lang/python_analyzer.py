# Auto-extracted from code_analyzer.py (verbatim class body).
import ast
import dis
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .base_code_analyzer import BaseCodeAnalyzer


class PythonCodeAnalyzer(BaseCodeAnalyzer):
    """
    Parses Python source files using AST. Ingests symbols from imports, extracts
    docstrings, synthesizes pseudocode for forward/backward passes, extracts tensor
    members, and captures introspection via `dis` (bytecode), `inspect`, and `traceback`.
    """

    def __init__(self, **kwargs):
        super().__init__(language_name="python", **kwargs)

    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        parsed_trees = {}
        for file_id, file_path in enumerate(self.file_paths, start=1):
            if not file_path.exists() or file_path.suffix != ".py":
                continue
            try:
                code_text = file_path.read_text(encoding="utf-8")
                tree = ast.parse(code_text, filename=file_path.name)
                parsed_trees[file_id] = (file_path, tree, code_text)
            except Exception as err:
                print(f"Failed to parse {file_path}: {err}")

        # Pass 1: Index Defined Classes
        for file_id, (_, tree, _) in parsed_trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    self._class_registry[node.name] = self._class_counter
                    self._class_counter += 1

        # Pass 2: Extract Definitions, Imports & Disassembly
        for file_id, (file_path, tree, code_text) in parsed_trees.items():
            self._process_file_ast(file_id, file_path, tree, code_text)

        self._build_temp_kind_details_table()
        self.export()
        return self.get_tables()

    def _process_file_ast(
        self, file_id: int, file_path: Path, tree: ast.AST, code_text: str
    ):
        # Module-level introspection (bytecode disassembly).
        try:
            compiled_code = compile(code_text, str(file_path), "exec")
            disassembly = dis.Bytecode(compiled_code).dis()
        except Exception:
            disassembly = None

        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=file_id,
            entity_type="module",
            inspection_source="inspect + dis + traceback",
            bytecode_or_ast_dump=disassembly,
            structural_properties={
                "file": str(file_path),
                "line_count": len(code_text.splitlines()),
            },
        )

        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._handle_import(file_id, node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._handle_variable(file_id, node, scope="module")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._handle_function(file_id, node, code_text, parent_class_id=None)
            elif isinstance(node, ast.ClassDef):
                self._handle_class(file_id, node, code_text)

    def _handle_import(self, file_id: int, node: Union[ast.Import, ast.ImportFrom]):
        """
        Extracts imports and dynamically injects them into functions,
        classes, or variables tables according to naming heuristics.
        """
        imported_symbols = []
        source_module = ""

        # `import x` / `import x.y as z` binds a MODULE object; `from x import y`
        # binds a symbol (class / function / constant) out of a module.
        is_module_import = isinstance(node, ast.Import)

        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_symbols.append((alias.asname or alias.name, alias.name, None))
                source_module = alias.name
        elif isinstance(node, ast.ImportFrom):
            source_module = node.module or "." * node.level
            for alias in node.names:
                imported_symbols.append(
                    (
                        alias.asname or alias.name,
                        f"{source_module}.{alias.name}",
                        alias.asname,
                    )
                )

        for name, src, alias in imported_symbols:
            import_id = self._import_counter
            self._import_counter += 1
            self.imports_table.append(
                {
                    "import_id": import_id,
                    "import_name": name,
                    "import_source": src,
                    "alias": alias,
                }
            )
            self._record_symbol(file_id, "import", import_id)

            # Projection into classes, functions, or module variables.
            # `import x` binds a module object -> project as a module-bound
            # variable, never a callable. A `from`-imported name whose class is
            # DEFINED in this run is a class regardless of casing; otherwise fall
            # back to a first-letter naming heuristic.
            known_class = (not is_module_import) and name in self._class_registry
            if not is_module_import and (
                known_class or (name[0].isupper() and not name.isupper())
            ):
                # Class projection
                cls_id = self._class_counter
                self._class_counter += 1
                # Do not clobber a class DEFINED in this run (registered in pass 1);
                # the imported symbol is projected as its own distinct row.
                self._class_registry.setdefault(name, cls_id)
                self.classes_table.append(
                    {
                        "class_id": cls_id,
                        "class_name": name,
                        "class_description": f"Imported external class from `{src}`",
                        "parent_class_ids": [],
                        "method_ids": [],
                        "args_ids": [],
                        "attr_ids": [],
                        "tensor_member_ids": [],
                        "is_imported": True,
                        "source_import_id": import_id,
                    }
                )
                self._record_symbol(file_id, "class/struct/interface", cls_id)

            elif (not is_module_import) and name.islower() and not name.isupper():
                # Function projection
                fn_id = self._func_counter
                self._func_counter += 1
                self.functions_table.append(
                    {
                        "function_id": fn_id,
                        "function_name": name,
                        "args_ids": [],
                        "function_outputs_ids": [],
                        "class_id": None,
                        "function_description": f"Imported callable/subroutine from `{src}`",
                        "function_forward_pass": f"```pseudocode\n// Delegated call to external runtime: {src}\nRESULT = EXECUTE({name}, ARGS...)\nRETURN RESULT\n```",
                        "function_backward_pass": f"```pseudocode\n// Upstream Autograd dispatch\nIF HAS_GRAD({name}):\n    INCOMING_GRAD = BACKPROP(UPSTREAM_GRAD)\n```",
                        "is_imported": True,
                        "source_import_id": import_id,
                    }
                )
                self._record_symbol(file_id, "function", fn_id)

            else:
                # Variable/Constant projection
                var_id = self._var_counter
                self._var_counter += 1
                self.variables_table.append(
                    {
                        "variable_id": var_id,
                        "variable_name": name,
                        "variable_value": (
                            f"Imported module `{src}`"
                            if is_module_import
                            else f"Imported from {src}"
                        ),
                        "scope": "imported_module" if is_module_import else "imported",
                        "is_imported": True,
                        "source_import_id": import_id,
                    }
                )
                self._record_symbol(file_id, "variable", var_id)

    def _handle_variable(
        self, file_id: int, node: Union[ast.Assign, ast.AnnAssign], scope: str
    ):
        val_str = self._unparse_node(node.value) if node.value else None
        target_names = []

        if isinstance(node, ast.Assign):
            for target in node.targets:
                target_names.append(self._unparse_node(target))
        elif isinstance(node, ast.AnnAssign):
            target_names.append(self._unparse_node(node.target))

        for name in target_names:
            var_id = self._var_counter
            self._var_counter += 1
            self.variables_table.append(
                {
                    "variable_id": var_id,
                    "variable_name": name,
                    "variable_value": val_str,
                    "scope": scope,
                    "is_imported": False,
                    "source_import_id": None,
                }
            )
            self._record_symbol(file_id, "variable", var_id)

    def _handle_function(
        self,
        file_id: int,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        code_text: str,
        parent_class_id: Optional[int],
    ) -> int:
        func_id = self._func_counter
        self._func_counter += 1

        arg_ids = self._extract_function_args(node.args)
        output_ids = self._extract_function_outputs(node)
        docstring = ast.get_docstring(node)

        # Synthesize Forward & Backward Passes
        forward_pass = self._synthesize_forward_pass(node)
        backward_pass = self._synthesize_backward_pass(node)

        self.functions_table.append(
            {
                "function_id": func_id,
                "function_name": node.name,
                "args_ids": arg_ids,
                "function_outputs_ids": output_ids,
                "class_id": parent_class_id,
                "function_description": docstring,
                "function_forward_pass": forward_pass,
                "function_backward_pass": backward_pass,
                "is_imported": False,
                "source_import_id": None,
            }
        )
        self._record_symbol(file_id, "function", func_id)

        # Disassemble function subtree for introspection metadata
        func_bytecode = None
        try:
            segment = ast.get_source_segment(code_text, node)
            if segment:
                compiled = compile(segment, "<string>", "exec")
                func_bytecode = dis.Bytecode(compiled).dis()
        except Exception:
            pass

        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=func_id,
            entity_type="function",
            inspection_source="inspect.signature + dis.disassemble",
            bytecode_or_ast_dump=func_bytecode,
            runtime_decorators_or_attributes={
                "decorators": [self._unparse_node(d) for d in node.decorator_list]
            },
        )
        return func_id

    def _handle_class(self, file_id: int, node: ast.ClassDef, code_text: str):
        class_id = self._class_registry.get(node.name, self._class_counter)
        self._class_counter = max(self._class_counter + 1, class_id + 1)
        class_docstring = ast.get_docstring(node)

        parent_class_ids = []
        for base in node.bases:
            base_name = self._unparse_node(base)
            if base_name in self._class_registry:
                parent_class_ids.append(self._class_registry[base_name])

        method_ids, constructor_arg_ids, attr_ids, tensor_member_ids = [], [], [], []

        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                m_id = self._handle_function(
                    file_id, item, code_text, parent_class_id=class_id
                )
                method_ids.append(m_id)

                if item.name == "__init__":
                    constructor_arg_ids = [
                        aid
                        for aid in self._extract_function_args(item.args)
                        if aid not in constructor_arg_ids
                    ]

                for sub_node in ast.walk(item):
                    if isinstance(sub_node, ast.Assign):
                        self._inspect_class_assignment(
                            sub_node, attr_ids, tensor_member_ids, file_id
                        )

            elif isinstance(item, (ast.Assign, ast.AnnAssign)):
                self._handle_variable(file_id, item, scope=f"class:{node.name}")

        self.classes_table.append(
            {
                "class_id": class_id,
                "class_name": node.name,
                "class_description": class_docstring,
                "parent_class_ids": parent_class_ids,
                "method_ids": method_ids,
                "args_ids": constructor_arg_ids,
                "attr_ids": attr_ids,
                "tensor_member_ids": tensor_member_ids,
                "is_imported": False,
                "source_import_id": None,
            }
        )
        self._record_symbol(file_id, "class/struct/interface", class_id)

        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=class_id,
            entity_type="class",
            inspection_source="inspect.getmro + Object.getPrototypeOf emulation",
            structural_properties={
                "bases": [self._unparse_node(b) for b in node.bases]
            },
        )

    # ================= Pass Synthesizers =================

    def _synthesize_forward_pass(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> str:
        """Synthesizes step-by-step algorithmic pseudocode of the function's forward execution."""
        lines = [f"// Pseudocode for: {node.name}"]
        arg_names = [a.arg for a in node.args.args]
        lines.append(f"INPUT ({', '.join(arg_names)})")

        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                targets = ", ".join(self._unparse_node(t) for t in stmt.targets)
                val = self._unparse_node(stmt.value)
                lines.append(f"  {targets} = COMPUTE({val})")
            elif isinstance(stmt, ast.Return):
                ret = self._unparse_node(stmt.value) if stmt.value else "VOID"
                lines.append(f"  RETURN {ret}")
            elif isinstance(stmt, ast.If):
                test = self._unparse_node(stmt.test)
                lines.append(f"  IF ({test}) THEN EVALUATE_BRANCH")
            elif isinstance(stmt, (ast.For, ast.While)):
                lines.append(f"  LOOP OVER SEQUENCE")

        if not any(isinstance(s, ast.Return) for s in node.body):
            lines.append("  RETURN None")

        body_str = "\n".join(lines)
        return f"```pseudocode\n{body_str}\n```"

    def _synthesize_backward_pass(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> str:
        """
        Synthesizes reverse automatic differentiation, tracking how upstream gradients
        accumulate into parameters/tensors and update via an optimizer step.
        """
        lines = [f"// Backward Pass & Gradient Tracking: {node.name}"]
        lines.append("RECEIVE dLoss_dOutput (Incoming upstream gradient)")

        assigned_targets = []
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    t_name = self._unparse_node(target)
                    assigned_targets.append(t_name)

        if assigned_targets:
            for target in reversed(assigned_targets):
                lines.append(
                    f"  dLoss_d_{target} = BACKPROP(dLoss_dOutput, USING Jacobian_{target})"
                )
                if (
                    "weight" in target.lower()
                    or "param" in target.lower()
                    or "bias" in target.lower()
                    or "self." in target
                ):
                    lines.append(
                        f"    --> ACCUMULATE GRADIENT: {target}.grad += dLoss_d_{target}"
                    )
                    lines.append(
                        f"    --> OPTIMIZER STEP: {target} = {target} - LearningRate * {target}.grad"
                    )
        else:
            lines.append("  PASS THROUGH: dLoss_dInput = IDENTITY(dLoss_dOutput)")

        lines.append("EMIT dLoss_dInput TO ANTECEDENT LAYERS")
        body_str = "\n".join(lines)
        return f"```pseudocode\n{body_str}\n```"

    # ================= Argument & Attribute Extractors =================

    def _extract_function_args(self, args_node: ast.arguments) -> List[int]:
        ids = []
        defaults_offset = len(args_node.args) - len(args_node.defaults)

        for i, arg in enumerate(args_node.args):
            arg_name = arg.arg
            if arg_name == "self":
                continue

            arg_type = self._unparse_node(arg.annotation) if arg.annotation else "Any"
            default_val = None
            if i >= defaults_offset:
                default_val = self._unparse_node(
                    args_node.defaults[i - defaults_offset]
                )

            arg_id = self._arg_counter
            self._arg_counter += 1

            self.args_table.append(
                {
                    "args_id": arg_id,
                    "args_name": arg_name,
                    "args_type": arg_type,
                    "default_value": default_val,
                    "permitted_values": None,
                }
            )
            ids.append(arg_id)
        return ids

    def _extract_function_outputs(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> List[int]:
        ids = []
        return_type = self._unparse_node(node.returns) if node.returns else None

        returns_encountered = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                returns_encountered.append(self._unparse_node(child.value))

        if return_type or returns_encountered:
            out_id = self._output_counter
            self._output_counter += 1
            self.outputs_table.append(
                {
                    "output_id": out_id,
                    "output_type": return_type or "Inferred",
                    "description": (
                        ", ".join(returns_encountered) if returns_encountered else None
                    ),
                }
            )
            ids.append(out_id)
        return ids

    def _inspect_class_assignment(
        self,
        node: ast.Assign,
        attr_ids: List[int],
        tensor_member_ids: List[int],
        file_id: int,
    ):
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                attr_name = target.attr
                val_repr = self._unparse_node(node.value)
                lower_val = val_repr.lower()

                is_tensor_member = any(
                    term in lower_val
                    for term in [
                        "parameter",
                        "buffer",
                        "weight",
                        "bias",
                        "torch.tensor",
                        "tf.variable",
                    ]
                )

                if is_tensor_member:
                    member_id = self._member_counter
                    self._member_counter += 1
                    kind = (
                        "parameter"
                        if "parameter" in lower_val
                        else ("buffer" if "buffer" in lower_val else "weight/bias")
                    )
                    self.tensor_members_table.append(
                        {
                            "member_id": member_id,
                            "kind": kind,
                            "name": attr_name,
                            "count": None,
                            "shape": None,
                        }
                    )
                    tensor_member_ids.append(member_id)
                    self._record_symbol(file_id, "tensor_member/field", member_id)
                else:
                    arg_id = self._arg_counter
                    self._arg_counter += 1
                    self.args_table.append(
                        {
                            "args_id": arg_id,
                            "args_name": attr_name,
                            "args_type": "Attribute",
                            "default_value": val_repr,
                            "permitted_values": None,
                        }
                    )
                    attr_ids.append(arg_id)

    @staticmethod
    def _unparse_node(node: Optional[ast.AST]) -> str:
        if node is None:
            return ""
        try:
            return ast.unparse(node)
        except AttributeError:
            return ""
