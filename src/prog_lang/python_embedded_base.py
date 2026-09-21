# Shared base for Python-embedded DSLs (Cirq/pyQuil/PennyLane/Triton/Dagster/
# Luigi/Prefect/Locust ...).  These "languages" are ordinary, importable Python
# source that uses a domain framework; the *syntax* is Python, so the honest
# analyzer is the AST-based `PythonCodeAnalyzer`.  The only differences from a
# plain `.py` file are (a) the on-disk extension and (b) which decorators / base
# classes carry domain meaning.  This base adds both, mirroring how
# `regex_base.RegexCodeAnalyzer` and `tree_sitter_base` serve their families:
#
#   * suffix-flexible `analyze()` keyed off the subclass `EXTENSIONS` tuple
#     (the parent hard-requires ``.py``), and
#   * a `_dsl_enrich(file_id, tree, code_text)` hook each subclass overrides to
#     record framework-specific entry points (decorated kernels, task/flow/op
#     definitions, framework base-class subclasses) as introspection metadata.
#
# The full class/function/import/argument extraction is inherited unchanged, so
# every construct a real Cirq/Luigi/... program contains is captured for free;
# `_dsl_enrich` only *adds* domain tags, it never replaces the base pass.
import ast
from typing import Any, Dict, List

from .python_analyzer import PythonCodeAnalyzer


class PythonEmbeddedAnalyzer(PythonCodeAnalyzer):
    LANG_KEY = "python-embedded"
    EXTENSIONS = ()  # overridden per language
    DSL_DECORATORS = ()  # decorator roots that mark a domain entry point
    DSL_BASECLASSES = ()  # base-class roots that mark a domain object

    def __init__(self, **kwargs):
        # PythonCodeAnalyzer.__init__ pins language_name="python"; re-pin it to
        # this DSL so introspection rows are attributed correctly.
        super().__init__(**kwargs)
        self.language_name = self.LANG_KEY
        # per-instance, mutable, like the regex analyzers' `self.extensions`
        self.extensions = list(self.EXTENSIONS)
        # class_ids already handed out by _handle_class, so a second file that
        # defines a same-named class gets a fresh id instead of colliding.
        self._used_class_ids = set()

    def _handle_class(self, file_id, node, code_text):
        # PythonCodeAnalyzer keys its class registry by NAME, so two files that
        # each define e.g. `class Config:` would both resolve to the one
        # registered id and produce a duplicate class_id PK.  Reserve a unique
        # id per definition here (the parent then reads it back from the
        # registry and threads it into this class's methods correctly).
        reg_id = self._class_registry.get(node.name)
        if reg_id is None or reg_id in self._used_class_ids:
            reg_id = self._class_counter
            self._class_counter += 1
        self._used_class_ids.add(reg_id)
        self._class_registry[node.name] = reg_id
        super()._handle_class(file_id, node, code_text)

    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        parsed_trees = {}
        exts = {e.lower() for e in self.extensions}
        for file_id, file_path in enumerate(self.file_paths, start=1):
            if not file_path.exists() or file_path.suffix.lower() not in exts:
                continue
            try:
                code_text = file_path.read_text(encoding="utf-8")
                tree = ast.parse(code_text, filename=file_path.name)
                parsed_trees[file_id] = (file_path, tree, code_text)
            except Exception as err:
                print(f"Failed to parse {file_path}: {err}")

        # Pass 1: index defined classes (same as the parent).
        for file_id, (_, tree, _) in parsed_trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    self._class_registry[node.name] = self._class_counter
                    self._class_counter += 1

        # Pass 2: full extraction, then per-language DSL enrichment.
        for file_id, (file_path, tree, code_text) in parsed_trees.items():
            self._process_file_ast(file_id, file_path, tree, code_text)
            self._dsl_enrich(file_id, tree, code_text)

        self._build_temp_kind_details_table()
        self.export()
        return self.get_tables()

    # ---- helpers shared by the concrete DSL subclasses -----------------

    @staticmethod
    def _decorator_root(dec: ast.AST) -> str:
        """Left-most dotted name of a decorator, e.g. ``triton.jit`` or
        ``app.task`` -> the head token used to match DSL_DECORATORS."""
        node = dec
        if isinstance(node, ast.Call):
            node = node.func
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        parts.reverse()
        return ".".join(parts)

    @staticmethod
    def _base_root(base: ast.AST) -> str:
        node = base
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        parts.reverse()
        return ".".join(parts)

    def _dsl_tag(self, file_id: int, name: str, role: str, extra=None):
        """Record a domain-specific entry point as introspection metadata,
        anchored to the file (entity_id=file_id keeps it join-safe)."""
        props = {"dsl": self.LANG_KEY, "role": role, "name": name}
        if extra:
            props.update(extra)
        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=file_id,
            entity_type="module",
            inspection_source="dsl-enrich",
            structural_properties=props,
        )

    def _dsl_enrich(self, file_id: int, tree: ast.AST, code_text: str):
        """Default enrichment: flag any top-level function whose decorator root
        is in DSL_DECORATORS, and any class whose base root is in
        DSL_BASECLASSES.  Subclasses override for finer, framework-aware rules
        but may also call `super()._dsl_enrich(...)` to keep this baseline."""
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    root = self._decorator_root(dec)
                    if (
                        root in self.DSL_DECORATORS
                        or root.split(".")[-1] in self.DSL_DECORATORS
                    ):
                        self._dsl_tag(file_id, node.name, "decorated:" + root)
                        break
            elif isinstance(node, ast.ClassDef):
                for base in node.bases:
                    root = self._base_root(base)
                    if (
                        root in self.DSL_BASECLASSES
                        or root.split(".")[-1] in self.DSL_BASECLASSES
                    ):
                        self._dsl_tag(file_id, node.name, "subclass:" + root)
                        break
