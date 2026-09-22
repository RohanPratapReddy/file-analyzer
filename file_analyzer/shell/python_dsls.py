# Script/recipe formats whose on-disk syntax IS Python and are therefore parsed
# by the real stdlib `ast`, inheriting the full class/function/import/argument
# extraction from `PythonEmbeddedAnalyzer` (exactly as the Python-embedded DSLs
# in `prog_lang` do).  Each subclass only differs by (a) its extension(s) and
# (b) the framework decorators / base classes that carry domain meaning, which
# `_dsl_enrich` flags on top of the inherited pass -- never a placeholder.
#
#   .conanfile  Conan package recipe   -> class ConanFile: def build()/package()
#   .scons      SCons build script     -> Environment(); env.Program(...)
#   .spack      Spack package recipe   -> class Foo(CMakePackage): ...
#   .sage       SageMath script        -> ordinary Python + Sage globals
#   .jnl        Abaqus journal         -> replayed Python (mdb.*, session.*)
#   .star       Starlark config        -> Python-subset (Bazel/Buck rules)
import ast

from ..prog_lang.python_embedded_base import PythonEmbeddedAnalyzer


class ConanRecipeAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "conan"
    EXTENSIONS = (".conanfile",)
    DSL_BASECLASSES = ("ConanFile",)
    DSL_DECORATORS = ()


class SConsBuildAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "scons"
    EXTENSIONS = (".scons",)
    DSL_BASECLASSES = ()
    DSL_DECORATORS = ()

    # SCons scripts are call-driven (Environment(), env.Program(...)); flag the
    # builder invocations as domain entry points on top of the base extraction.
    _BUILDERS = (
        "Program",
        "Library",
        "SharedLibrary",
        "StaticLibrary",
        "Object",
        "Environment",
        "Install",
        "Alias",
        "Command",
    )

    def _dsl_enrich(self, file_id, tree, code_text):
        super()._dsl_enrich(file_id, tree, code_text)
        seen = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = getattr(fn, "attr", None) or getattr(fn, "id", None)
                if name in self._BUILDERS and name not in seen:
                    seen.add(name)
                    self._dsl_tag(file_id, name, "builder:" + name)


class SpackRecipeAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "spack"
    EXTENSIONS = (".spack",)
    DSL_BASECLASSES = (
        "Package",
        "CMakePackage",
        "AutotoolsPackage",
        "MakefilePackage",
        "PythonPackage",
        "CudaPackage",
        "MesonPackage",
        "RPackage",
    )
    DSL_DECORATORS = ("run_before", "run_after", "when", "on_package_attributes")


class SageScriptAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "sage"
    EXTENSIONS = (".sage",)


class AbaqusJournalAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "abaqus-journal"
    EXTENSIONS = (".jnl",)


class StarlarkAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "starlark"
    EXTENSIONS = (".star",)
    DSL_DECORATORS = ()

    _RULES = ("rule", "provider", "aspect", "repository_rule", "module_extension")

    def _dsl_enrich(self, file_id, tree, code_text):
        super()._dsl_enrich(file_id, tree, code_text)
        # Starlark rule/provider definitions are `x = rule(...)` assignments.
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                callee = node.value.func
                name = getattr(callee, "attr", None) or getattr(callee, "id", None)
                if name in self._RULES:
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            self._dsl_tag(file_id, tgt.id, "starlark:" + name)
