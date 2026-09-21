# Build-system script dialects for the `script` plane.
#
#   .cmake    CMake module / script                 -> new CMakeAnalyzer
#   .gradle   Gradle build script (Groovy DSL)      -> real GroovyAnalyzer
#   .bzl      Bazel Starlark extension (Python)      -> real StarlarkAnalyzer
#
# Gradle and Bazel are exact dialects of languages that already have real
# parsers in the tree, so they subclass those parsers and only change the owned
# extension -- no reimplementation, no placeholder.
import re

from ..prog_lang.groovy_analyzer import GroovyAnalyzer
from ..prog_lang.regex_base import RegexCodeAnalyzer
from ..shell.python_dsls import StarlarkAnalyzer


class GradleBuildAnalyzer(GroovyAnalyzer):
    """`.gradle` build scripts are Groovy (imports, closures/methods, `def`
    variables, plugin/task blocks) -- the real Groovy parser handles them."""

    LANG_KEY = "gradle"
    EXTENSIONS = (".gradle",)


class BazelExtensionAnalyzer(StarlarkAnalyzer):
    """`.bzl` files are Starlark (the Python-subset used by Bazel), parsed by the
    real `ast`-backed Starlark analyzer -- rule()/provider()/aspect() defs, load
    statements, functions and variables all come out of the inherited pass."""

    LANG_KEY = "bazel-starlark"
    EXTENSIONS = (".bzl",)


class CMakeAnalyzer(RegexCodeAnalyzer):
    """CMake module / script (`.cmake`).

    function(my_fn ARG1 ARG2)  ... endfunction()   -> function (+params)
    macro(my_macro a b)        ... endmacro()       -> function (+params)
    set(MY_VAR value CACHE ...)                     -> variable
    option(BUILD_TESTS "desc" ON)                   -> variable
    include(GNUInstallDirs)                          -> import
    find_package(Threads REQUIRED)                   -> import
    add_subdirectory(src)                            -> import (directory)
    """

    LANG_KEY = "cmake"
    EXTENSIONS = (".cmake",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()  # `#[[ ... ]]` handled in _strip_bracket_comments
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(r"(?im)^[ \t]*(function|macro)[ \t]*\(([^)]*)\)")
    _SET = re.compile(r"(?im)^[ \t]*set[ \t]*\([ \t]*([A-Za-z_]\w*)([^)]*)\)")
    _OPTION = re.compile(
        r"(?im)^[ \t]*(?:option|cmake_dependent_option)[ \t]*\(" r"[ \t]*([A-Za-z_]\w*)"
    )
    _INCLUDE = re.compile(r"(?im)^[ \t]*include[ \t]*\([ \t]*([^\s)]+)")
    _FIND = re.compile(r"(?im)^[ \t]*find_package[ \t]*\([ \t]*([A-Za-z_][\w.\-]*)")
    _SUBDIR = re.compile(r"(?im)^[ \t]*add_subdirectory[ \t]*\([ \t]*([^\s)]+)")

    def _strip_bracket_comments(self, text: str) -> str:
        # CMake bracket comments: #[[ ... ]] and #[=[ ... ]=]
        return re.sub(r"#\[(=*)\[.*?\]\1\]", "", text, flags=re.DOTALL)

    def _register_types(self, file_id, text, path):
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(self._strip_bracket_comments(text))

        # Imports first: include()/find_package()/add_subdirectory().
        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            mod = m.group(1).strip('"')
            if mod and not mod.startswith("$") and mod not in seen_imp:
                seen_imp.add(mod)
                self._add_import(
                    file_id, mod.replace("\\", "/").split("/")[-1], mod, alias="include"
                )
        for m in self._FIND.finditer(clean):
            pkg = m.group(1)
            if pkg not in seen_imp:
                seen_imp.add(pkg)
                self._add_import(file_id, pkg, pkg, alias="find_package")
        for m in self._SUBDIR.finditer(clean):
            d = m.group(1).strip('"')
            if d and not d.startswith("$") and d not in seen_imp:
                seen_imp.add(d)
                self._add_import(
                    file_id,
                    d.replace("\\", "/").split("/")[-1],
                    d,
                    alias="add_subdirectory",
                )

        # Functions / macros (+ declared parameters).
        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            parts = m.group(2).split()
            if not parts:
                continue
            name, params = parts[0], parts[1:]
            if name in seen_fn:
                continue
            seen_fn.add(name)
            arg_ids = [self._add_arg(p) for p in params]
            self._add_function(
                file_id, name, arg_ids=arg_ids, description=f"cmake {m.group(1)}"
            )

        # Variables: set(VAR ...) and option(VAR ...).
        seen_var = set()
        for m in self._SET.finditer(clean):
            name, rhs = m.group(1), m.group(2)
            if name in seen_var:
                continue
            seen_var.add(name)
            scope = "cache" if re.search(r"\bCACHE\b", rhs) else "module"
            val = rhs.strip().split("CACHE")[0].strip()
            self._add_variable(file_id, name, (val[:120] or None), scope=scope)
        for m in self._OPTION.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, scope="option")

        self.record_introspection_metadata(
            file_id=file_id,
            entity_id=file_id,
            entity_type="module",
            inspection_source=self.introspection_source,
            structural_properties={
                "dialect": "cmake",
                "functions": len(seen_fn),
                "variables": len(seen_var),
                "imports": len(seen_imp),
            },
        )
