# Auto-extracted tree-sitter get_parser shim (verbatim from code_analyzer.py).
try:
    # Preferred: the aggregate package ships one parser per language.
    from tree_sitter_languages import get_parser
except ImportError:
    # Fallback shim: tree_sitter_languages has no distribution for newer
    # CPython (e.g. 3.14). Build a parser on demand from the modern
    # `tree_sitter` core + per-language `tree_sitter_<lang>` packages, each
    # of which exposes a `.language()` PyCapsule. Returns None for a language
    # whose package is not installed, so callers degrade gracefully.
    try:
        import importlib as _importlib

        from tree_sitter import Language as _TSLanguage
        from tree_sitter import Parser as _TSParser

        # tree_sitter_languages accepts a few aliases; map them to PyPI names.
        _TS_LANG_MODULES = {
            "python": "tree_sitter_python",
            "rust": "tree_sitter_rust",
            "go": "tree_sitter_go",
            "java": "tree_sitter_java",
            "javascript": "tree_sitter_javascript",
            "typescript": "tree_sitter_typescript",
            "tsx": "tree_sitter_typescript",
            "c": "tree_sitter_c",
            "cpp": "tree_sitter_cpp",
            "c_sharp": "tree_sitter_c_sharp",
            "ruby": "tree_sitter_ruby",
            "php": "tree_sitter_php",
            "kotlin": "tree_sitter_kotlin",
            "scala": "tree_sitter_scala",
            "swift": "tree_sitter_swift",
            "elixir": "tree_sitter_elixir",
            "r": "tree_sitter_r",
        }

        def get_parser(lang):  # type: ignore[misc]
            mod_name = _TS_LANG_MODULES.get(lang)
            if mod_name is None:
                raise LookupError(
                    f"No tree-sitter module mapping for language {lang!r}"
                )
            mod = _importlib.import_module(mod_name)
            # typescript/php expose language_<variant>() rather than language().
            if lang in ("typescript", "tsx") and hasattr(mod, "language_" + lang):
                lang_capsule = getattr(mod, "language_" + lang)()
            elif lang == "php" and hasattr(mod, "language_php"):
                lang_capsule = mod.language_php()
            else:
                lang_capsule = mod.language()
            return _TSParser(_TSLanguage(lang_capsule))

    except ImportError:
        get_parser = None
