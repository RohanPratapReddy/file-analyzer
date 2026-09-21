# Shared plumbing for the hand-written shell / command-language / automation
# script analyzers (the `py.shell` subpackage).
#
# This is the shell-family analog of `prog_lang.regex_base.RegexCodeAnalyzer`:
# it does NOT reimplement the relational engine (id allocation, symbol indexing,
# introspection rows, the two-pass `analyze` driver, comment/string-aware text
# utilities and the exporter all live in `RegexCodeAnalyzer` / `BaseCodeAnalyzer`
# and are inherited unchanged), so every shell table is byte-for-byte compatible
# with the `code` tables produced by the programming-language analyzers.  What it
# ADDS is the handful of record helpers that are natural for command languages
# rather than object-oriented source:
#
#   * a sourced / dot-included file            -> import      (import_source=path)
#   * an external command a script depends on  -> import      (import_source="command")
#   * an alias / abbreviation                  -> variable    (scope="alias")
#   * a shell function (with positional args)  -> function
#   * a shebang / interpreter directive        -> introspection_metadata (module)
#
# Concrete analyzers set `LANG_KEY` / `EXTENSIONS` (and their comment delimiters)
# and implement `_register_types` (pass 1) and `_extract_entities` (pass 2) with
# the REAL syntax of their own command language, exactly like the prog_lang
# regex analyzers.
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..prog_lang.regex_base import RegexCodeAnalyzer


class ShellScriptBase(RegexCodeAnalyzer):
    """Base engine for command-language / automation-script analyzers.

    Adds shell-oriented record helpers on top of `RegexCodeAnalyzer` while
    keeping the emitted table shape identical to the programming-language
    analyzers, so the shell files fold into the single `code` domain of the
    pipeline with no schema changes.
    """

    LANG_KEY: str = "shell"
    EXTENSIONS: Tuple[str, ...] = ()
    LINE_COMMENTS: Tuple[str, ...] = ("#",)
    BLOCK_COMMENTS: Tuple[Tuple[str, str], ...] = ()
    STRING_DELIMS: Tuple[str, ...] = ('"', "'")

    # A shebang / interpreter directive on the first line.
    _SHEBANG = re.compile(r"^#!\s*(\S+)(?:\s+(.*))?")

    # ------------------------------------------------------------------
    # Shell-flavoured record helpers (all delegate to the inherited engine).
    # ------------------------------------------------------------------
    def _add_sourced(self, file_id: int, target: str, keyword: str = "source") -> int:
        """A ``source foo`` / ``. foo`` / ``require foo`` dependency -> import."""
        target = target.strip().strip("'\"")
        name = target.replace("\\", "/").split("/")[-1]
        return self._add_import(file_id, name or target, target, alias=keyword)

    def _add_command_dep(self, file_id: int, command: str) -> int:
        """An external command the script invokes / requires -> import.

        Recorded with ``import_source="command"`` so downstream consumers can
        distinguish a program dependency from a sourced file.  Callers are
        expected to de-duplicate; this only allocates the row.
        """
        command = command.strip()
        return self._add_import(file_id, command, "command", alias="exec")

    def _add_alias(self, file_id: int, name: str, value: Optional[str] = None) -> int:
        """A shell alias / abbreviation -> variable(scope="alias")."""
        return self._add_variable(file_id, name, (value or "").strip()[:120] or None,
                                   scope="alias")

    def _add_shell_function(self, file_id: int, name: str,
                            params: Optional[List[str]] = None,
                            description: Optional[str] = None,
                            class_id: Optional[int] = None) -> int:
        """A function / procedure / handler -> function, with positional or
        named parameters recorded as args."""
        arg_ids = []
        for p in params or []:
            p = p.strip()
            if p:
                arg_ids.append(self._add_arg(p))
        return self._add_function(file_id, name, arg_ids=arg_ids,
                                  class_id=class_id, description=description)

    def _record_shebang(self, file_id: int, text: str) -> Optional[str]:
        """Record the ``#!`` interpreter line (if any) as module introspection
        metadata and return the interpreter path."""
        first = text.split("\n", 1)[0]
        m = self._SHEBANG.match(first)
        if not m:
            return None
        interp = m.group(1)
        args = (m.group(2) or "").strip()
        # ``#!/usr/bin/env bash`` -> the real interpreter is the first argument.
        real = interp
        if interp.rsplit("/", 1)[-1] == "env" and args:
            real = args.split()[0]
        self.record_introspection_metadata(
            file_id=file_id, entity_id=file_id, entity_type="module",
            inspection_source=self.introspection_source,
            structural_properties={"shebang": interp, "interpreter": real,
                                   "shebang_args": args or None},
        )
        return real

    def _record_module_meta(self, file_id: int, **props: Any) -> None:
        """Record arbitrary file-level facts as module introspection metadata."""
        cleaned = {k: v for k, v in props.items() if v is not None}
        if cleaned:
            self.record_introspection_metadata(
                file_id=file_id, entity_id=file_id, entity_type="module",
                inspection_source=self.introspection_source,
                structural_properties=cleaned,
            )

    # ------------------------------------------------------------------
    @staticmethod
    def _uniq(seq):
        """Order-preserving de-duplication."""
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
