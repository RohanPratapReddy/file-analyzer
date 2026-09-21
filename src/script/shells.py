# Interactive-shell script dialects for the `script` plane.
#
#   .sh .bash .zsh .ksh   POSIX / bash / zsh / ksh scripts
#   .fish                 Fish shell scripts (its own grammar: `function..end`,
#                         `set var val`, no `VAR=value` assignments)
#
# The POSIX-family dialect reuses the fully real `PosixShellAnalyzer` parser
# unchanged (bash/ksh/zsh share POSIX function + assignment + `source`/alias
# syntax); only the owned extensions differ.  Fish has a distinct grammar, so it
# gets its own real `ShellScriptBase` analyzer.
import re

from ..shell.posix_shell import PosixShellAnalyzer
from ..shell.shell_base import ShellScriptBase


class PosixScriptShellAnalyzer(PosixShellAnalyzer):
    """`.sh` / `.bash` / `.zsh` / `.ksh` -- bash/ksh/zsh use the POSIX function,
    assignment, `source`/`.`, `export`/`declare`/`local` and `alias` syntax the
    inherited parser already extracts in full."""

    LANG_KEY = "shell"
    EXTENSIONS = (".sh", ".bash", ".zsh", ".ksh")


class FishShellAnalyzer(ShellScriptBase):
    """Fish shell (`.fish`).  Fish deliberately breaks from POSIX:

        function fish_prompt --description 'my prompt'   -> function (+params)
            ...
        end
        set -gx PATH $PATH /usr/local/bin                -> variable
        set -l tmp value                                 -> variable(local)
        source ~/.config/fish/aliases.fish               -> import
        abbr -a gco 'git checkout'                       -> variable(alias)
    """

    LANG_KEY = "fish"
    EXTENSIONS = (".fish",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    # function NAME [--flags] [posarg ...]
    _FUNC = re.compile(r"(?m)^[ \t]*function[ \t]+([A-Za-z_][\w-]*)([^\n]*)")
    # set [-flags] NAME value...   (scope from -g/-l/-U/-x flags)
    _SET = re.compile(r"(?m)^[ \t]*set[ \t]+((?:-\w+[ \t]+)*)([A-Za-z_]\w*)([^\n]*)")
    # abbr -a name 'expansion'   |   alias name 'cmd'
    _ABBR = re.compile(r"(?m)^[ \t]*abbr[ \t]+(?:-\w+[ \t]+)*([A-Za-z_][\w-]*)[ \t]*(.*)")
    _ALIAS = re.compile(r"(?m)^[ \t]*alias[ \t]+([A-Za-z_][\w-]*)[ \t]*(?:=|[ \t])(.*)")
    # source FILE   |   . FILE
    _SOURCE = re.compile(r"(?m)^[ \t]*(?:source|\.)[ \t]+(\S+)")
    _CONTROL = re.compile(r"(?m)^[ \t]*(if|for|while|switch|begin)\b")

    @staticmethod
    def _scope_of(flags: str) -> str:
        if "-x" in flags or "--export" in flags or "-gx" in flags:
            return "exported"
        if "-l" in flags or "--local" in flags:
            return "local"
        if "-U" in flags or "--universal" in flags:
            return "universal"
        return "module"

    def _register_types(self, file_id, text, path):
        # Fish has no user-defined types; nothing to pre-register.
        return

    def _extract_entities(self, file_id, text, path):
        self._record_shebang(file_id, text)
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name, tail = m.group(1), m.group(2)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            # Positional params: bare words in the signature tail that are not
            # option flags or the value of `--description`/`--argument-names`.
            params, i, toks = [], 0, tail.split()
            while i < len(toks):
                tok = toks[i]
                if tok in ("-a", "--argument-names"):
                    i += 1
                    while i < len(toks) and not toks[i].startswith("-"):
                        params.append(toks[i]); i += 1
                    continue
                if tok.startswith("-"):
                    # option that consumes a value (e.g. --description 'x')
                    i += 2 if tok in ("-d", "--description", "-w", "--wraps",
                                      "-V", "--inherit-variable", "-e",
                                      "--on-event", "-s", "--on-signal") else 1
                    continue
                i += 1
            self._add_shell_function(file_id, name, params=params,
                                     description="fish function")

        seen_var = set()
        for m in self._SET.finditer(clean):
            flags, name, tail = m.group(1), m.group(2), m.group(3)
            # `set -e VAR` erases; `set -q VAR` queries -- neither declares.
            if "-e" in flags or "-q" in flags:
                continue
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, (tail.strip()[:120] or None),
                               scope=self._scope_of(flags))

        seen_alias = set()
        for rx in (self._ABBR, self._ALIAS):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name in seen_alias:
                    continue
                seen_alias.add(name)
                self._add_alias(file_id, name, m.group(2))

        seen_src = set()
        for m in self._SOURCE.finditer(clean):
            tgt = m.group(1)
            if tgt in seen_src or tgt.startswith(("(", "$")):
                continue
            seen_src.add(tgt)
            self._add_sourced(file_id, tgt, keyword="source")

        self._record_module_meta(
            file_id, dialect="fish",
            control_blocks=len(self._CONTROL.findall(clean)),
            functions=len(seen_fn), variables=len(seen_var))
