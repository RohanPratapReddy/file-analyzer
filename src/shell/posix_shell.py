# POSIX / Bourne / bash / zsh + C-shell (tcsh/csh) scripts, shell rc & login
# profiles, and the shell-scripted package recipes that share their grammar
# (Gentoo ebuild, Arch PKGBUILD, Debian maintainer scripts, the Gradle wrapper,
# cloud-init user-data).
#
#   name() { ... }   /   function name { ... }      -> function
#   VAR=value        export VAR=value               -> variable (exported flagged)
#   local/declare/readonly/typeset VAR=...          -> variable (scoped)
#   set  var = value   /   setenv VAR value  (csh)  -> variable
#   source file   /   . file                        -> import  (sourced)
#   alias name='...'  /  alias name cmd  (csh)       -> variable(scope="alias")
#   #!/usr/bin/env bash                              -> module introspection
#
# Bourne and C-shell dialects are handled by one analyzer: the two grammars use
# disjoint keywords (`function`/`local` vs `set`/`setenv`/`foreach`), so the
# additive patterns never mis-fire across dialects and a single file is parsed
# by whichever set of rules its own syntax triggers.
import re
from pathlib import Path

from .shell_base import ShellScriptBase

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
# A shell variable name may include '::' (zsh) but we keep it simple/portable.


class PosixShellAnalyzer(ShellScriptBase):
    LANG_KEY = "shell"
    EXTENSIONS = (
        ".bashrc", ".zshrc", ".profile", ".tcsh",
        ".xinitrc", ".xsession",
        ".ebuild", ".pkgbuild", ".gradlew",
        ".postinst", ".postrm", ".preinst", ".prerm",
        ".userdata",
    )
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    # func()  {   |   function func {   |   function func() {
    _FUNC = re.compile(
        r"(?m)^[ \t]*(?:function[ \t]+(" + _NAME + r")[ \t]*(?:\(\))?"
        r"|(" + _NAME + r")[ \t]*\(\))[ \t]*\{?",
    )
    # export FOO=... / export FOO / declare|local|readonly|typeset [-flags] FOO=...
    _EXPORT = re.compile(r"(?m)^[ \t]*export[ \t]+(" + _NAME + r")(?:=(.*))?")
    _DECL = re.compile(
        r"(?m)^[ \t]*(local|declare|readonly|typeset)[ \t]+(?:-\w+[ \t]+)*"
        r"(" + _NAME + r")(?:=(.*))?")
    # plain assignment FOO=bar at statement start (not == comparison)
    _ASSIGN = re.compile(r"(?m)^[ \t]*(" + _NAME + r")=(.*)")
    # csh:  set var = value | set var=value | setenv VAR value | @ var = expr
    _CSH_SET = re.compile(r"(?m)^[ \t]*set[ \t]+(" + _NAME + r")[ \t]*=[ \t]*(.*)")
    _CSH_SETENV = re.compile(r"(?m)^[ \t]*setenv[ \t]+(" + _NAME + r")(?:[ \t]+(.*))?")
    # source file  |  . file
    _SOURCE = re.compile(r"(?m)^[ \t]*(?:source|\.)[ \t]+(\S+)")
    # bash alias name='...'   |   csh alias name cmd
    _ALIAS = re.compile(r"(?m)^[ \t]*alias[ \t]+(" + _NAME + r")(?:[ \t]*=[ \t]*(.+)|[ \t]+(.+))?$")
    # package-recipe function conventions worth surfacing as structure.
    _CONTROL = re.compile(r"(?m)^[ \t]*(if|for|while|until|case|foreach|select)\b")

    def _extract_entities(self, file_id, text, path):
        self._record_shebang(file_id, text)
        clean = self._strip_comments(text)

        # Functions (define the callable surface of the script).
        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1) or m.group(2)
            if not name or name in seen_fn:
                continue
            seen_fn.add(name)
            self._add_shell_function(file_id, name, description="shell function")

        seen_var = set()

        def _var(name, value, scope, exported=False):
            if name in seen_var:
                return
            seen_var.add(name)
            val = (value or "").strip()
            self._add_variable(file_id, name, (val[:120] or None),
                               scope=("exported" if exported else scope))

        for m in self._EXPORT.finditer(clean):
            _var(m.group(1), m.group(2), "exported", exported=True)
        for m in self._DECL.finditer(clean):
            _var(m.group(2), m.group(3), m.group(1))
        for m in self._CSH_SET.finditer(clean):
            _var(m.group(1), m.group(2), "local")
        for m in self._CSH_SETENV.finditer(clean):
            _var(m.group(1), m.group(2), "exported", exported=True)
        # Plain FOO=bar assignments last (lower priority than the typed forms).
        for m in self._ASSIGN.finditer(clean):
            name, val = m.group(1), m.group(2)
            # skip keywords that only look like assignments
            if name in ("if", "then", "fi", "do", "done", "esac"):
                continue
            _var(name, val, "module")

        # Sourced files -> imports.
        seen_src = set()
        for m in self._SOURCE.finditer(clean):
            tgt = m.group(1)
            if tgt in seen_src or tgt.startswith(("$", "`", "(")):
                # still record variable-driven includes, just once
                pass
            if tgt in seen_src:
                continue
            seen_src.add(tgt)
            self._add_sourced(file_id, tgt, keyword="source")

        # Aliases -> variables(scope="alias").
        seen_alias = set()
        for m in self._ALIAS.finditer(clean):
            name = m.group(1)
            if name in seen_alias:
                continue
            seen_alias.add(name)
            self._add_alias(file_id, name, m.group(2) or m.group(3))

        # Structural summary (control-flow density) as module metadata.
        controls = len(self._CONTROL.findall(clean))
        dialect = "csh" if (self._CSH_SET.search(clean) or self._CSH_SETENV.search(clean)) \
            and not self._FUNC.search(clean) else "posix"
        self._record_module_meta(
            file_id, dialect=dialect, control_blocks=controls,
            functions=len(seen_fn), variables=len(seen_var),
            recipe_kind=self._recipe_kind(path),
        )

    @staticmethod
    def _recipe_kind(path: Path):
        suf = path.suffix.lower()
        return {
            ".ebuild": "gentoo-ebuild", ".pkgbuild": "arch-pkgbuild",
            ".postinst": "debian-postinst", ".postrm": "debian-postrm",
            ".preinst": "debian-preinst", ".prerm": "debian-prerm",
            ".gradlew": "gradle-wrapper", ".userdata": "cloud-init-userdata",
        }.get(suf)
