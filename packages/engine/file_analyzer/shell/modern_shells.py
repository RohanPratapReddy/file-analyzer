# Modern structured shells with a non-POSIX grammar: Elvish (.elv) and
# Nushell (.nu).  They have their own function / variable / module syntax, so a
# POSIX parser would miss everything -- each gets its own real analyzer.
import re

from .shell_base import ShellScriptBase


class ElvishAnalyzer(ShellScriptBase):
    """Elvish shell scripts (.elv).

    ``fn name {|a b| ... }``   -> function (params from the |...| signature)
    ``var x = ...`` / ``set x = ...``  -> variable
    ``use path/mod``           -> import
    """

    LANG_KEY = "elvish"
    EXTENSIONS = (".elv",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _FN = re.compile(
        r"(?m)^[ \t]*fn[ \t]+([A-Za-z_][\w-]*)[ \t]*\{[ \t]*(?:\|([^|]*)\|)?"
    )
    _VAR = re.compile(r"(?m)^[ \t]*(var|set)[ \t]+([A-Za-z_][\w-]*)")
    _USE = re.compile(r"(?m)^[ \t]*use[ \t]+([^\s]+)")

    def _extract_entities(self, file_id, text, path):
        self._record_shebang(file_id, text)
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FN.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = [p.strip() for p in (m.group(2) or "").split() if p.strip()]
            self._add_shell_function(
                file_id, name, params=params, description="elvish fn"
            )

        seen_var = set()
        for m in self._VAR.finditer(clean):
            name = m.group(2)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, None, scope=m.group(1))

        seen_imp = set()
        for m in self._USE.finditer(clean):
            mod = m.group(1)
            if mod not in seen_imp:
                seen_imp.add(mod)
                self._add_import(file_id, mod.split("/")[-1], mod, alias="use")

        self._record_module_meta(
            file_id, functions=len(seen_fn), variables=len(seen_var)
        )


class NushellAnalyzer(ShellScriptBase):
    """Nushell scripts (.nu).

    ``def name [params] { ... }`` / ``def-env`` / ``export def`` -> function
    ``let x = ...`` / ``mut x = ...`` / ``const x = ...``        -> variable
    ``use mod`` / ``source file``                               -> import
    ``alias n = ...``                                           -> variable(alias)
    """

    LANG_KEY = "nushell"
    EXTENSIONS = (".nu",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'", "`")

    _DEF = re.compile(
        r"(?m)^[ \t]*(?:export[ \t]+)?def(?:-env)?[ \t]+"
        r'(?:"([^"]+)"|([\w!?.-]+))[ \t]*\[([^\]]*)\]'
    )
    _LET = re.compile(
        r"(?m)^[ \t]*(let|mut|const)[ \t]+([A-Za-z_][\w-]*)[ \t]*=[ \t]*(.*)"
    )
    _USE = re.compile(r"(?m)^[ \t]*(?:export[ \t]+)?use[ \t]+([^\s]+)")
    _SOURCE = re.compile(r"(?m)^[ \t]*source(?:-env)?[ \t]+([^\s]+)")
    _ALIAS = re.compile(
        r"(?m)^[ \t]*(?:export[ \t]+)?alias[ \t]+([\w-]+)[ \t]*=[ \t]*(.+)"
    )

    def _extract_entities(self, file_id, text, path):
        self._record_shebang(file_id, text)
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._DEF.finditer(clean):
            name = m.group(1) or m.group(2)
            if not name or name in seen_fn:
                continue
            seen_fn.add(name)
            params = []
            for tok in self._split_top_level(m.group(3) or ""):
                params.append(tok.split(":")[0].strip())
            self._add_shell_function(
                file_id,
                name,
                params=[p for p in params if p],
                description="nushell def",
            )

        seen_var = set()
        for m in self._LET.finditer(clean):
            name = m.group(2)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(
                    file_id, name, m.group(3).strip()[:120] or None, scope=m.group(1)
                )

        seen_imp = set()
        for m in self._USE.finditer(clean):
            mod = m.group(1).strip('"')
            if mod not in seen_imp:
                seen_imp.add(mod)
                self._add_import(file_id, mod.split("/")[-1], mod, alias="use")
        for m in self._SOURCE.finditer(clean):
            tgt = m.group(1).strip('"')
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="source")

        seen_alias = set()
        for m in self._ALIAS.finditer(clean):
            name = m.group(1)
            if name not in seen_alias:
                seen_alias.add(name)
                self._add_alias(file_id, name, m.group(2))

        self._record_module_meta(
            file_id,
            functions=len(seen_fn),
            variables=len(seen_var),
            aliases=len(seen_alias),
        )
