# Line-oriented text-processing mini-languages: AWK (.awk) and sed (.sed).
import re

from .shell_base import ShellScriptBase


class AwkAnalyzer(ShellScriptBase):
    """AWK programs (.awk).

    ``function name(args) { ... }``   -> function
    ``BEGIN { ... }`` / ``END { ... }`` and ``/pat/ { ... }`` rules -> function
    ``@include "file"`` (gawk)        -> import
    top-level ``name = value`` assignments -> variable
    """
    LANG_KEY = "awk"
    EXTENSIONS = (".awk",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(r"(?m)^[ \t]*func(?:tion)?[ \t]+([A-Za-z_]\w*)[ \t]*\(([^)]*)\)")
    _SPECIAL = re.compile(r"(?m)^[ \t]*(BEGIN|END|BEGINFILE|ENDFILE)[ \t]*\{")
    _INCLUDE = re.compile(r'(?m)^[ \t]*@include[ \t]+"([^"]+)"')
    _ASSIGN = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*([^=].*)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = self._split_top_level(m.group(2) or "")
            self._add_shell_function(file_id, name, params=params,
                                     description="awk function")
        specials = self._uniq(self._SPECIAL.findall(clean))
        for name in specials:
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="awk rule block")

        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in seen_var or name in ("if", "while", "for", "print", "printf"):
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                               scope="awk")

        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="@include")

        self._record_module_meta(file_id, functions=len(seen_fn),
                                 blocks=specials or None, variables=len(seen_var))


class SedAnalyzer(ShellScriptBase):
    """sed scripts (.sed).

    sed has no functions or imports; its structure is labels and commands.
    ``:label``               -> function (a branch target)
    top-level ``s/…/…/`` etc. counted as module metadata (command profile).
    """
    LANG_KEY = "sed"
    EXTENSIONS = (".sed",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    _LABEL = re.compile(r"(?m)^[ \t]*:[ \t]*([A-Za-z_]\w*)")
    _BRANCH = re.compile(r"(?m)^[ \t]*[btT][ \t]*([A-Za-z_]\w*)?")
    _SUBST = re.compile(r"(?m)(?:^|;)[ \t]*s([^\w\s])")
    _CMD = re.compile(r"(?m)^[ \t]*(?:\d+[, ]*)?[/$]?.*?([sydpaicDGHNPx])\b")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_lbl = set()
        for m in self._LABEL.finditer(clean):
            name = m.group(1)
            if name not in seen_lbl:
                seen_lbl.add(name)
                self._add_shell_function(file_id, name, description="sed label")

        subst = len(self._SUBST.findall(clean))
        branches = self._uniq(b for b in self._BRANCH.findall(clean) if b)
        self._record_module_meta(
            file_id, labels=sorted(seen_lbl) or None,
            substitutions=subst, branch_targets=branches or None,
        )
