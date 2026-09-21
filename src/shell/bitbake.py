# BitBake recipes / append files / class files (.bb / .bbappend / .bbclass) as
# consumed by OpenEmbedded / Yocto.  BitBake is a make-like metadata language
# whose task bodies are shell or embedded Python:
#
#   VAR = "value"   VAR ?= ..   VAR += ..   VAR:append = ..                -> variable
#   inherit cmake pkgconfig                                                -> import (class)
#   require foo.inc   /   include bar.inc                                  -> import (file)
#   do_compile() { ... }         (shell task)                             -> function
#   python do_install() { ... }  (python task)                            -> function
#   def helper(d): ...           (python def)                             -> function
#   addtask / EXPORT_FUNCTIONS                                            -> module metadata
import re
from pathlib import Path

from .shell_base import ShellScriptBase

_VAR = r"[A-Za-z_][A-Za-z0-9_+.\-${}]*"


class BitBakeAnalyzer(ShellScriptBase):
    LANG_KEY = "bitbake"
    EXTENSIONS = (".bb", ".bbappend", ".bbclass")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    # VARFLAG assignment: name, optional :override / _override, operator.
    _VARSET = re.compile(
        r"(?m)^[ \t]*(" + _VAR + r")(?::[A-Za-z0-9_${}\-]+)*[ \t]*"
        r"(\?\?=|\?=|:=|\+=|=\+|\.=|=\.|=)[ \t]*(.*)")
    _INHERIT = re.compile(r"(?m)^[ \t]*inherit(?:_defer)?[ \t]+(.+)$")
    _REQUIRE = re.compile(r"(?m)^[ \t]*(require|include)[ \t]+(\S+)")
    # shell task:  [fakeroot] do_name() {   |   python do_name() {
    _SHTASK = re.compile(r"(?m)^[ \t]*(?:fakeroot[ \t]+)?(" + r"[A-Za-z_][A-Za-z0-9_\-]*"
                         + r")[ \t]*\(\)[ \t]*\{")
    _PYTASK = re.compile(r"(?m)^[ \t]*python[ \t]*(" + r"[A-Za-z_][A-Za-z0-9_\-]*"
                         + r")?[ \t]*\(\)[ \t]*\{")
    _PYDEF = re.compile(r"(?m)^[ \t]*def[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(([^)]*)\)")
    _ADDTASK = re.compile(r"(?m)^[ \t]*addtask[ \t]+(\S+)")
    _EXPORTFN = re.compile(r"(?m)^[ \t]*EXPORT_FUNCTIONS[ \t]+(.+)$")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_var = set()
        for m in self._VARSET.finditer(clean):
            name = m.group(1)
            if name in seen_var or name in ("inherit", "require", "include",
                                            "addtask", "python", "def"):
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, (m.group(3) or "").strip()[:120] or None,
                               scope="recipe")

        seen_imp = set()
        for m in self._INHERIT.finditer(clean):
            for cls in m.group(1).split():
                if cls not in seen_imp:
                    seen_imp.add(cls)
                    self._add_import(file_id, cls, "bbclass", alias="inherit")
        for m in self._REQUIRE.finditer(clean):
            tgt = m.group(2)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword=m.group(1))

        seen_fn = set()
        for m in self._SHTASK.finditer(clean):
            name = m.group(1)
            if name and name not in seen_fn and name not in ("python", "def"):
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="bitbake shell task")
        for m in self._PYTASK.finditer(clean):
            name = m.group(1) or "__anonymous"
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="bitbake python task")
        for m in self._PYDEF.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                params = [p.strip() for p in m.group(2).split(",") if p.strip()]
                self._add_shell_function(file_id, name, params=params,
                                         description="bitbake python def")

        tasks = self._uniq(self._ADDTASK.findall(clean))
        exported = []
        for m in self._EXPORTFN.finditer(clean):
            exported.extend(m.group(1).split())
        self._record_module_meta(
            file_id, recipe_kind=path.suffix.lower().lstrip("."),
            added_tasks=tasks or None, exported_functions=self._uniq(exported) or None,
            variables=len(seen_var), functions=len(seen_fn),
        )
