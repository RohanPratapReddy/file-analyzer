# Build-system / CI authoring languages: GNU M4 & Autoconf input (.m4/.ac),
# Jenkins declarative/scripted pipelines in Groovy (.jenkinsfile) and Vagrant
# environment definitions in Ruby (.vagrantfile).
import re

from .shell_base import ShellScriptBase


class M4Analyzer(ShellScriptBase):
    """GNU M4 macro files (.m4) and Autoconf input (.ac).

    ``define(`NAME', ...)`` / ``m4_define`` / ``AC_DEFUN([NAME], ...)`` -> function
    ``include(`file')`` / ``m4_include`` / ``sinclude``               -> import
    ``AC_INIT`` / ``AM_INIT_AUTOMAKE`` and other top macros           -> metadata
    """

    LANG_KEY = "m4"
    EXTENSIONS = (".m4", ".ac")
    LINE_COMMENTS = ("dnl",)  # `dnl` = m4 "delete to newline"
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()  # m4 quotes are `...' -- handled by regex

    _DEFINE = re.compile(r"(?m)(?:m4_)?define\(\s*[`\[]?\s*([A-Za-z_]\w*)")
    _ACDEFUN = re.compile(r"(?m)AC_DEFUN\(\s*\[?\s*([A-Za-z_]\w*)")
    _INCLUDE = re.compile(r"(?m)(?:m4_)?s?include\(\s*[`\[]?\s*([^'\])\s]+)")
    _ACINIT = re.compile(r"(?m)^[ \t]*(AC_INIT|AM_INIT_AUTOMAKE|AC_CONFIG_\w+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for rx, kind in ((self._DEFINE, "m4 macro"), (self._ACDEFUN, "autoconf macro")):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name in seen_fn:
                    continue
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description=kind)

        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1)
            if tgt and tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="include")

        macros = self._uniq(m.group(1) for m in self._ACINIT.finditer(clean))
        self._record_module_meta(
            file_id,
            kind="autoconf" if path.suffix.lower() == ".ac" else "m4",
            macros_defined=len(seen_fn),
            config_macros=macros or None,
        )


class JenkinsfileAnalyzer(ShellScriptBase):
    """Jenkins pipeline definitions (.jenkinsfile) -- Groovy.

    ``stage('name') { ... }``            -> function (a pipeline stage)
    ``def name(args) { ... }``           -> function
    ``pipeline { ... }`` / ``node { }``  -> class (the top-level pipeline block)
    ``@Library('x')`` / ``import x``     -> import
    ``environment { KEY = 'v' }``        -> variable
    """

    LANG_KEY = "jenkins"
    EXTENSIONS = (".jenkinsfile",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _STAGE = re.compile(r"(?m)\bstage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
    _DEF = re.compile(r"(?m)^[ \t]*def[ \t]+([A-Za-z_]\w*)[ \t]*\(([^)]*)\)")
    _LIBRARY = re.compile(r"(?m)@Library\(\s*['\"]([^'\"]+)['\"]")
    _IMPORT = re.compile(r"(?m)^[ \t]*import[ \t]+([\w.]+)")
    _PIPELINE = re.compile(r"(?m)^[ \t]*(pipeline|node)\b")
    _ENVVAR = re.compile(r"(?m)^[ \t]*([A-Z][A-Z0-9_]*)\s*=\s*(.+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        if self._PIPELINE.search(clean):
            self._add_class(file_id, "pipeline", description="jenkins pipeline")

        seen_fn = set()
        for m in self._STAGE.finditer(clean):
            name = m.group(1)
            key = "stage:" + name
            if key in seen_fn:
                continue
            seen_fn.add(key)
            self._add_shell_function(file_id, name, description="jenkins stage")
        for m in self._DEF.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = [
                p.strip().split()[-1]
                for p in self._split_top_level(m.group(2) or "")
                if p.strip()
            ]
            self._add_shell_function(
                file_id, name, params=params, description="jenkins def"
            )

        seen_imp = set()
        for rx, kw in ((self._LIBRARY, "@Library"), (self._IMPORT, "import")):
            for m in rx.finditer(clean):
                tgt = m.group(1)
                if tgt not in seen_imp:
                    seen_imp.add(tgt)
                    self._add_import(file_id, tgt.split(".")[-1], tgt, alias=kw)

        seen_var = set()
        for m in self._ENVVAR.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(
                    file_id, name, m.group(2).strip()[:120] or None, scope="environment"
                )

        self._record_module_meta(
            file_id,
            stages=len([s for s in seen_fn if s.startswith("stage:")]),
            functions=len([s for s in seen_fn if not s.startswith("stage:")]),
            env_vars=len(seen_var),
        )


class VagrantfileAnalyzer(ShellScriptBase):
    """Vagrant environment definitions (.vagrantfile) -- Ruby.

    ``Vagrant.configure("2") do |config| ... end``  -> class (the config block)
    ``config.vm.define "name" do |x| ... end``      -> function (a defined VM)
    ``def name ... end``                            -> function
    ``require 'x'`` / ``require_relative 'y'``       -> import
    ``config.vm.box = "..."`` and ``x = y``          -> variable
    """

    LANG_KEY = "vagrant"
    EXTENSIONS = (".vagrantfile",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("=begin", "=end"),)
    STRING_DELIMS = ('"', "'")

    _CONFIGURE = re.compile(r"(?m)Vagrant\.configure\s*\(\s*['\"]?([^'\")]+)")
    _DEFINE = re.compile(r"(?m)\.(?:vm\.)?define[ \t]*\(?[ \t]*['\"]([^'\"]+)['\"]")
    _DEF = re.compile(r"(?m)^[ \t]*def[ \t]+([A-Za-z_]\w*[!?]?)")
    _REQUIRE = re.compile(r"(?m)^[ \t]*require(?:_relative)?[ \t]+['\"]([^'\"]+)['\"]")
    _ASSIGN = re.compile(r"(?m)^[ \t]*([A-Za-z_][\w.]*)[ \t]*=[ \t]*(.+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        m = self._CONFIGURE.search(clean)
        if m:
            self._add_class(
                file_id,
                "Vagrant.configure",
                description="vagrant config v" + m.group(1),
            )

        seen_fn = set()
        for m in self._DEFINE.finditer(clean):
            name = m.group(1)
            key = "vm:" + name
            if key not in seen_fn:
                seen_fn.add(key)
                self._add_shell_function(file_id, name, description="vagrant vm")
        for m in self._DEF.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="ruby def")

        seen_imp = set()
        for m in self._REQUIRE.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_import(file_id, tgt.split("/")[-1], tgt, alias="require")

        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in seen_var or "==" in m.group(0):
                continue
            seen_var.add(name)
            self._add_variable(
                file_id,
                name,
                m.group(2).strip()[:120] or None,
                scope="config" if name.startswith("config") else "ruby",
            )

        self._record_module_meta(
            file_id,
            vms=len([f for f in seen_fn if f.startswith("vm:")]),
            functions=len([f for f in seen_fn if not f.startswith("vm:")]),
            settings=len(seen_var),
        )
