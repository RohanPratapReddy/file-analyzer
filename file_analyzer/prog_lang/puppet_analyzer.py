# Puppet (.pp) analyzer.
#
# Real parser for the Puppet configuration-management DSL:
#
#     class nginx (String $version = 'latest', Integer $port = 80) { ... }
#         -> class (with params as args)
#     class nginx::config inherits nginx { ... }   -> class + parent
#     define nginx::vhost ($docroot, $port = 80) { ... }  -> function (defined type)
#     node 'web01.example.com' { ... }             -> class (node definition)
#     function stdlib::upcase(String $s) >> String { ... } -> function
#     $ssl_enabled = true                          -> variable
#     include apache                               -> import
#     require ntp
#
# Comments are '#'; strings use "'" and '"'.  Params live in '( ... )'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[a-z_][a-zA-Z0-9_]*(?:::[a-z_][a-zA-Z0-9_]*)*"
_VAR = r"\$[a-z_][a-zA-Z0-9_]*(?:::[a-z_][a-zA-Z0-9_]*)*"


class PuppetAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "puppet"
    EXTENSIONS = (".pp",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'", '"')

    _CLASS = re.compile(
        r"(?m)^\s*class\s+(" + _ID + r")\s*(\([^{]*?\))?"
        r"\s*(?:inherits\s+(" + _ID + r"))?\s*\{"
    )
    _DEFINE = re.compile(r"(?m)^\s*define\s+(" + _ID + r")\s*(\([^{]*?\))?\s*\{")
    _FUNCTION = re.compile(
        r"(?m)^\s*function\s+(" + _ID + r")\s*(\([^)]*\))?"
        r"(?:\s*>>\s*([A-Za-z:\[\], ]+))?\s*\{"
    )
    _NODE = re.compile(r"(?m)^\s*node\s+([^\{]+?)\s*\{")
    _INCLUDE = re.compile(
        r"(?m)^\s*(?:include|require|contain)\s+(?:::)?(" + _ID + r")"
    )
    _ASSIGN = re.compile(r"(?m)^\s*(" + _VAR + r")\s*=")

    def _params(self, paren):
        if not paren:
            return []
        inner = paren[1:-1]
        ids = []
        for grp in self._split_top_level(inner):
            grp = grp.strip()
            if not grp:
                continue
            vm = re.search(r"\$([a-zA-Z_]\w*)", grp)
            if not vm:
                continue
            typ = grp[: grp.index("$")].strip() or None
            dm = grp.split("=", 1)
            default = dm[1].strip() if len(dm) > 1 else None
            ids.append(self._add_arg(vm.group(1), arg_type=typ, default_value=default))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))
        for m in self._NODE.finditer(clean):
            self._register_class("node:" + m.group(1).strip().strip("'\""))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            self._add_import(file_id, m.group(1).split("::")[-1], m.group(1))

        for m in self._CLASS.finditer(clean):
            parent = m.group(3)
            parent_ids = [self._register_class(parent)] if parent else None
            self._add_class(
                file_id,
                m.group(1),
                description="puppet class",
                parent_ids=parent_ids,
                method_ids=self._class_methods(file_id, m),
            )

        for m in self._NODE.finditer(clean):
            self._add_class(
                file_id,
                "node:" + m.group(1).strip().strip("'\""),
                description="puppet node",
            )

        for m in self._DEFINE.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._params(m.group(2)),
                [],
                description="puppet defined type",
            )
        for m in self._FUNCTION.finditer(clean):
            out = [self._add_output(m.group(3).strip())] if m.group(3) else []
            self._add_function(
                file_id,
                m.group(1),
                self._params(m.group(2)),
                out,
                description="puppet function",
            )

        for m in self._ASSIGN.finditer(clean):
            self._add_variable(file_id, m.group(1)[1:], scope="module")

    def _class_methods(self, file_id, class_match):
        # params of a class become its constructor-style args recorded as a
        # single synthetic method so the parameters are captured on the class.
        arg_ids = self._params(class_match.group(2))
        if not arg_ids:
            return None
        fid = self._add_function(
            file_id,
            class_match.group(1) + "::params",
            arg_ids,
            [],
            description="puppet class params",
        )
        return [fid]
