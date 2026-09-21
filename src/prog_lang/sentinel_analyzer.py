# Sentinel (.sentinel) analyzer -- HashiCorp policy-as-code language.
#
#     import "tfplan/v2" as tfplan                  -> import (alias tfplan)
#     import "strings"                              -> import
#     param instance_count default 3               -> variable
#     allowed = ["t2.micro", "t2.small"]            -> variable
#     find_resources = func(type) { ... }           -> function
#     is_valid = rule { all instances as i { ... }} -> function (rule)
#     main = rule { find_resources("x") }           -> function (rule)
#
# Comments are '//', '#' and '/* */'; strings use '"' and '`'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class SentinelAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "sentinel"
    EXTENSIONS = (".sentinel",)
    LINE_COMMENTS = ("//", "#")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "`")

    _IMPORT = re.compile(r'(?m)^\s*import\s+"([^"]+)"(?:\s+as\s+(' + _ID + r'))?')
    _PARAM = re.compile(r"(?m)^\s*param\s+(" + _ID + r")\b")
    # `name = func(args) { ... }`
    _FUNC = re.compile(r"(?m)^\s*(" + _ID + r")\s*=\s*func\s*\(([^)]*)\)")
    # `name = rule { ... }`  |  `name = rule when <cond> { ... }`
    _RULE = re.compile(r"(?m)^\s*(" + _ID + r")\s*=\s*rule\b")
    # generic top-level assignment (value that is not func/rule)
    _ASSIGN = re.compile(r"(?m)^\s*(" + _ID + r")\s*=\s*(?!func\b|rule\b)(\S)")

    def _register_types(self, file_id, text, path):
        # Sentinel has no class construct.
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src, alias=m.group(2))

        defined = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            defined.add(name)
            args = self._simple_args(m.group(2))
            self._add_function(file_id, name, args, [],
                               description="sentinel func")
        for m in self._RULE.finditer(clean):
            name = m.group(1)
            defined.add(name)
            self._add_function(file_id, name, [], [],
                               description="sentinel rule")

        for m in self._PARAM.finditer(clean):
            name = m.group(1)
            defined.add(name)
            self._add_variable(file_id, name, scope="param")

        seen = set(defined)
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            self._add_variable(file_id, name, scope="module")

    def _simple_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip().split("=")[0].strip()
            m = re.match(_ID, part)
            if m:
                arg_ids.append(self._add_arg(m.group(0)))
        return arg_ids
