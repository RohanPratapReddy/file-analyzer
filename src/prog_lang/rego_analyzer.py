# Rego (.rego) analyzer.
#
# Real parser for Rego (the Open Policy Agent policy language; '#' line comments,
# no block comments; strings "..." and raw `...`):
#   package authz.rbac                              -> (package marker)
#   import future.keywords.if                        -> import
#   import data.roles as r                            -> import (aliased)
#   default allow := false                            -> variable (default rule)
#   allow if { input.method == "GET" }               -> function (rule)
#   allow { input.user == "admin" }                  -> function (rule)
#   deny[msg] { ... }                                 -> function (partial-set rule)
#   is_admin(user) if { ... }                         -> function
#   add(x, y) := z { z := x + y }                     -> function
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_NAME = r"[a-zA-Z_]\w*"


class RegoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "rego"
    EXTENSIONS = (".rego",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "`")

    _PACKAGE = re.compile(r"^\s*package\s+([\w.]+)", re.MULTILINE)
    _IMPORT = re.compile(r"^\s*import\s+([\w.]+)(?:\s+as\s+(" + _NAME + r"))?",
                         re.MULTILINE)
    _DEFAULT = re.compile(r"^\s*default\s+(" + _NAME + r")", re.MULTILINE)
    # a rule head at column 0-ish:  name  |  name(args)  |  name[key]  optionally
    # followed by  := value | = value | contains x | if | {
    _RULE = re.compile(
        r"^(" + _NAME + r")(?:\(([^)]*)\))?(?:\[([^\]]*)\])?\s*"
        r"(?::=|=|contains\b|if\b|\{)", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._IMPORT.finditer(text):
            mod, alias = m.group(1), m.group(2)
            self._add_import(file_id, alias or mod.split(".")[-1], mod, alias)

        # `default X := v` records a fallback value for document X; X may ALSO
        # have rule bodies, so we defer emitting it and let the rule loop win.
        defaults = {m.group(1) for m in self._DEFAULT.finditer(text)}

        rule_names = set()
        seen = set()
        for m in self._RULE.finditer(text):
            name, params, key = m.group(1), m.group(2), m.group(3)
            if name in ("package", "import", "default", "some", "every",
                        "not", "with", "else"):
                continue
            if params is not None:
                # function rule -- keyed by name+arity so overloads register once
                arity_key = (name, len([p for p in
                                        self._split_top_level(params) if p]))
                if arity_key in seen:
                    continue
                seen.add(arity_key)
                rule_names.add(name)
                arg_ids = [self._add_arg(p.strip())
                           for p in self._split_top_level(params) if p.strip()]
                self._add_function(file_id, name, arg_ids, [],
                                   description="rego function")
            else:
                if name in seen:
                    continue
                seen.add(name)
                rule_names.add(name)
                desc = "rego partial rule" if key is not None else "rego rule"
                self._add_function(file_id, name, [], [], description=desc)

        # a `default` document with no rule body of its own is a plain value.
        for name in defaults:
            if name not in rule_names:
                self._add_variable(file_id, name, None)
