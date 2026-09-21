# Nix (.nix) expression-language analyzer.
#
# Real parser for Nix (`#` line, `/* */` block comments):
#   import ./pkgs.nix                             -> import
#   with pkgs;                                     -> import (scope open)
#   { pkgs, lib, ... }:                            -> function (formal args)
#   name = value;                                  -> attribute binding (variable)
#   greet = name: "hi ${name}";                    -> function (lambda binding)
#   let x = 1; in ...                              -> let bindings (variables)
# Nix has no classes; attribute sets are captured as variables and lambda-valued
# bindings as functions, which is the honest structural model for the language.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class NixAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "nix"
    EXTENSIONS = (".nix",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("/*", "*/"),)

    _IMPORT = re.compile(r"\bimport\s+([./\w]+)")
    _WITH = re.compile(r"^\s*with\s+([\w.]+)\s*;", re.MULTILINE)
    _FORMALS = re.compile(r"^\s*\{\s*([\w,\s?.]*?)\}\s*:", re.MULTILINE)
    # binding whose RHS is a lambda:  name = arg: ...   or  name = {a,b}: ...
    _LAMBDA = re.compile(
        r"^\s*([\w.\"-]+)\s*=\s*(?:\{[^}]*\}\s*:|[\w]+\s*:)", re.MULTILINE)
    _BIND = re.compile(r"^\s*([\w.\"-]+)\s*=\s*(?!=)([^\n;]*)", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        seen_imp = set()
        for m in self._IMPORT.finditer(t):
            src = m.group(1)
            if src not in seen_imp:
                seen_imp.add(src)
                self._add_import(file_id, src.split("/")[-1], src)
        for m in self._WITH.finditer(t):
            src = m.group(1)
            if src not in seen_imp:
                seen_imp.add(src)
                self._add_import(file_id, src.split(".")[-1], src)

        # File-level formal argument set -> the file's top lambda parameters.
        fm = self._FORMALS.search(t)
        if fm:
            for arg in fm.group(1).split(","):
                arg = arg.strip().rstrip("?").strip()
                if arg and arg != "...":
                    self._add_arg(arg)

        lambda_names = set()
        for m in self._LAMBDA.finditer(t):
            name = m.group(1).strip('"')
            lambda_names.add(name)
            self._add_function(file_id, name.split(".")[-1],
                               description="nix lambda binding")

        for m in self._BIND.finditer(t):
            name = m.group(1).strip('"')
            if name in lambda_names:
                continue
            val = m.group(2).strip()
            self._add_variable(file_id, name.split(".")[-1], val[:120] or None)
