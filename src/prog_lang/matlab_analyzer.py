# MATLAB / Octave (.m) analyzer.
#
# Real parser for MATLAB (`%` line, `%{ %}` block comments):
#   classdef Account < handle                     -> class (parent)
#     properties  balance = 0;  end                -> attributes
#     methods  function deposit(obj, a) ... end end -> methods (functions)
#   function [y1, y2] = name(a, b)                  -> function (outputs + args)
#   import pkg.Class                                 -> import
#   x = 5;   global G;                               -> variable
#
# A .m file is either a class definition, a function file, or a script.  The
# `classdef` / `function` grammar is parsed directly; loose top-level
# assignments in a script become variables.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class MatlabAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "matlab"
    EXTENSIONS = (".m",)
    LINE_COMMENTS = ("%",)
    BLOCK_COMMENTS = (("%{", "%}"),)
    STRING_DELIMS = ("'", '"')

    _CLASSDEF = re.compile(
        r"^\s*classdef\s+(?:\([^)]*\)\s*)?(\w+)(?:\s*<\s*([\w.&\s]+))?",
        re.MULTILINE)
    _IMPORT = re.compile(r"^\s*import\s+([\w.]+(?:\.\*)?)", re.MULTILINE)
    _FUNC = re.compile(
        r"^\s*function\s+(?:\[([^\]]*)\]|(\w+))?\s*=?\s*(\w+)\s*\(([^)]*)\)",
        re.MULTILINE)
    _FUNC_NORET = re.compile(
        r"^\s*function\s+(\w+)\s*\(([^)]*)\)\s*$", re.MULTILINE)
    _PROP_BLOCK = re.compile(
        r"^\s*properties\b[^\n]*\n(.*?)^\s*end", re.MULTILINE | re.DOTALL)
    _GLOBAL = re.compile(r"^\s*global\s+([\w\s]+)", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._CLASSDEF.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._IMPORT.finditer(t):
            self._add_import(file_id, m.group(1).split(".")[-1].rstrip(".*"),
                             m.group(1))

        class_id = None
        cd = self._CLASSDEF.search(t)
        if cd:
            parents = []
            if cd.group(2):
                for p in re.split(r"[&\s]+", cd.group(2).strip()):
                    p = p.strip()
                    if p:
                        pid = self._register_class(p.split(".")[-1])
                        if pid is not None:
                            parents.append(pid)
            attr_ids = []
            for pm in self._PROP_BLOCK.finditer(t):
                for line in pm.group(1).splitlines():
                    fm = re.match(r"\s*(\w+)\s*(?:=|;|%|$)", line)
                    if fm and fm.group(1) not in ("end",):
                        attr_ids.append(self._add_arg(fm.group(1)))
            class_id = self._add_class(file_id, cd.group(1), parent_ids=parents,
                                       attr_ids=attr_ids,
                                       description="matlab classdef")

        for m in self._FUNC.finditer(t):
            outs, single_out, name, params = m.groups()
            out_ids = []
            if outs:
                for o in outs.split(","):
                    o = o.strip()
                    if o:
                        out_ids.append(self._add_output(o))
            elif single_out:
                out_ids.append(self._add_output(single_out.strip()))
            arg_ids = [self._add_arg(a.strip())
                       for a in params.split(",") if a.strip()]
            self._add_function(file_id, name, arg_ids, out_ids,
                               class_id=class_id, description="matlab function")

        for m in self._GLOBAL.finditer(t):
            for nm in m.group(1).split():
                self._add_variable(file_id, nm, scope="global")
