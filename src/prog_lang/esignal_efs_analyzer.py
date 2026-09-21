# eSignal Formula Script (.els / EFS).
#
# EFS is eSignal's charting/study language: an ECMAScript (JavaScript) dialect
# with a handful of reserved study entry points (preMain / main).  A study
# looks like:
#
#     function preMain() {
#         setStudyTitle("My MA");
#         setCursorLabelName("MA", 0);
#     }
#     var xMA = null;
#     var nLength = 20;
#     function main(nInputLength) {
#         if (xMA == null) xMA = sma(nLength);
#         return xMA.getValue(0);
#     }
#
# Recovered symbols:
#   * `function name(args) { ... }`                       -> function
#   * `name = function (args) { ... }` (expression form)  -> function
#   * `var|let|const name [= value]`                      -> variable
#   * a top-level `#include "file"` (rare EFS2 preprocessor) or
#     `library("name")`                                   -> import
# `//` and `/* ... */` are comments; `"` and `'` delimit strings.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_$][A-Za-z0-9_$]*"


class ESignalEFSAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "esignal_efs"
    EXTENSIONS = (".els",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _FUNC = re.compile(r"(?m)\bfunction\s+(" + _ID + r")\s*\(([^)]*)\)")
    _FUNC_EXPR = re.compile(r"(?m)^[ \t]*(?:var\s+|let\s+|const\s+)?(" + _ID +
                            r")\s*=\s*function\s*\(")
    _VAR = re.compile(r"(?m)^[ \t]*(?:var|let|const)\s+(" + _ID + r")\b")
    _IMPORT = re.compile(r'(?m)(?:^[ \t]*#\s*include\s+"([^"]+)"|'
                         r'\blibrary\s*\(\s*"([^"]+)")')

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            arg_ids = []
            for a in self._split_top_level(m.group(2)):
                a = a.strip()
                if a:
                    arg_ids.append(self._add_arg(a))
            self._add_function(file_id, name, arg_ids, [],
                               description="EFS function")
        for m in self._FUNC_EXPR.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_function(file_id, name, [], [],
                                   description="EFS function")

        seen_v = set()
        for m in self._VAR.finditer(clean):
            name = m.group(1)
            if name in seen_fn or name in seen_v:
                continue
            seen_v.add(name)
            self._add_variable(file_id, name, None, scope="module")

        seen_i = set()
        for m in self._IMPORT.finditer(clean):
            src = m.group(1) or m.group(2)
            if src and src not in seen_i:
                seen_i.add(src)
                self._add_import(file_id, src.split("/")[-1], src)
