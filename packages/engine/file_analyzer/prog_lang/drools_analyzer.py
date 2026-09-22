# Drools DRL (.drl) analyzer -- Drools Rule Language.
#
#     package com.example.rules               -> (namespace, ignored)
#     import com.example.Customer             -> import
#     import function com.util.Math.max       -> import (static function)
#     global java.util.List results           -> variable (global)
#     declare Person                           -> class (fact type)
#         name : String                        ->   attr
#         age  : int                           ->   attr
#     end
#     function String greet(String n) { ... }  -> function
#     rule "discount"                          -> function (rule unit)
#         when ... then ... end
#     query "adults"(int min)                  -> function
#         ...
#     end
#
# Comments are '//' and '/* */'; strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_$][A-Za-z0-9_$]*"
_QUAL = r"[A-Za-z_$][A-Za-z0-9_$.]*"
_TYPE = r"[A-Za-z_$][A-Za-z0-9_$<>\[\].]*"


class DroolsAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "drools"
    EXTENSIONS = (".drl",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _IMPORT = re.compile(r"(?m)^\s*import\s+(?:function\s+|static\s+)?(" + _QUAL + r")")
    _GLOBAL = re.compile(r"(?m)^\s*global\s+(" + _TYPE + r")\s+(" + _ID + r")\s*;?")
    _DECLARE = re.compile(r"(?ms)^\s*declare\s+(" + _ID + r")(.*?)^\s*end\b")
    _FIELD = re.compile(r"(?m)^\s*(" + _ID + r")\s*:\s*(" + _TYPE + r")")
    _FUNCTION = re.compile(
        r"(?m)^\s*function\s+(" + _TYPE + r")\s+(" + _ID + r")\s*\(([^)]*)\)"
    )
    _RULE = re.compile(r'(?m)^\s*rule\s+"([^"]+)"')
    _RULE_ID = re.compile(r"(?m)^\s*rule\s+(" + _ID + r")\b")
    _QUERY = re.compile(
        r'(?m)^\s*query\s+(?:"([^"]+)"|(' + _ID + r"))\s*(?:\(([^)]*)\))?"
    )

    def _args(self, inner):
        ids = []
        for a in self._split_top_level(inner):
            a = a.strip()
            if not a:
                continue
            parts = a.split()
            nm = parts[-1]
            typ = " ".join(parts[:-1]) or None
            if re.match(_ID + r"$", nm):
                ids.append(self._add_arg(nm, arg_type=typ))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._DECLARE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split(".")[-1], src)
        for m in self._GLOBAL.finditer(clean):
            self._add_variable(file_id, m.group(2), scope="global")

        for m in self._DECLARE.finditer(clean):
            attrs = [
                self._add_arg(fm.group(1), arg_type=fm.group(2))
                for fm in self._FIELD.finditer(m.group(2))
            ]
            self._add_class(
                file_id,
                m.group(1),
                description="drools fact type",
                attr_ids=attrs or None,
            )

        for m in self._FUNCTION.finditer(clean):
            out = [self._add_output(m.group(1))] if m.group(1) != "void" else []
            self._add_function(
                file_id,
                m.group(2),
                self._args(m.group(3)),
                out,
                description="drools function",
            )

        for m in self._RULE.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], description="drools rule")
        for m in self._RULE_ID.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], description="drools rule")
        for m in self._QUERY.finditer(clean):
            name = m.group(1) or m.group(2)
            self._add_function(
                file_id,
                name,
                self._args(m.group(3) or ""),
                [],
                description="drools query",
            )
