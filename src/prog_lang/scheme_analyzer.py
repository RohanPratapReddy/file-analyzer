# Scheme (.scm / .ss) analyzer.
#
# Real parser for Scheme / R6RS / R7RS (s-expressions; ';' line, '#| |#' block,
# '#;' datum comments; strings "..."):
#   (import (rnrs) (srfi :1))                            -> import
#   (use-modules (ice-9 rdelim))                          -> import
#   (load "helpers.scm")                                  -> import
#   (define (area r) (* pi r r))                          -> function
#   (define add (lambda (a b) (+ a b)))                   -> function (lambda)
#   (define *tolerance* 1e-9)                             -> variable
#   (define-syntax swap! (syntax-rules () ...))           -> function (macro)
#   (define-record-type point                            -> record (class)
#     (make-point x y) point? (x point-x) (y point-y))    -> fields
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_SYM = r"[A-Za-z0-9+\-*/<>=!?._%&$:~^]+"


class SchemeAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "scheme"
    EXTENSIONS = (".scm", ".ss")
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = (("#|", "|#"),)
    STRING_DELIMS = ('"',)

    _DEFUN = re.compile(r"\(\s*define\s*\(\s*(" + _SYM + r")", re.IGNORECASE)
    _DEFVAL = re.compile(r"\(\s*define\s+(" + _SYM + r")\s+(.*?)$",
                         re.IGNORECASE | re.MULTILINE)
    _DEFSYNTAX = re.compile(
        r"\(\s*(define-syntax|define-syntax-rule)\s*\(?\s*(" + _SYM + r")",
        re.IGNORECASE)
    _RECORD = re.compile(
        r"\(\s*define-record-type\s*\(?\s*(" + _SYM + r")", re.IGNORECASE)
    _IMPORT = re.compile(
        r"\(\s*(?:import|use-modules|require|library)\b", re.IGNORECASE)
    _LOAD = re.compile(r'\(\s*load\s+"([^"]+)"', re.IGNORECASE)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._RECORD.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        record_spans = []

        # records first (so their nested defines aren't mistaken for functions)
        for m in self._RECORD.finditer(text):
            name = m.group(1)
            form = self._form_at(text, m.start())
            record_spans.append((m.start(), m.start() + len(form)))
            attrs = self._parse_record(form, name)
            self._add_class(file_id, name, description="scheme record",
                            attr_ids=attrs)

        def in_record(pos):
            return any(a <= pos < b for a, b in record_spans)

        # imports
        for m in self._IMPORT.finditer(text):
            form = self._form_at(text, m.start())
            # collect library names: last symbol of each nested (a b c) group,
            # plus bare symbols
            for grp in re.findall(r"\(([^()]*)\)", form):
                syms = re.findall(_SYM, grp)
                syms = [s for s in syms if s.lower() not in (
                    "only", "except", "prefix", "rename", "srfi")]
                if syms:
                    self._add_import(file_id, syms[-1].lstrip(":"), " ".join(syms))
        for m in self._LOAD.finditer(text):
            src = m.group(1)
            self._add_import(file_id, Path(src).stem, src)

        # (define (name args) ...) -> function
        for m in self._DEFUN.finditer(text):
            if in_record(m.start()):
                continue
            name = m.group(1)
            params = self._lambda_list(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            self._add_function(file_id, name, arg_ids, [])

        # (define name value) -> function if lambda else variable
        for m in self._DEFVAL.finditer(text):
            if in_record(m.start()):
                continue
            name, rest = m.group(1), m.group(2).strip()
            if name.startswith("("):
                continue
            lm = re.match(r"\(\s*(lambda|case-lambda|named-lambda)\b", rest,
                          re.IGNORECASE)
            if lm:
                params = self._lambda_list(rest, lm.end())
                arg_ids = [self._add_arg(p) for p in params]
                self._add_function(file_id, name, arg_ids, [])
            else:
                val = rest.rstrip(")").strip() or None
                self._add_variable(file_id, name, val)

        # (define-syntax name ...) -> macro function
        for m in self._DEFSYNTAX.finditer(text):
            if in_record(m.start()):
                continue
            self._add_function(file_id, m.group(2), [], [], description="scheme macro")

    # ------------------------------------------------------------------
    def _form_at(self, text, pos):
        start = text.find("(", pos)
        if start == -1:
            return ""
        end = self._find_matching(text, start, "(", ")")
        return text[start:end]

    def _lambda_list(self, text, after_name_pos):
        # args may be a list (a b c), improper (a . rest), or a bare symbol
        i = after_name_pos
        while i < len(text) and text[i] in " \t\n":
            i += 1
        if i >= len(text):
            return []
        if text[i] == "(":
            rp = self._find_matching(text, i, "(", ")")
            inner = text[i + 1:rp - 1]
            return [t for t in re.findall(_SYM, inner) if t != "."]
        m = re.match(_SYM, text[i:])
        return [m.group(0)] if m else []

    def _parse_record(self, form, name):
        # fields are the (accessor ...) or (field accessor [modifier]) groups
        attrs = []
        # skip the constructor spec (make-x a b) and predicate; a field clause is
        # (field-name accessor) or (field-name accessor modifier)
        for grp in re.findall(r"\(([^()]*)\)", form):
            syms = re.findall(_SYM, grp)
            # constructor line contains 'make-' typically; predicate ends '?'
            if not syms:
                continue
            first = syms[0]
            if first.startswith("make-") or first.endswith("?"):
                continue
            # heuristic: field clause has an accessor that looks like name-field
            if len(syms) >= 2 and any("-" in s for s in syms[1:]):
                attrs.append(self._add_arg(first, "field"))
        return attrs
