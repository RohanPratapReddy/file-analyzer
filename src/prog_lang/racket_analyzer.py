# Racket (.rkt) analyzer.
#
# Real parser for Racket (s-expressions; ';' line, '#| |#' block, '#;' datum
# comments; strings "..."):
#   #lang racket                                         -> (language marker)
#   (require racket/list (only-in racket/math pi))       -> import
#   (provide area point)                                 -> (export marker)
#   (define (area r) (* pi r r))                          -> function
#   (define greet (lambda (n) ...))                       -> function
#   (define TAU 6.283)                                    -> variable
#   (struct point (x y) #:transparent)                    -> struct (class + fields)
#   (define-struct posn (x y))                            -> struct (class + fields)
#   (define-syntax-rule (swap a b) ...)                   -> function (macro)
import re

from .regex_base import RegexCodeAnalyzer

_SYM = r"[A-Za-z0-9+\-*/<>=!?._%&$:~^]+"


class RacketAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "racket"
    EXTENSIONS = (".rkt",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = (("#|", "|#"),)
    STRING_DELIMS = ('"',)

    _DEFUN = re.compile(r"\(\s*define\s*\(\s*(" + _SYM + r")", re.IGNORECASE)
    _DEFVAL = re.compile(
        r"\(\s*define\s+(" + _SYM + r")\s+(.*?)$", re.IGNORECASE | re.MULTILINE
    )
    _STRUCT = re.compile(
        r"\(\s*(?:struct|define-struct)\s+\(?\s*(" + _SYM + r")", re.IGNORECASE
    )
    _DEFSYNTAX = re.compile(
        r"\(\s*(define-syntax-rule|define-simple-macro|define-syntax)\s*\(?\s*("
        + _SYM
        + r")",
        re.IGNORECASE,
    )
    _REQUIRE = re.compile(r"\(\s*require\b", re.IGNORECASE)
    _LANG = re.compile(r"^#lang\s+(\S+)", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._STRUCT.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        # structs first
        struct_spans = []
        for m in self._STRUCT.finditer(text):
            name = m.group(1)
            form = self._form_at(text, m.start())
            struct_spans.append((m.start(), m.start() + len(form)))
            attrs = self._struct_fields(text, m.end())
            self._add_class(file_id, name, description="racket struct", attr_ids=attrs)

        def in_struct(pos):
            return any(a <= pos < b for a, b in struct_spans)

        # imports (require)
        for m in self._REQUIRE.finditer(text):
            form = self._form_at(text, m.start())
            inner = form[form.find("require") + len("require") : -1]
            # top-level tokens and (sub-form ...) module paths
            i = 0
            while i < len(inner):
                ch = inner[i]
                if ch == "(":
                    j = self._find_matching(inner, i, "(", ")")
                    raw = re.findall(_SYM, inner[i:j])
                    kw = raw[0].lower() if raw else ""
                    # For require sub-forms the module spec position depends on
                    # the leading keyword: prefix-in puts it second, all the
                    # others (only-in/except-in/rename-in/combine-in/for-*) first.
                    if kw in (
                        "only-in",
                        "except-in",
                        "rename-in",
                        "combine-in",
                        "relative-in",
                        "multi-in",
                        "for-syntax",
                        "for-template",
                        "for-label",
                        "for-meta",
                    ):
                        mod = raw[1] if len(raw) > 1 else raw[0]
                    elif kw == "prefix-in":
                        mod = raw[2] if len(raw) > 2 else raw[-1]
                    elif kw == "submod":
                        mod = raw[1] if len(raw) > 1 else raw[0]
                    else:
                        mod = raw[-1] if raw else ""
                    if mod:
                        self._add_import(file_id, mod.split("/")[-1], mod)
                    i = j
                    continue
                sm = re.match(_SYM, inner[i:])
                if sm:
                    mod = sm.group(0)
                    self._add_import(file_id, mod.split("/")[-1], mod)
                    i += len(mod)
                    continue
                i += 1

        # functions
        for m in self._DEFUN.finditer(text):
            if in_struct(m.start()):
                continue
            name = m.group(1)
            params = self._lambda_list(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            self._add_function(file_id, name, arg_ids, [])

        # define name value
        for m in self._DEFVAL.finditer(text):
            if in_struct(m.start()):
                continue
            name, rest = m.group(1), m.group(2).strip()
            if name.startswith("("):
                continue
            lm = re.match(r"\(\s*(lambda|case-lambda|Î»)\b", rest, re.IGNORECASE)
            if lm:
                params = self._lambda_list(rest, lm.end())
                arg_ids = [self._add_arg(p) for p in params]
                self._add_function(file_id, name, arg_ids, [])
            else:
                self._add_variable(file_id, name, rest.rstrip(")").strip() or None)

        # macros
        for m in self._DEFSYNTAX.finditer(text):
            if in_struct(m.start()):
                continue
            self._add_function(file_id, m.group(2), [], [], description="racket macro")

    # ------------------------------------------------------------------
    def _form_at(self, text, pos):
        start = text.find("(", pos)
        if start == -1:
            return ""
        end = self._find_matching(text, start, "(", ")")
        return text[start:end]

    def _lambda_list(self, text, after_name_pos):
        i = after_name_pos
        while i < len(text) and text[i] in " \t\n":
            i += 1
        if i >= len(text):
            return []
        if text[i] == "(":
            rp = self._find_matching(text, i, "(", ")")
            inner = text[i + 1 : rp - 1]
            out = []
            for t in re.findall(_SYM, inner):
                if t == "." or t.startswith("#"):
                    continue
                out.append(t)
            return out
        m = re.match(_SYM, text[i:])
        return [m.group(0)] if m else []

    def _struct_fields(self, text, after_name_pos):
        lp = text.find("(", after_name_pos)
        if lp == -1:
            return []
        rp = self._find_matching(text, lp, "(", ")")
        inner = text[lp + 1 : rp - 1]
        attrs = []
        for t in re.findall(_SYM, inner):
            if not t.startswith("#"):
                attrs.append(self._add_arg(t, "field"))
        return attrs
