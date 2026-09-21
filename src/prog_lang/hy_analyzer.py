# Hy (.hy) analyzer.
#
# Real parser for Hy (a Lisp dialect that compiles to Python AST; ';' line
# comments and '#_' form comments; strings "..."):
#   (import os)                                   -> import
#   (import os :as o)                              -> import (aliased)
#   (import [os.path [join basename]])             -> import (Python-style, names)
#   (require hyrule.control)                        -> import (macro module)
#   (setv COUNT 0)                                  -> variable
#   (defn area [r] (* math.pi r r))                -> function
#   (defn/a fetch [url] ...)                        -> function (async)
#   (defmacro unless [test #* body] ...)            -> function (macro)
#   (defclass Point [object] (defn __init__ [self x] ...)) -> class (+ methods)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_SYM = r"[A-Za-z_][A-Za-z0-9_.*/?!<>=+-]*"
# A Hy symbol is any run of non-whitespace, non-structural characters, so
# operator-named functions/bindings (e.g. `+`, `->`, dunders) are captured too.
_NAME = r"[^\s()\[\]{}\";'`~@,]+"


class HyAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "hy"
    EXTENSIONS = (".hy",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _DEFN = re.compile(r"\(\s*(defn/a|defn|defmacro|deftag)\s+(" + _NAME + r")")
    _CLASS = re.compile(r"\(\s*defclass\s+(" + _SYM + r")")
    _SETV = re.compile(r"\(\s*(?:setv|setx|def)\s+(" + _NAME + r")")
    _IMPORT = re.compile(r"\(\s*(import|require)\b")

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._CLASS.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._IMPORT.finditer(text):
            form = self._form_at(text, m.start())
            self._parse_import(file_id, form)

        # top-level variable bindings (skip ones nested inside a defn/defclass body
        # is hard without full parse; setv at any level is still a real binding)
        seen_var = set()
        for m in self._SETV.finditer(text):
            name = m.group(1)
            if name in seen_var or "." in name:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, self._value_after(text, m.end()))

        # classes: capture their [bases] and inner (defn ...) methods
        for m in self._CLASS.finditer(text):
            name = m.group(1)
            form = self._form_at(text, m.start())
            cid = self._class_registry.get(name)
            parents = []
            bm = re.search(r"defclass\s+" + re.escape(name) + r"\s*\[([^\]]*)\]", form)
            if bm:
                for b in re.findall(_SYM, bm.group(1)):
                    if b in self._class_registry:
                        parents.append(self._class_registry[b])
            methods = []
            for dm in self._DEFN.finditer(form):
                mname = dm.group(2)
                params = self._arg_vector(form, dm.end())
                arg_ids = [self._add_arg(p) for p in params]
                methods.append(self._add_function(
                    file_id, mname, arg_ids, [], class_id=cid,
                    description="hy method"))
            self._add_class(file_id, name, description="hy class",
                            parent_ids=parents, method_ids=methods)

        # free functions / macros (not inside a defclass form)
        class_spans = [(mm.start(), self._form_at(text, mm.start()))
                       for mm in self._CLASS.finditer(text)]
        class_ranges = []
        for start, form in class_spans:
            op = text.find("(", start)
            class_ranges.append((op, op + len(form)))

        def in_class(pos):
            return any(a <= pos < b for a, b in class_ranges)

        for m in self._DEFN.finditer(text):
            if in_class(m.start()):
                continue
            name = m.group(2)
            params = self._arg_vector(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            desc = "hy macro" if m.group(1) in ("defmacro", "deftag") else "hy function"
            self._add_function(file_id, name, arg_ids, [], description=desc)

    # ------------------------------------------------------------------
    def _parse_import(self, file_id, form):
        # (import a b) | (import a :as x) | (import [pkg [n1 n2]]) | (require m)
        body = form[form.find("import") + 6:] if "import" in form else \
            form[form.find("require") + 7:]
        body = body.rsplit(")", 1)[0]
        # bracketed selective imports first
        for bm in re.finditer(r"\[\s*(" + _SYM + r")\s*\[([^\]]*)\]\s*\]", body):
            pkg = bm.group(1)
            for n in re.findall(_SYM, bm.group(2)):
                self._add_import(file_id, n, pkg)
        stripped = re.sub(r"\[\s*" + _SYM + r"\s*\[[^\]]*\]\s*\]", " ", body)
        # remaining tokens: module optionally followed by :as alias
        toks = re.findall(r":as|" + _SYM, stripped)
        i = 0
        while i < len(toks):
            t = toks[i]
            if t == ":as":
                i += 1
                continue
            alias = None
            if i + 1 < len(toks) and toks[i + 1] == ":as" and i + 2 < len(toks):
                alias = toks[i + 2]
            self._add_import(file_id, (alias or t).split(".")[-1], t, alias)
            i += 3 if alias else 1

    def _form_at(self, text, open_pos):
        start = text.find("(", open_pos)
        if start == -1:
            return ""
        end = self._find_matching(text, start, "(", ")")
        return text[start:end]

    def _arg_vector(self, text, pos):
        lb = text.find("[", pos)
        for ch in text[pos:lb if lb != -1 else len(text)]:
            if ch in "([{":
                return []
            if not ch.isspace():
                break
        if lb == -1:
            return []
        rb = self._find_matching(text, lb, "[", "]")
        params = []
        for tok in re.findall(_SYM, text[lb + 1:rb - 1]):
            if tok in ("#*", "#**", "/", "*"):
                continue
            params.append(tok)
        return params

    def _value_after(self, text, pos):
        rest = text[pos:].lstrip()
        if not rest:
            return None
        if rest[0] == "(":
            end = self._find_matching(rest, 0, "(", ")")
            return rest[:end].strip()[:120]
        m = re.match(r"[^\s)]+", rest)
        return m.group(0) if m else None
