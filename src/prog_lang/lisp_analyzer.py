# Common Lisp (.lisp / .lsp) analyzer.
#
# Real parser for Common Lisp (s-expressions; ';' line and '#| |#' block
# comments):
#   (defpackage :app (:use :cl))                        -> import (:use symbols)
#   (require :alexandria)                                -> import
#   (defvar *count* 0) (defparameter *n* 1) (defconstant +pi+ 3.14) -> variable
#   (defun area (r) (* pi r r))                          -> function
#   (defmacro when-let (b &body body) ...)               -> function (macro)
#   (defgeneric draw (shape))                            -> function
#   (defclass point () ((x :initarg :x) (y :initarg :y))) -> class (+ slots)
#   (defmethod move ((p point) dx) ...)                   -> method of POINT
#   (defstruct person name (age 0))                       -> struct (class + fields)
import re

from .regex_base import RegexCodeAnalyzer

_SYM = r"[A-Za-z0-9+\-*/<>=!?._%&$:~^@]+"


class LispAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "lisp"
    EXTENSIONS = (".lisp", ".lsp")
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = (("#|", "|#"),)
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(
        r"\(\s*(defun|defmacro|defgeneric|define-compiler-macro|"
        r"define-modify-macro|defsetf)\s+(" + _SYM + r")",
        re.IGNORECASE,
    )
    _METHOD = re.compile(r"\(\s*defmethod\s+(" + _SYM + r")", re.IGNORECASE)
    _CLASS = re.compile(
        r"\(\s*(defclass|define-condition)\s+(" + _SYM + r")", re.IGNORECASE
    )
    _STRUCT = re.compile(
        r"\(\s*defstruct\s+(?:\(\s*(" + _SYM + r")|(" + _SYM + r"))", re.IGNORECASE
    )
    _VAR = re.compile(
        r"\(\s*(defvar|defparameter|defconstant)\s+(" + _SYM + r")"
        r"(?:\s+([^\s)]+))?",
        re.IGNORECASE,
    )
    _PKG = re.compile(r"\(\s*defpackage\s+", re.IGNORECASE)
    _REQUIRE = re.compile(r"\(\s*require\s+[:']?(" + _SYM + r")", re.IGNORECASE)
    _USE_PKG = re.compile(r"\(\s*use-package\s+[:']?(" + _SYM + r")", re.IGNORECASE)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._CLASS.finditer(text):
            self._register_class(m.group(2))
        for m in self._STRUCT.finditer(text):
            self._register_class(m.group(1) or m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        # imports: defpackage :use list, require, use-package
        for m in self._PKG.finditer(text):
            form = self._form_at(text, m.start())
            um = re.search(r"\(:use\b([^)]*)\)", form, re.IGNORECASE)
            if um:
                for sym in re.findall(_SYM, um.group(1)):
                    sym = sym.lstrip(":")
                    if sym and sym.lower() != "use":
                        self._add_import(file_id, sym, sym)
        for m in self._REQUIRE.finditer(text):
            self._add_import(file_id, m.group(1).lstrip(":"), m.group(1))
        for m in self._USE_PKG.finditer(text):
            self._add_import(file_id, m.group(1).lstrip(":"), m.group(1))

        # variables
        for m in self._VAR.finditer(text):
            self._add_variable(
                file_id, m.group(2), m.group(3).strip() if m.group(3) else None
            )

        # plain functions / macros
        for m in self._FUNC.finditer(text):
            name = m.group(2)
            params = self._lambda_list(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            self._add_function(file_id, name, arg_ids, [])

        # classes with slot definitions
        classes = {}
        for m in self._CLASS.finditer(text):
            name = m.group(2)
            form = self._form_at(text, m.start())
            parents, attrs = self._parse_defclass(form, name)
            classes[name] = {"parents": parents, "attrs": attrs, "methods": []}

        # structs with fields
        for m in self._STRUCT.finditer(text):
            name = m.group(1) or m.group(2)
            form = self._form_at(text, m.start())
            attrs = self._parse_defstruct(form, name)
            classes.setdefault(name, {"parents": [], "attrs": [], "methods": []})
            classes[name]["attrs"].extend(attrs)

        # methods: attach to the first specialized argument's class
        for m in self._METHOD.finditer(text):
            name = m.group(1)
            owner, params = self._method_signature(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            cid = self._class_registry.get(owner) if owner else None
            fid = self._add_function(file_id, name, arg_ids, [], class_id=cid)
            if owner and owner in classes:
                classes[owner]["methods"].append(fid)

        for name, c in classes.items():
            self._add_class(
                file_id,
                name,
                description="lisp class",
                parent_ids=c["parents"],
                method_ids=c["methods"],
                attr_ids=c["attrs"],
            )

    # ------------------------------------------------------------------
    def _form_at(self, text, open_paren_pos):
        start = text.find("(", open_paren_pos)
        if start == -1:
            return ""
        end = self._find_matching(text, start, "(", ")")
        return text[start:end]

    def _lambda_list(self, text, after_name_pos):
        """Return parameter symbols from the (args...) list following a name."""
        lp = text.find("(", after_name_pos)
        if lp == -1:
            return []
        rp = self._find_matching(text, lp, "(", ")")
        inner = text[lp + 1 : rp - 1]
        params = []
        for tok in re.findall(_SYM, inner):
            if tok.startswith("&"):
                continue
            if tok in (
                "&optional",
                "&rest",
                "&key",
                "&body",
                "&aux",
                "&allow-other-keys",
            ):
                continue
            params.append(tok)
        return params

    def _method_signature(self, text, after_name_pos):
        # skip optional qualifiers (keywords/symbols) before the lambda list
        lp = text.find("(", after_name_pos)
        if lp == -1:
            return None, []
        rp = self._find_matching(text, lp, "(", ")")
        inner = text[lp + 1 : rp - 1]
        owner = None
        params = []
        # each specializer is (var class) or a bare var
        for spec in re.finditer(
            r"\(\s*(" + _SYM + r")\s+(" + _SYM + r")\s*\)" r"|(" + _SYM + r")", inner
        ):
            if spec.group(1):
                params.append(spec.group(1))
                if owner is None and spec.group(2) in self._class_registry:
                    owner = spec.group(2)
            elif spec.group(3):
                t = spec.group(3)
                if t.startswith("&") or t.startswith(":"):
                    continue
                params.append(t)
        return owner, params

    def _parse_defclass(self, form, name):
        # (defclass NAME (super...) (slot...) options...)
        m = re.search(
            r"defclass\s+" + re.escape(name) + r"\s*\(([^)]*)\)", form, re.IGNORECASE
        )
        parents = []
        if m:
            for s in re.findall(_SYM, m.group(1)):
                if s in self._class_registry:
                    parents.append(self._class_registry[s])
        # slot list is the next parenthesised group after the superclass list
        attrs = []
        if m:
            rest = form[m.end() :]
            sp = rest.find("(")
            if sp != -1:
                ep = self._find_matching(rest, sp, "(", ")")
                slots = rest[sp + 1 : ep - 1]
                # each slot: symbol or (slotname ...)
                depth = 0
                i = 0
                while i < len(slots):
                    ch = slots[i]
                    if ch == "(":
                        j = self._find_matching(slots, i, "(", ")")
                        sm = re.match(r"\(\s*(" + _SYM + r")", slots[i:j])
                        if sm:
                            attrs.append(self._add_arg(sm.group(1), "slot"))
                        i = j
                        continue
                    i += 1
        return parents, attrs

    def _parse_defstruct(self, form, name):
        # (defstruct NAME slot (slot default) ...)  OR (defstruct (NAME opts) ...)
        m = re.search(
            r"defstruct\s+(?:\([^)]*\)|" + re.escape(name) + r")", form, re.IGNORECASE
        )
        attrs = []
        if not m:
            return attrs
        rest = form[m.end() : -1]
        i = 0
        while i < len(rest):
            ch = rest[i]
            if ch == "(":
                j = self._find_matching(rest, i, "(", ")")
                sm = re.match(r"\(\s*(" + _SYM + r")", rest[i:j])
                if sm:
                    attrs.append(self._add_arg(sm.group(1), "field"))
                i = j
                continue
            if ch == '"':
                # docstring
                j = rest.find('"', i + 1)
                i = (j + 1) if j != -1 else i + 1
                continue
            sm = re.match(_SYM, rest[i:])
            if sm and not sm.group(0).startswith(":"):
                attrs.append(self._add_arg(sm.group(0), "field"))
                i += len(sm.group(0))
                continue
            i += 1
        return attrs
