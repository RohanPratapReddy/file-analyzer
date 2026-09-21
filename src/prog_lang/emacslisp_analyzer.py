# Emacs Lisp (.el) analyzer.
#
# Real parser for Emacs Lisp (s-expressions; ';' line comments; strings "..."):
#   (require 'cl-lib)                              -> import
#   (defvar my-var 10 "doc")                       -> variable
#   (defconst PI 3.14)  (defcustom foo t ...)        -> variable
#   (defun area (r) (* float-pi r r))              -> function
#   (defmacro when-let (b &rest body) ...)          -> function (macro)
#   (cl-defun greet (name &optional greeting) ...)  -> function
#   (cl-defstruct point x y)                        -> struct (class + fields)
#   (cl-defmethod area ((c circle)) ...)             -> method
#   (define-minor-mode foo-mode ...)                 -> function (mode)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_SYM = r"[A-Za-z0-9+\-*/<>=!?._%&:~^@]+"


class EmacsLispAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "emacslisp"
    EXTENSIONS = (".el",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(
        r"\(\s*(cl-defun|cl-defmacro|cl-defgeneric|cl-defsubst|defun|defmacro|"
        r"defsubst|defadvice|define-inline)\s+(" + _SYM + r")")
    _MODE = re.compile(
        r"\(\s*(define-minor-mode|define-derived-mode|define-globalized-minor-mode)"
        r"\s+(" + _SYM + r")")
    _VAR = re.compile(
        r"\(\s*(defvar-local|defvar|defconst|defcustom|defface|defvar-keymap)"
        r"\s+(" + _SYM + r")(?:\s+([^\s)]+))?")
    _STRUCT = re.compile(
        r"\(\s*cl-defstruct\s+(?:\(\s*(" + _SYM + r")|(" + _SYM + r"))")
    _METHOD = re.compile(r"\(\s*cl-defmethod\s+(" + _SYM + r")")
    _REQUIRE = re.compile(r"\(\s*require\s+'(" + _SYM + r")")
    _AUTOLOAD = re.compile(r"\(\s*autoload\s+'(" + _SYM + r")\s+\"([^\"]+)\"")

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._STRUCT.finditer(text):
            self._register_class(m.group(1) or m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._REQUIRE.finditer(text):
            self._add_import(file_id, m.group(1), m.group(1))
        for m in self._AUTOLOAD.finditer(text):
            self._add_import(file_id, m.group(1), m.group(2))

        for m in self._VAR.finditer(text):
            self._add_variable(file_id, m.group(2),
                               m.group(3).strip() if m.group(3) else None)

        for m in self._FUNC.finditer(text):
            name = m.group(2)
            params = self._arg_list(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            desc = "elisp macro" if "macro" in m.group(1) else "elisp function"
            self._add_function(file_id, name, arg_ids, [], description=desc)

        for m in self._MODE.finditer(text):
            self._add_function(file_id, m.group(2), [], [], description="elisp mode")

        # cl-defstruct -> class with slot fields
        for m in self._STRUCT.finditer(text):
            name = m.group(1) or m.group(2)
            form = self._form_at(text, m.start())
            attrs = self._struct_slots(form, name)
            self._add_class(file_id, name, description="elisp struct", attr_ids=attrs)

        # cl-defmethod -> attach to specialized class if known
        for m in self._METHOD.finditer(text):
            name = m.group(1)
            owner, params = self._method_sig(text, m.end())
            arg_ids = [self._add_arg(p) for p in params]
            cid = self._class_registry.get(owner) if owner else None
            self._add_function(file_id, name, arg_ids, [], class_id=cid,
                               description="elisp method")

    # ------------------------------------------------------------------
    def _form_at(self, text, open_pos):
        start = text.find("(", open_pos)
        if start == -1:
            return ""
        return text[start:self._find_matching(text, start, "(", ")")]

    def _arg_list(self, text, pos):
        lp = text.find("(", pos)
        for ch in text[pos:lp if lp != -1 else len(text)]:
            if not ch.isspace():
                break
        if lp == -1:
            return []
        rp = self._find_matching(text, lp, "(", ")")
        params = []
        for tok in re.findall(_SYM, text[lp + 1:rp - 1]):
            if tok.startswith("&"):
                continue
            params.append(tok)
        return params

    def _method_sig(self, text, pos):
        # skip optional qualifier symbols (:around, :before) before the arglist
        lp = text.find("(", pos)
        if lp == -1:
            return None, []
        rp = self._find_matching(text, lp, "(", ")")
        inner = text[lp + 1:rp - 1]
        owner, params = None, []
        for spec in re.finditer(r"\(\s*(" + _SYM + r")\s+(" + _SYM + r")\s*\)"
                                r"|(" + _SYM + r")", inner):
            if spec.group(1):
                params.append(spec.group(1))
                if owner is None and spec.group(2) in self._class_registry:
                    owner = spec.group(2)
            elif spec.group(3) and not spec.group(3).startswith("&"):
                params.append(spec.group(3))
        return owner, params

    def _struct_slots(self, form, name):
        # (cl-defstruct NAME slot (slot default) ...) or (cl-defstruct (NAME opts) ...)
        m = re.search(r"cl-defstruct\s+(?:\([^)]*\)|" + re.escape(name) + r")", form)
        attrs = []
        if not m:
            return attrs
        rest = form[m.end():-1] if form.endswith(")") else form[m.end():]
        i = 0
        while i < len(rest):
            ch = rest[i]
            if ch == "(":
                j = self._find_matching(rest, i, "(", ")")
                sm = re.match(r"\(\s*(" + _SYM + r")", rest[i:j])
                if sm:
                    attrs.append(self._add_arg(sm.group(1), "slot"))
                i = j
                continue
            if ch == '"':
                j = rest.find('"', i + 1)
                i = (j + 1) if j != -1 else i + 1
                continue
            sm = re.match(_SYM, rest[i:])
            if sm and not sm.group(0).startswith(":"):
                attrs.append(self._add_arg(sm.group(0), "slot"))
                i += len(sm.group(0))
                continue
            i += 1
        return attrs
