# Clarity (.clar) analyzer.
#
# Real parser for Clarity (the Stacks smart-contract language; a LISP with ';;'
# line comments, no block comments; strings "..." and u"..."):
#   (use-trait ft-trait .sip-010.ft-trait)          -> import (trait)
#   (impl-trait .sip-010.sip-010-trait)              -> import (impl)
#   (define-constant ERR_OWNER (err u100))           -> variable
#   (define-data-var counter uint u0)                -> variable
#   (define-map balances principal uint)             -> variable
#   (define-fungible-token my-token)                 -> variable
#   (define-non-fungible-token my-nft uint)          -> variable
#   (define-public (transfer (amt uint) (to principal)) ...) -> function
#   (define-read-only (get-balance (who principal)) ...)     -> function
#   (define-private (helper (x uint)) ...)                    -> function
#   (define-trait ft-trait ((transfer (uint principal) (response bool uint)))) -> class (+ method sigs)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_SYM = r"[A-Za-z*+!?<>=/_-][A-Za-z0-9*+!?<>=/._-]*"


class ClarityAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "clarity"
    EXTENSIONS = (".clar",)
    LINE_COMMENTS = (";",)          # ';;' collapses under single-';' handling
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(
        r"\(\s*(define-public|define-read-only|define-private)\s+\(\s*(" + _SYM + r")")
    _VARDEF = re.compile(
        r"\(\s*(define-constant|define-data-var|define-map|"
        r"define-fungible-token|define-non-fungible-token)\s+(" + _SYM + r")")
    _TRAIT = re.compile(r"\(\s*define-trait\s+(" + _SYM + r")")
    _USE = re.compile(r"\(\s*(use-trait|impl-trait)\s+(?:(" + _SYM + r")\s+)?"
                      r"([.\w-]+)")

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._TRAIT.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._USE.finditer(text):
            kind, alias, ref = m.group(1), m.group(2), m.group(3)
            leaf = (alias or ref.split(".")[-1])
            self._add_import(file_id, leaf, ref, alias)

        for m in self._VARDEF.finditer(text):
            val = self._value_after(text, m.end())
            self._add_variable(file_id, m.group(2), val)

        for m in self._TRAIT.finditer(text):
            name = m.group(1)
            form = self._form_at(text, m.start())
            methods = []
            # method signatures:  (method-name (arg-types...) (response ok err))
            for sm in re.finditer(r"\(\s*(" + _SYM + r")\s*\(", form[len("(define-trait"):]):
                methods.append(self._add_function(
                    file_id, sm.group(1), [], [],
                    class_id=self._class_registry.get(name),
                    description="clarity trait method"))
            self._add_class(file_id, name, description="clarity trait",
                            method_ids=methods)

        for m in self._FUNC.finditer(text):
            kind, name = m.group(1), m.group(2)
            arg_ids = self._parse_params(text, m.end())
            desc = {"define-public": "clarity public",
                    "define-read-only": "clarity read-only",
                    "define-private": "clarity private"}[kind]
            self._add_function(file_id, name, arg_ids, [], description=desc)

    # ------------------------------------------------------------------
    def _parse_params(self, text, name_end):
        # after the name inside (name (a t1) (b t2)) ...): collect the (arg type)
        # pairs that live in the signature list, i.e. up to the close of the
        # signature paren that opened just before the name.
        # find the signature list bounds: the '(' immediately preceding name
        sig_open = text.rfind("(", 0, name_end)
        sig_close = self._find_matching(text, sig_open, "(", ")")
        sig = text[name_end:sig_close - 1]
        arg_ids = []
        i = 0
        while i < len(sig):
            if sig[i] == "(":
                j = self._find_matching(sig, i, "(", ")")
                inner = sig[i + 1:j - 1].strip()
                pm = re.match(r"(" + _SYM + r")\s+(.+)", inner, re.DOTALL)
                if pm:
                    arg_ids.append(self._add_arg(pm.group(1),
                                                 " ".join(pm.group(2).split())[:80]))
                i = j
            else:
                i += 1
        return arg_ids

    def _form_at(self, text, open_pos):
        start = text.find("(", open_pos)
        if start == -1:
            return ""
        end = self._find_matching(text, start, "(", ")")
        return text[start:end]

    def _value_after(self, text, pos):
        rest = text[pos:].lstrip()
        if not rest:
            return None
        if rest[0] == "(":
            end = self._find_matching(rest, 0, "(", ")")
            return rest[:end].strip()[:120]
        m = re.match(r"[^\s)]+", rest)
        return m.group(0) if m else None
