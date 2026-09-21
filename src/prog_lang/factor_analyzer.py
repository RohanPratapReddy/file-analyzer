# Factor (.factor) analyzer.
#
# Real parser for Factor (a concatenative, stack-based language; '!' line
# comments and '( ... )' stack-effect / inline comments -- both must be
# whitespace-delimited tokens; strings "..."):
#   USING: sequences math.functions ;            -> imports (many)
#   USE: kernel                                    -> import (one)
#   IN: my.vocab                                    -> (vocabulary marker)
#   : circle-area ( r -- a ) sq pi * ;             -> word (function)
#   :: clamp ( x lo hi -- y ) ... ;                 -> word (lexical args)
#   TUPLE: circle < shape radius ;                  -> tuple (class + parent + slots)
#   GENERIC: area ( shape -- n )                     -> word (generic)
#   M: circle area radius>> sq pi * ;                -> method (of circle)
#   SYMBOL: counter    CONSTANT: max 100             -> variable
#
# NOTE: '!' is a legal suffix in mutating word names (push!, set-nth!), so the
# generic comment stripper cannot be used -- comments are stripped token-aware.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_WORD = r"[^\s]+"


class FactorAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "factor"
    EXTENSIONS = (".factor",)
    LINE_COMMENTS = ()      # handled token-aware in _clean
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _USING = re.compile(r"(?:^|\s)USING:\s+(.+?)\s+;", re.DOTALL)
    _USE = re.compile(r"(?:^|\s)USE:\s+(\S+)")
    _COLON = re.compile(r"(?:^|\s)(::|:)\s+(\S+)\s+(.*?)\s+;", re.DOTALL)
    _GENERIC = re.compile(r"(?:^|\s)(?:GENERIC:|GENERIC#:|HOOK:)\s+(\S+)")
    _TUPLE = re.compile(r"(?:^|\s)TUPLE:\s+(\S+)(.*?)\s+;", re.DOTALL)
    _TUPLE_OPEN = re.compile(r"(?:^|\s)TUPLE:\s+(\S+)([^;]*)$")   # unterminated
    _METHOD = re.compile(r"(?:^|\s)M:\s+(\S+)\s+(\S+)")
    _VARWORD = re.compile(
        r"(?:^|\s)(SYMBOL:|CONSTANT:|SYMBOLS:|C:|VALUE:)\s+(\S+)")

    def _clean(self, text):
        """Strip Factor '!' / '#!' line comments token-aware, preserving newlines.
        Parenthesised groups are LEFT INTACT because a `:` definition's stack
        effect ``( in -- out )`` is the most valuable signal and is
        syntactically indistinguishable from an inline ``( comment )``; strings
        are copied verbatim."""
        out, i, n = [], 0, len(text)
        at_tok_start = True   # True when the previous char was whitespace / start
        while i < n:
            ch = text[i]
            if ch == '"':          # copy string literal verbatim
                out.append(ch)
                i += 1
                while i < n:
                    c = text[i]
                    out.append(c)
                    if c == "\\" and i + 1 < n:
                        out.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    if c == '"':
                        break
                at_tok_start = False
                continue
            # line comment: '!' or '#!' as a standalone token, to end of line
            if at_tok_start and (ch == "!" or text.startswith("#!", i)):
                nxt = i + (2 if text.startswith("#!", i) else 1)
                if nxt >= n or text[nxt] in " \t\r\n":
                    j = text.find("\n", i)
                    j = n if j == -1 else j
                    out.append(" " * (j - i))
                    i = j
                    continue
            out.append(ch)
            at_tok_start = ch in " \t\r\n"
            i += 1
        return "".join(out)

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for m in self._TUPLE.finditer(text):
            self._register_class(m.group(1))
        for m in self._TUPLE_OPEN.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        for m in self._USING.finditer(text):
            for vocab in m.group(1).split():
                self._add_import(file_id, vocab.split(".")[-1], vocab)
        for m in self._USE.finditer(text):
            self._add_import(file_id, m.group(1).split(".")[-1], m.group(1))

        for m in self._VARWORD.finditer(text):
            self._add_variable(file_id, m.group(2), None)

        # tuples: parent after '<', then slot names
        for m in self._TUPLE.finditer(text):
            self._emit_tuple(file_id, m.group(1), m.group(2))
        for m in self._TUPLE_OPEN.finditer(text):
            self._emit_tuple(file_id, m.group(1), m.group(2))

        # generic words
        for m in self._GENERIC.finditer(text):
            self._add_function(file_id, m.group(1), [], [], description="factor generic")

        # colon definitions -> words; parse ( in -- out ) if the effect survives
        for m in self._COLON.finditer(text):
            name = m.group(2)
            arg_ids, out_ids = self._stack_effect(text, m.end(2))
            self._add_function(file_id, name, arg_ids, out_ids,
                               description="factor word")

        # M: methods -> attach to the class named after M:
        for m in self._METHOD.finditer(text):
            owner, word = m.group(1), m.group(2)
            cid = self._class_registry.get(owner)
            self._add_function(file_id, word, [], [], class_id=cid,
                               description="factor method")

    # ------------------------------------------------------------------
    def _emit_tuple(self, file_id, name, rest):
        parents, attrs = [], []
        toks = rest.split()
        idx = 0
        if idx < len(toks) and toks[idx] == "<":
            idx += 1
            if idx < len(toks):
                p = toks[idx]
                if p in self._class_registry:
                    parents.append(self._class_registry[p])
                idx += 1
        for slot in toks[idx:]:
            if slot in ("{", "}", "<") or slot.startswith("{"):
                continue
            attrs.append(self._add_arg(slot, "slot"))
        self._add_class(file_id, name, description="factor tuple",
                        parent_ids=parents, attr_ids=attrs)

    def _stack_effect(self, text, name_end):
        """The stack effect '( in -- out )' immediately follows the word name.
        (Note: _clean strips *comment* parens, but the effect paren is part of a
        `:` definition head, so we re-scan the raw slice here.)"""
        rest = text[name_end:]
        m = re.match(r"\s*\(([^)]*)\)", rest)
        if not m:
            return [], []
        inner = m.group(1)
        if "--" in inner:
            before, after = inner.split("--", 1)
        else:
            before, after = inner, ""
        arg_ids = [self._add_arg(t) for t in before.split() if t not in ("(", ")")]
        out_ids = [self._add_output(t) for t in after.split() if t not in ("(", ")")]
        return arg_ids, out_ids
