# Forth (.forth / .fth) analyzer.
#
# Real parser for Forth (a concatenative, stack-based language; '\' line
# comments and '( ... )' inline / stack comments -- both whitespace-delimited
# tokens; case-insensitive):
#   : SQUARE ( n -- n2 ) DUP * ;                  -> word (function) + stack effect
#   VARIABLE COUNTER                                -> variable
#   0 VALUE FLAG        3 CONSTANT RATE              -> variable
#   2VARIABLE POINT     FVARIABLE X                  -> variable
#   CREATE TABLE 100 ALLOT                           -> variable
#   DEFER 'HANDLER                                    -> variable (deferred word)
#
# Forth has no classes; strings use S" ..." / ." ..." (delimited by a closing
# '"'), which we do not treat as generic string literals.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class ForthAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "forth"
    EXTENSIONS = (".forth", ".fth")
    LINE_COMMENTS = ()      # handled token-aware in _clean
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    # colon definition:  : NAME ( effect ) body ;
    _COLON = re.compile(r"(?:^|\s):\s+(\S+)", re.MULTILINE)
    _DEFVAR = re.compile(
        r"(?:^|\s)(VARIABLE|2VARIABLE|FVARIABLE|CVARIABLE|CREATE|DEFER)\s+(\S+)",
        re.IGNORECASE)
    # value/constant: the NAME follows the defining word (a preceding number is
    # the initialiser and is on the stack): `0 VALUE X`, `3 CONSTANT R`
    _DEFVAL = re.compile(
        r"(?:^|\s)(VALUE|CONSTANT|2CONSTANT|FCONSTANT|2VALUE)\s+(\S+)",
        re.IGNORECASE)

    def _clean(self, text):
        """Strip Forth '\\' line comments and '( ... )' comments token-aware,
        preserving newlines. Both delimiters must be standalone tokens."""
        out, i, n = [], 0, len(text)
        at_tok_start = True
        while i < n:
            ch = text[i]
            # line comment: '\' as a token to end of line
            if at_tok_start and ch == "\\" and (i + 1 >= n or text[i + 1] in " \t\r\n"):
                j = text.find("\n", i)
                j = n if j == -1 else j
                out.append(" " * (j - i))
                i = j
                continue
            # inline comment: '(' token ... ')'
            if at_tok_start and ch == "(" and (i + 1 >= n or text[i + 1] in " \t"):
                j = text.find(")", i)
                j = n if j == -1 else j + 1
                out.append("".join(c if c == "\n" else " " for c in text[i:j]))
                i = j
                at_tok_start = True
                continue
            out.append(ch)
            at_tok_start = ch in " \t\r\n"
            i += 1
        return "".join(out)

    def _register_types(self, file_id, text, path):
        # No user-defined types/classes in standard Forth.
        pass

    def _extract_entities(self, file_id, text, path):
        # capture stack effects from RAW text (comment '(' == stack-effect '(')
        effects = {}
        for m in re.finditer(r"(?:^|\s):\s+(\S+)\s*\(([^)]*)\)", text, re.MULTILINE):
            effects[m.group(1).upper()] = m.group(2)

        text = self._clean(text)

        seen_word = set()
        for m in self._COLON.finditer(text):
            name = m.group(1)
            if name in (";",) or name.upper() in seen_word:
                continue
            seen_word.add(name.upper())
            arg_ids, out_ids = self._effect_ids(effects.get(name.upper()))
            self._add_function(file_id, name, arg_ids, out_ids,
                               description="forth word")

        seen_var = set()
        for rx in (self._DEFVAR, self._DEFVAL):
            for m in rx.finditer(text):
                name = m.group(2)
                if name.upper() in seen_var:
                    continue
                seen_var.add(name.upper())
                self._add_variable(file_id, name, None)

    # ------------------------------------------------------------------
    def _effect_ids(self, effect):
        if not effect:
            return [], []
        if "--" in effect:
            before, after = effect.split("--", 1)
        else:
            before, after = effect, ""
        arg_ids = [self._add_arg(t) for t in before.split()]
        out_ids = [self._add_output(t) for t in after.split()]
        return arg_ids, out_ids
