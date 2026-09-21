# OCamllex (.mll) lexer-definition analyzer.
#
# Real parser for ocamllex lexer definitions:
#
#     { (* OCaml header *) open Lexing let x = 1 }   -> header (imports/lets)
#     let digit = ['0'-'9']                          -> named regex (variable)
#     let ident = ['a'-'z'] ident_char*
#     rule token = parse                             -> lexer entry (function)
#       | digit+   { INT (int_of_string ...) }
#       | "if"     { IF }
#       | eof      { EOF }
#     and comment depth = parse                      -> lexer entry with args
#       | "*)"     { ... }
#     { (* OCaml trailer *) }                        -> trailer
#
# `let NAME = regex` become variables, `rule`/`and NAME [args] = parse|shortest`
# become functions, and `open X` inside the OCaml `{ }` blocks become imports.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class OCamllexAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ocamllex"
    EXTENSIONS = (".mll",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _LET = re.compile(r"^[ \t]*let\s+([A-Za-z_]\w*)\s*=", re.MULTILINE)
    _RULE = re.compile(r"^[ \t]*(?:rule|and)\s+([A-Za-z_]\w*)([^=\n]*)=\s*"
                       r"(?:parse|shortest)\b", re.MULTILINE)
    _OPEN = re.compile(r"\bopen\s+([A-Z][\w.]*)")

    def _blank_braces(self, s):
        """Blank out `{ ... }` OCaml code blocks (keeping newlines) so their
        inner `let f x = ...` bindings are not read as regex abbreviations."""
        out = list(s)
        i = 0
        while i < len(s):
            if s[i] == "{":
                j = self._find_matching(s, i, "{", "}")
                for k in range(i, min(j, len(out))):
                    if out[k] != "\n":
                        out[k] = " "
                i = j
            else:
                i += 1
        return "".join(out)

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        # OCaml header/trailer `{ ... }` code blocks: pull `open X` imports.
        # The header is the leading brace block; scan every top-level brace block.
        for om in self._OPEN.finditer(clean):
            mod = om.group(1)
            self._add_import(file_id, mod.split(".")[-1], mod)

        # rule entrypoints (functions).  Record their spans so `let` bindings that
        # are really regex abbreviations are separated from OCaml action lets.
        rule_names = set()
        for m in self._RULE.finditer(clean):
            name = m.group(1)
            if name in rule_names:
                continue
            rule_names.add(name)
            arg_ids = []
            for a in re.split(r"[ \t]+", m.group(2).strip()):
                if re.match(r"^[A-Za-z_]\w*$", a):
                    arg_ids.append(self._add_arg(a))
            self._add_function(file_id, name, arg_ids, [],
                               description="ocamllex rule")

        # named regex abbreviations `let name = ...` in the definition area
        # (before the first `rule`).  Anything after `rule` is OCaml action code.
        first_rule = clean.find("rule ")
        head = clean if first_rule == -1 else clean[:first_rule]
        head = self._blank_braces(head)
        for m in self._LET.finditer(head):
            self._add_variable(file_id, m.group(1), "regex")
