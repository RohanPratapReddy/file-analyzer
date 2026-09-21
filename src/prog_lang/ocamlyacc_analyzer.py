# OCamlyacc / Menhir (.mly) parser-definition analyzer.
#
# Real parser for ocamlyacc / menhir grammar files.  Two `%%`-separated sections
# plus an optional trailer:
#
#     %{ open Ast (* OCaml header *) %}
#     %token <int> INT                 -> tokens        (variables)
#     %token PLUS MINUS TIMES
#     %start <Ast.expr> main           -> start symbol
#     %type  <Ast.expr> expr           -> typed nonterminal
#     %left PLUS MINUS
#     %%
#     main:                            -> nonterminal   (function)
#       | e = expr EOF { e }
#     expr:
#       | INT              { $1 }
#       | expr PLUS expr   { ... }
#     %%
#     (* OCaml trailer *)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class OCamlyaccAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "ocamlyacc"
    EXTENSIONS = (".mly",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _TOKEN = re.compile(r"^[ \t]*%token\b(?:\s*<[^>]*>)?\s+(.+)$", re.MULTILINE)
    _TYPE = re.compile(r"^[ \t]*%type\b(?:\s*<[^>]*>)?\s+(.+)$", re.MULTILINE)
    _START = re.compile(r"^[ \t]*%start\b(?:\s*<[^>]*>)?\s+(.+)$", re.MULTILINE)
    _RULE = re.compile(r"^([a-zA-Z_]\w*)\s*(?:\(([^)]*)\))?\s*:", re.MULTILINE)
    _OPEN = re.compile(r"\bopen\s+([A-Z][\w.]*)")

    def _sections(self, text):
        parts = re.split(r"^%%[ \t]*$", text, flags=re.MULTILINE)
        parts += ["", "", ""]
        return parts[0], parts[1], parts[2]

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        defs, rules, trailer = self._sections(text)
        clean_defs = self._strip_comments(defs)

        # imports from OCaml header `%{ ... %}` and trailer
        header_code = "\n".join(re.findall(r"%\{(.*?)%\}", defs, re.DOTALL))
        for blob in (self._strip_comments(header_code),
                     self._strip_comments(trailer)):
            for om in self._OPEN.finditer(blob):
                mod = om.group(1)
                self._add_import(file_id, mod.split(".")[-1], mod)

        seen = set()

        def emit_names(blob, kind):
            for name in re.split(r"[ \t]+", blob.strip()):
                name = name.strip()
                if re.match(r"^[A-Za-z_]\w*$", name) and name not in seen:
                    seen.add(name)
                    self._add_variable(file_id, name, kind)

        for m in self._TOKEN.finditer(clean_defs):
            emit_names(m.group(1), "token")
        for m in self._TYPE.finditer(clean_defs):
            emit_names(m.group(1), "nonterminal-type")
        for m in self._START.finditer(clean_defs):
            emit_names(m.group(1), "start-symbol")

        # grammar productions -> functions (with optional menhir parameters)
        clean_rules = self._strip_comments(rules)
        rseen = set()
        for m in self._RULE.finditer(clean_rules):
            name = m.group(1)
            if name in rseen:
                continue
            rseen.add(name)
            arg_ids = []
            if m.group(2):
                for p in self._split_top_level(m.group(2)):
                    pm = re.match(r"([A-Za-z_]\w*)", p.strip())
                    if pm:
                        arg_ids.append(self._add_arg(pm.group(1)))
            self._add_function(file_id, name, arg_ids, [],
                               description="menhir nonterminal")
