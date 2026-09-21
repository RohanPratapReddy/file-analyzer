# Yacc / Bison (.y) grammar analyzer.
#
# Real parser for yacc/bison grammar files.  Three sections split by `%%`:
#
#     %{  C prologue  %}
#     %token NUMBER IDENT           -> tokens        (variables)
#     %token <ival> INT
#     %type  <node> expr stmt       -> typed nonterminals
#     %left '+' '-'
#     %start program                -> start symbol   (variable)
#     %union { int ival; char *sval; }  -> semantic value struct  (class)
#     %%
#     program : stmt_list ;         -> nonterminal    (function)
#     expr : expr '+' expr { $$ = $1 + $3; }
#          | NUMBER          { $$ = $1; }
#          ;
#     %%
#     int main(void) { ... }        -> C functions
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_C_FUNC = re.compile(
    r"^[ \t]*(?:static\s+|inline\s+|extern\s+)*"
    r"(?:[A-Za-z_][\w\s\*]*?[\s\*])([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*\{",
    re.MULTILINE)


class YaccAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "yacc"
    EXTENSIONS = (".y",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ("'", '"')

    _TOKEN = re.compile(r"^[ \t]*%(?:token|term|nterm)\b(?:\s*<[^>]*>)?\s+(.+)$",
                        re.MULTILINE)
    _TYPE = re.compile(r"^[ \t]*%type\b(?:\s*<[^>]*>)?\s+(.+)$", re.MULTILINE)
    _START = re.compile(r"^[ \t]*%start\s+([A-Za-z_]\w*)", re.MULTILINE)
    _RULE = re.compile(r"^([a-zA-Z_]\w*)\s*:", re.MULTILINE)
    _INCLUDE = re.compile(r'^[ \t]*#\s*include\s+[<"]([^>"]+)[>"]', re.MULTILINE)

    def _sections(self, text):
        parts = re.split(r"^%%[ \t]*$", text, flags=re.MULTILINE)
        parts += ["", "", ""]
        return parts[0], parts[1], parts[2]

    def _register_types(self, file_id, text, path):
        if re.search(r"^[ \t]*%union\b", text, re.MULTILINE):
            self._register_class("YYSTYPE")

    def _extract_entities(self, file_id, text, path):
        defs, rules, epilogue = self._sections(text)
        clean_defs = self._strip_comments(defs)

        # `#include` directives from the C-embed regions (%{ %} / %code { }
        # blocks in the definition section, and the epilogue) -> imports.
        c_region = self._strip_comments(defs + "\n" + epilogue)
        for m in self._INCLUDE.finditer(c_region):
            hdr = m.group(1)
            self._add_import(file_id, hdr.replace("\\", "/").split("/")[-1], hdr)

        # tokens / typed nonterminals / start symbol -> variables
        seen_vars = set()

        def emit_names(blob, kind):
            for name in re.split(r"[ \t]+", blob.strip()):
                name = name.strip()
                if re.match(r"^[A-Za-z_]\w*$", name) and name not in seen_vars:
                    seen_vars.add(name)
                    self._add_variable(file_id, name, kind)

        for m in self._TOKEN.finditer(clean_defs):
            emit_names(m.group(1), "token")
        for m in self._TYPE.finditer(clean_defs):
            emit_names(m.group(1), "nonterminal-type")
        for m in self._START.finditer(clean_defs):
            if m.group(1) not in seen_vars:
                seen_vars.add(m.group(1))
                self._add_variable(file_id, m.group(1), "start-symbol")

        # %union { ... } -> a class whose fields are the value members
        um = re.search(r"%union\s*\{", clean_defs)
        if um:
            lb = clean_defs.find("{", um.start())
            rb = self._find_matching(clean_defs, lb, "{", "}")
            attrs = []
            for fld in re.split(r";", clean_defs[lb + 1:rb - 1]):
                fm = re.search(r"([A-Za-z_]\w*)\s*$", fld.replace("*", " ").strip())
                if fm:
                    attrs.append(self._add_arg(fm.group(1), fld.strip()))
            self._add_class(file_id, "YYSTYPE", description="yacc semantic value",
                            attr_ids=attrs)

        # grammar rules -> functions (nonterminals)
        clean_rules = self._strip_comments(rules)
        for m in self._RULE.finditer(clean_rules):
            self._add_function(file_id, m.group(1), [], [],
                               description="yacc nonterminal")

        # C functions in prologue + epilogue
        c_code = "\n".join(re.findall(r"%\{(.*?)%\}", defs, re.DOTALL)) \
            + "\n" + epilogue
        c_code = self._strip_comments(c_code)
        for m in _C_FUNC.finditer(c_code):
            name = m.group(1)
            if name in ("if", "for", "while", "switch", "return", "sizeof"):
                continue
            arg_ids = []
            for part in self._split_top_level(m.group(2)):
                if part.strip() in ("void", ""):
                    continue
                pm = re.search(r"([A-Za-z_]\w*)\s*$", part.replace("*", " "))
                if pm:
                    arg_ids.append(self._add_arg(pm.group(1), part.strip()))
            self._add_function(file_id, name, arg_ids, [], description="yacc C routine")
