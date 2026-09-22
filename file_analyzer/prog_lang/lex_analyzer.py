# Lex / Flex (.l) scanner-definition analyzer.
#
# Real parser for lex/flex scanner definitions.  A lex file has three sections
# separated by lines consisting of `%%`:
#
#     %{  C prologue  %}            -> functions live in the C code
#     %option noyywrap
#     DIGIT    [0-9]               -> named definition   (variable)
#     ID       [a-zA-Z_][a-zA-Z0-9_]*
#     %x STRING                    -> exclusive start condition (class/state)
#     %s COMMENT                   -> inclusive start condition (class/state)
#     %%
#     {DIGIT}+     { return NUM; } -> a rule (pattern -> action)
#     "if"         { return IF;  }
#     %%
#     int main(void) { ... }       -> C functions (epilogue)
#
# Named definitions become variables, start-condition states become classes and
# any C function found in the `%{ %}` blocks / epilogue becomes a function.
import re

from .regex_base import RegexCodeAnalyzer

# a C function definition:  ret_type  name ( args ) {
_C_FUNC = re.compile(
    r"^[ \t]*(?:static\s+|inline\s+|extern\s+)*"
    r"(?:[A-Za-z_][\w\s\*]*?[\s\*])([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*\{",
    re.MULTILINE,
)


class LexAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "lex"
    EXTENSIONS = (".l",)
    LINE_COMMENTS = ()  # lex '//' is not a comment; C /* */ only
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _STATE = re.compile(r"^[ \t]*%[xs]\s+(.+)$", re.MULTILINE)
    _DEF = re.compile(r"^([A-Za-z_]\w*)[ \t]+(\S.*)$", re.MULTILINE)
    _INCLUDE = re.compile(r'^[ \t]*#\s*include\s+[<"]([^>"]+)[>"]', re.MULTILINE)

    def _sections(self, text):
        """Return (definitions, rules, user_code) split on lone `%%` lines."""
        parts = re.split(r"^%%[ \t]*$", text, flags=re.MULTILINE)
        parts += ["", "", ""]
        return parts[0], parts[1], parts[2]

    def _register_types(self, file_id, text, path):
        # start-condition states are the only "types" we reserve
        for m in self._STATE.finditer(text):
            for name in re.split(r"[ \t]+", m.group(1).strip()):
                if re.match(r"^[A-Za-z_]\w*$", name):
                    self._register_class(name)

    def _extract_entities(self, file_id, text, path):
        defs, rules, epilogue = self._sections(text)
        clean_defs = self._strip_comments(defs)

        # `#include` directives from the C-embed regions (%{ %} / %top{ } blocks
        # in the definition section, and the epilogue) -> imports.
        c_region = self._strip_comments(defs + "\n" + epilogue)
        for m in self._INCLUDE.finditer(c_region):
            hdr = m.group(1)
            self._add_import(file_id, hdr.replace("\\", "/").split("/")[-1], hdr)

        # start-condition states -> classes
        for m in self._STATE.finditer(text):
            for name in re.split(r"[ \t]+", m.group(1).strip()):
                if re.match(r"^[A-Za-z_]\w*$", name):
                    self._add_class(file_id, name, description="lex start condition")

        # named definitions:  NAME  pattern   (definition section only)
        in_brace = 0
        for line in clean_defs.splitlines():
            in_brace += line.count("{") - line.count("}")
            if line.lstrip().startswith("%"):
                continue
            if in_brace > 0:
                continue
            m = self._DEF.match(line)
            if m and not line.startswith(("%{", "%}")):
                self._add_variable(file_id, m.group(1), m.group(2).strip()[:80])

        # C functions in the `%{ %}` blocks of the definition section + epilogue
        c_code = (
            "\n".join(re.findall(r"%\{(.*?)%\}", defs, re.DOTALL)) + "\n" + epilogue
        )
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
            self._add_function(file_id, name, arg_ids, [], description="lex C routine")
