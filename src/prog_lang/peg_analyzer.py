# PEG (.peg) parsing-expression-grammar analyzer.
#
# Real parser for PEG grammar files (Bryan Ford PEG / peg/leg / pointlander-peg
# style; '#' line comments, string literals "..." and '...'):
#
#     # a grammar
#     package main                     -> (pointlander header, optional)
#     Grammar    <- Spacing Definition+ EndOfFile   -> rule (function)
#     Definition <- Identifier LEFTARROW Expression
#     Expression =  Sequence (SLASH Sequence)*      -> rule (alt arrow '=')
#     Name      <-  'literal'
#
# Every `Name <- expr` / `Name = expr` / `Name <- ... ` production becomes a
# function.  A leading `{ package ... }` action block (pointlander/peg) is
# scanned for `import` lines.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class PegAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "peg"
    EXTENSIONS = (".peg",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    # Name followed by a definition arrow: <- , <~ , =  or the unicode LEFTARROW
    _RULE = re.compile(r"^[ \t]*([A-Za-z_]\w*)\s*(?:<-|<~|←|=(?!=))",
                       re.MULTILINE)
    # pointlander/peg embeds Go: `package x` + import block / single imports
    _PACKAGE = re.compile(r"^[ \t]*package\s+([A-Za-z_]\w*)", re.MULTILINE)
    _IMPORT1 = re.compile(r'^[ \t]*import\s+"([^"]+)"', re.MULTILINE)

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        # optional Go-style imports from a pointlander/peg header
        for m in self._IMPORT1.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, re.split(r"/", src)[-1], src)
        for gm in re.finditer(r"^[ \t]*import\s*\((.*?)\)", clean,
                              re.MULTILINE | re.DOTALL):
            for line in gm.group(1).splitlines():
                sm = re.search(r'"([^"]+)"', line)
                if sm:
                    src = sm.group(1)
                    self._add_import(file_id, re.split(r"/", src)[-1], src)

        # grammar productions -> functions
        seen = set()
        for m in self._RULE.finditer(clean):
            name = m.group(1)
            if name in seen or name in ("package", "import", "type", "func"):
                continue
            seen.add(name)
            self._add_function(file_id, name, [], [], description="peg rule")
