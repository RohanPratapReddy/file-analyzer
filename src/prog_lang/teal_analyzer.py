# TEAL (.teal) Algorand smart-contract assembly analyzer.
#
# Real parser for TEAL (Transaction Execution Approval Language):
#
#     #pragma version 8                 -> variable (pragma directive)
#     main:                             -> function (label / jump target)
#         int 1
#         txn NumAppArgs
#         callsub is_creator            -> call site (not emitted)
#     is_creator:                       -> function (subroutine label)
#         proto 0 1
#         retsub
#
# Labels (a bare identifier followed by ':') are the only named entities in TEAL
# — they are subroutine entry points / jump targets — so they become functions;
# the `#pragma` directive is recorded as a module variable.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class TealAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "teal"
    EXTENSIONS = (".teal",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _PRAGMA = re.compile(r"^[ \t]*#pragma\s+(.+)$", re.MULTILINE)
    # a label:  optional leading ws, identifier, ':'  and nothing else of note
    _LABEL = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?://.*)?$",
                        re.MULTILINE)

    def _register_types(self, file_id, text, path):
        pass

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._PRAGMA.finditer(clean):
            parts = m.group(1).split()
            name = parts[0] if parts else "pragma"
            self._add_variable(file_id, name, m.group(1).strip()[:80])

        seen = set()
        for m in self._LABEL.finditer(clean):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            self._add_function(file_id, name, [], [], description="teal label")
