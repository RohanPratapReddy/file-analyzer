# YARA (.yar / .yara) analyzer.
#
# Real parser for YARA malware-detection rules:
#
#     import "pe"                          -> import
#     include "./other.yar"               -> import
#     rule Silent_Banker : banker trojan { -> class (the rule, tags noted)
#         meta:
#             author = "Anon"              -> variable (meta field)
#         strings:
#             $a = "hello"                 -> variable (string identifier)
#             $hex = { E2 34 ?? C8 }
#         condition:
#             $a and $hex
#     }
#     global private rule Foo { ... }      -> modifiers handled
#
# Comments are '//' and '/* ... */'; strings use '"'.  Rules may inherit via
# a ': base' style is not standard (that's tags), so no parents.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class YaraAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "yara"
    EXTENSIONS = (".yar", ".yara")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _RULE = re.compile(
        r"(?m)^\s*(?:(?:global|private)\s+)*rule\s+(" + _ID + r")"
        r"\s*(?::\s*([^\{]+))?\{")
    _IMPORT = re.compile(r'(?m)^\s*import\s+"([^"]+)"')
    _INCLUDE = re.compile(r'(?m)^\s*include\s+"([^"]+)"')
    _STRVAR = re.compile(r"(?m)^\s*(\$" + _ID + r"?)\s*=")
    _META = re.compile(r"(?m)^\s*(" + _ID + r")\s*=\s*")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._RULE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))
        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        # walk each rule body to attach strings/meta as members
        for m in self._RULE.finditer(clean):
            name = m.group(1)
            tags = m.group(2).split() if m.group(2) else []
            body_start = m.end() - 1
            body_end = self._find_matching(clean, body_start)
            body = clean[body_start:body_end]
            cls_id = self._add_class(
                file_id, name,
                description="yara rule" +
                (" [" + ",".join(tags) + "]" if tags else ""))
            # string identifiers -> class-scoped variables
            for sm in self._STRVAR.finditer(body):
                self._add_variable(file_id, sm.group(1), scope="rule")
            # meta fields (only within a meta: section)
            meta_m = re.search(r"(?s)\bmeta\s*:(.*?)(?:\bstrings\s*:|"
                               r"\bcondition\s*:)", body)
            if meta_m:
                for mm in self._META.finditer(meta_m.group(1)):
                    self._add_variable(file_id, name + "." + mm.group(1),
                                       scope="meta")
