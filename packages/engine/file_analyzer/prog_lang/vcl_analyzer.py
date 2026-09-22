# Varnish VCL (.vcl / .varnish) analyzer.
#
# The Varnish Configuration Language declares backends, directors, ACLs, probes
# and subroutines:
#
#     vcl 4.1;                                -> (version marker, ignored)
#     import std;                             -> import
#     import directors as dir;               -> import (aliased)
#     include "backends.vcl";                -> import (included file)
#     backend default { .host = "127.0.0.1"; }-> class (with .field attrs)
#     probe health { .url = "/"; }            -> class
#     acl purge { "localhost"; }              -> class
#     sub vcl_recv { ... }                    -> function
#     sub my_helper { ... }                   -> function
#
# Comments are '//', '#' and '/* */'; strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class VCLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "vcl"
    EXTENSIONS = (".vcl", ".varnish")
    LINE_COMMENTS = ("//", "#")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r"(?m)^\s*import\s+(" + _ID + r")(?:\s+as\s+(" + _ID + r"))?\s*;"
    )
    _INCLUDE = re.compile(r'(?m)^\s*include\s+"([^"]+)"\s*;')
    _SUB = re.compile(r"(?m)^\s*sub\s+(" + _ID + r")\s*\{")
    _BACKEND = re.compile(r"(?m)^\s*backend\s+(" + _ID + r")\s*\{")
    _PROBE = re.compile(r"(?m)^\s*probe\s+(" + _ID + r")\s*\{")
    _ACL = re.compile(r"(?m)^\s*acl\s+(" + _ID + r")\s*\{")
    _FIELD = re.compile(r"(?m)^\s*\.(" + _ID + r")\s*=")

    def _block_attrs(self, clean, open_brace_pos):
        end = self._find_matching(clean, open_brace_pos)
        body = clean[open_brace_pos + 1 : end - 1]
        return [self._add_arg(m.group(1)) for m in self._FIELD.finditer(body)]

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (self._BACKEND, self._PROBE, self._ACL):
            for m in rx.finditer(clean):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1), alias=m.group(2))
        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for rx, desc in (
            (self._BACKEND, "vcl backend"),
            (self._PROBE, "vcl probe"),
            (self._ACL, "vcl acl"),
        ):
            for m in rx.finditer(clean):
                attrs = self._block_attrs(clean, m.end() - 1)
                self._add_class(
                    file_id, m.group(1), description=desc, attr_ids=attrs or None
                )

        for m in self._SUB.finditer(clean):
            self._add_function(
                file_id, m.group(1), [], [], description="vcl subroutine"
            )
