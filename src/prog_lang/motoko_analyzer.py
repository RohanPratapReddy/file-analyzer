# Motoko (.mo) analyzer  (DFINITY / Internet Computer smart-contract language).
#
# Real parser for Motoko:
#
#     import Debug "mo:base/Debug";               -> import
#     import { print } "mo:base/Debug";           -> import
#     import Types "./types";                      -> import
#     type Account = { owner : Principal };        -> class (type)
#     actor Bank { ... }                           -> class (actor)
#     actor class Wallet(init : Nat) { ... }       -> class
#     class Vec<T>() { ... }                       -> class
#     module Utils { ... }                         -> class (module)
#     object counter { ... }                       -> class
#     public func transfer(to : Principal, amt : Nat) : async () { } -> function
#     public query func balance() : async Nat { }  -> function
#     stable var total : Nat = 0;                   -> variable
#     let name = "bank";                            -> variable
#
# Comments are '//' and (nestable) '/* */'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_MODS = r"(?:public\s+|private\s+|shared\s+|query\s+|stable\s+|transient\s+|" \
        r"flexible\s+|system\s+|composite\s+)*"


class MotokoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "motoko"
    EXTENSIONS = (".mo",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r'^[ \t]*import\s+(\{[^}]*\}|[A-Za-z_]\w*)?\s*(?:=\s*)?"([^"]+)"',
        re.MULTILINE)
    _TYPE = re.compile(r"^[ \t]*(?:public\s+|private\s+)?type\s+([A-Za-z_]\w*)",
                       re.MULTILINE)
    _CLASS = re.compile(
        r"^[ \t]*" + _MODS +
        r"(?:actor\s+class|class|actor|object|module)\s+([A-Za-z_]\w*)",
        re.MULTILINE)
    _FUNC = re.compile(
        r"^[ \t]*" + _MODS + r"func\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(",
        re.MULTILINE)
    _VAR = re.compile(
        r"^[ \t]*" + _MODS + r"(?:let|var)\s+([A-Za-z_]\w*)", re.MULTILINE)

    def _args(self, blob):
        ids = []
        for part in self._split_top_level(blob or ""):
            nm = re.match(r"([A-Za-z_]\w*)", part.strip())
            if nm:
                ty = part.split(":", 1)[1].strip() if ":" in part else None
                ids.append(self._add_arg(nm.group(1), ty))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            src = m.group(2)
            named = m.group(1)
            if named and not named.startswith("{"):
                name = named
            else:
                name = src.split("/")[-1]
            self._add_import(file_id, name, src,
                             named if named and not named.startswith("{") else None)

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="motoko type")
        for m in self._CLASS.finditer(clean):
            self._add_class(file_id, m.group(1), description="motoko class")

        for m in self._FUNC.finditer(clean):
            lp = m.end() - 1
            rp = self._find_matching(clean, lp, "(", ")")
            self._add_function(file_id, m.group(1),
                               self._args(clean[lp + 1:rp - 1]), [],
                               description="motoko func")

        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1))
