# Unison (.u / .unison) analyzer.
#
# Unison source declares types, abilities and named definitions:
#
#     use base.List map                       -> import (use clause)
#     unique type Optional a = None | Some a  -> class
#     structural type Tree a = ...            -> class
#     type Point = { x : Nat, y : Nat }       -> class
#     ability Stream a where emit : a -> ()   -> class (ability, effect ops as methods)
#     List.map : (a -> b) -> [a] -> [b]        -> function (signature)
#     List.map f as = ...                     -> function (definition, deduped)
#     square x = x * x                         -> function
#
# Comments are '--' and '{- -}'; strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_NAME = r"[A-Za-z_][A-Za-z0-9_'.]*"
_UID = r"[A-Z][A-Za-z0-9_']*"


class UnisonAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "unison"
    EXTENSIONS = (".u", ".unison")
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = (("{-", "-}"),)
    STRING_DELIMS = ('"',)

    _USE = re.compile(r"(?m)^\s*use\s+(" + _NAME + r")((?:\s+" + _NAME + r")*)")
    _TYPE = re.compile(r"(?m)^\s*(?:unique\s+|structural\s+)?type\s+(" + _UID + r")\b")
    _ABILITY = re.compile(
        r"(?m)^\s*(?:unique\s+|structural\s+)?ability\s+(" + _UID + r")\b"
    )
    _SIG = re.compile(r"(?m)^(" + _NAME + r")\s*:(?!:)")
    _DEF = re.compile(r"(?m)^(" + _NAME + r")\s+[^=\n]*=(?!=)")
    _DEF0 = re.compile(r"(?m)^(" + _NAME + r")\s*=(?!=)")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (self._TYPE, self._ABILITY):
            for m in rx.finditer(clean):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._USE.finditer(clean):
            base = m.group(1)
            leaf = base.split(".")[-1]
            self._add_import(file_id, leaf, base)
            for extra in (m.group(2) or "").split():
                extra = extra.strip()
                if extra:
                    self._add_import(file_id, extra.split(".")[-1], base + "." + extra)

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="unison type")
        for m in self._ABILITY.finditer(clean):
            self._add_class(file_id, m.group(1), description="unison ability")

        seen = set()
        for m in self._SIG.finditer(clean):
            nm = m.group(1)
            if nm[0:1].isupper():  # data constructor / type, not a term def
                continue
            if nm not in seen:
                self._add_function(file_id, nm, [], [], description="unison function")
                seen.add(nm)
        for rx in (self._DEF, self._DEF0):
            for m in rx.finditer(clean):
                nm = m.group(1)
                if nm[0:1].isupper() or nm in seen:
                    continue
                self._add_function(file_id, nm, [], [], description="unison def")
                seen.add(nm)
