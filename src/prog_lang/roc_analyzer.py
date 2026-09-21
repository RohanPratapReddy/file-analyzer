# Roc (.roc) analyzer.
#
# Roc is a young ML-family language.  A module header names the module and its
# imports; the body has type aliases, top-level defs and their type annotations:
#
#     app "hello"                            -> (header)
#     module [Model, init]                    -> (exposes)
#     interface Json exposes [decode] ...     -> class (interface module)
#     imports [pf.Stdout, json.Json]          -> import (each)
#     import pf.Stdout                         -> import (post-0.9 syntax)
#     Model : { count : I64 }                 -> class (type alias, Capitalized)
#     Color : [Red, Green, Blue]              -> class (tag-union alias)
#     increment : Model -> Model              -> function (annotation)
#     increment = \m -> ...                   -> function (definition, deduped)
#     main = ...                              -> function (value)
#
# Comments are '#'; strings use '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

# Roc effectful values carry a trailing '!' (e.g. main!, Stdout.line!); some
# builtins carry '?'.  Identifiers may include those suffixes.
_LID = r"[a-z_][A-Za-z0-9_]*[!?]?"
_UID = r"[A-Z][A-Za-z0-9_]*"
_QUAL = r"[A-Za-z_][A-Za-z0-9_.]*"


class RocAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "roc"
    EXTENSIONS = (".roc",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _INTERFACE = re.compile(r"(?m)^\s*interface\s+(" + _QUAL + r")\b")
    # `Name :: {}.{` and parameterized `Name(a) :: {}.{` module / opaque headers.
    _MODHDR = re.compile(r"(?m)^\s*(" + _UID + r")\s*(?:\([^)]*\))?\s*::")
    _MODEXPOSE = re.compile(r"(?ms)^\s*module\s*\[(.*?)\]")
    _IMPORTS = re.compile(r"(?ms)\bimports\s*\[(.*?)\]")
    _IMPORT1 = re.compile(r"(?m)^\s*import\s+(" + _QUAL + r")(?:\s+as\s+(" + _UID + r"))?")
    _PLATFORM = re.compile(r'\bplatform\s+"([^"]+)"')
    _TYPEALIAS = re.compile(r"(?m)^(" + _UID + r")\s*:(?!:)")
    _ANNOT = re.compile(r"(?m)^(" + _LID + r")\s*:(?!:)")
    _DEF = re.compile(r"(?m)^(" + _LID + r")\s*=(?!=)")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._INTERFACE.finditer(clean):
            self._register_class(m.group(1).split(".")[-1])
        for m in self._MODHDR.finditer(clean):
            self._register_class(m.group(1))
        for m in self._TYPEALIAS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INTERFACE.finditer(clean):
            self._add_class(file_id, m.group(1).split(".")[-1],
                            description="roc interface")
        for m in self._MODHDR.finditer(clean):
            self._add_class(file_id, m.group(1), description="roc module")
        for m in self._PLATFORM.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for block in self._IMPORTS.finditer(clean):
            for entry in re.split(r"[,\n]", block.group(1)):
                entry = entry.strip().split(".{")[0].strip()
                if not entry:
                    continue
                mod = entry.split()[0]
                leaf = mod.split(".")[-1]
                if re.match(r"[A-Za-z_]", leaf):
                    self._add_import(file_id, leaf, mod)
        for m in self._IMPORT1.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split(".")[-1], src, alias=m.group(2))

        for m in self._TYPEALIAS.finditer(clean):
            self._add_class(file_id, m.group(1), description="roc type alias")

        seen = set()
        for m in self._ANNOT.finditer(clean):
            nm = m.group(1)
            if nm not in seen:
                self._add_function(file_id, nm, [], [], description="roc function")
                seen.add(nm)
        for m in self._DEF.finditer(clean):
            nm = m.group(1)
            if nm not in seen:
                self._add_function(file_id, nm, [], [], description="roc def")
                seen.add(nm)

        # `module [greet, double, Foo]` exposes list: any exposed name not
        # already emitted as a def (e.g. destructured or platform-provided) is
        # still part of the module's public API -- surface it.
        for m in self._MODEXPOSE.finditer(clean):
            for nm in re.split(r"[,\s]+", m.group(1).strip()):
                nm = nm.strip()
                if not nm or nm in seen:
                    continue
                if nm[0:1].isupper():
                    self._add_class(file_id, nm, description="roc exposed type")
                elif re.match(_LID + r"$", nm):
                    self._add_function(file_id, nm, [], [],
                                       description="roc exposed value")
                    seen.add(nm)
