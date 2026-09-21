# Flix (.flix) analyzer.
#
# Flix is an ML/Datalog functional language with algebraic effects:
#
#     mod My.Mod { ... }                         -> class (module)
#     namespace N { ... }                        -> class (module, legacy)
#     use Foo.Bar.{baz, qux}                     -> import (base + each name)
#     import java.util.ArrayList                 -> import
#     def area(r: Int32): Int32 = ...            -> function
#     pub def map(f, l) = ...                     -> function
#     enum Shape { case Circle, case Square }    -> class
#     struct Node[r] { ... }                     -> class
#     trait Eq[a] { ... }                         -> class (type class)
#     eff Console { ... }                         -> class (effect)
#     instance Eq[Int32] { ... }                 -> (folded onto the trait)
#     type alias Pair = (Int32, Int32)           -> variable (type alias)
#
# Comments are '//', '///' and '/* */'; strings use '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
# A dotted path that does NOT gobble a trailing '.' (so `.{names}` still parses).
_QUAL = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"


class FlixAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "flix"
    EXTENSIONS = (".flix",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _MOD = re.compile(r"(?m)^\s*(?:mod|namespace)\s+(" + _QUAL + r")")
    _USE = re.compile(r"(?m)^\s*use\s+(" + _QUAL + r")\s*(?:\.\{([^}]*)\})?")
    _IMPORT = re.compile(r"(?m)^\s*import\s+(" + _QUAL + r")(?:\s*\.\{([^}]*)\})?")
    # `def` may sit inline inside a trait/instance body (`{ pub def eq(...) }`),
    # so anchor on a keyword boundary rather than line start.
    _DEF = re.compile(r"(?<![\w.])def\s+(" + _ID + r")")
    _ENUM = re.compile(r"(?m)^\s*(?:pub\s+)?(?:sealed\s+|restrictable\s+)?enum\s+(" + _ID + r")")
    _STRUCT = re.compile(r"(?m)^\s*(?:pub\s+)?struct\s+(" + _ID + r")")
    _TRAIT = re.compile(r"(?m)^\s*(?:pub\s+)?(?:trait|class)\s+(" + _ID + r")")
    _EFF = re.compile(r"(?m)^\s*(?:pub\s+)?eff\s+(" + _ID + r")")
    _ALIAS = re.compile(r"(?m)^\s*(?:pub\s+)?type\s+alias\s+(" + _ID + r")")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (self._MOD, self._ENUM, self._STRUCT, self._TRAIT, self._EFF):
            for m in rx.finditer(clean):
                self._register_class(m.group(1).split(".")[-1])

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for rx in (self._USE, self._IMPORT):
            for m in rx.finditer(clean):
                base = m.group(1)
                self._add_import(file_id, base.split(".")[-1], base)
                if m.group(2):
                    for nm in m.group(2).split(","):
                        nm = nm.strip()
                        if nm and re.match(r"[A-Za-z_]", nm):
                            self._add_import(file_id, nm, base + "." + nm)

        for m in self._MOD.finditer(clean):
            self._add_class(file_id, m.group(1).split(".")[-1],
                            description="flix module")
        for m in self._ENUM.finditer(clean):
            self._add_class(file_id, m.group(1), description="flix enum")
        for m in self._STRUCT.finditer(clean):
            self._add_class(file_id, m.group(1), description="flix struct")
        for m in self._TRAIT.finditer(clean):
            self._add_class(file_id, m.group(1), description="flix trait")
        for m in self._EFF.finditer(clean):
            self._add_class(file_id, m.group(1), description="flix effect")
        for m in self._ALIAS.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="type")

        for m in self._DEF.finditer(clean):
            self._add_function(file_id, m.group(1), [], [],
                               description="flix function")
