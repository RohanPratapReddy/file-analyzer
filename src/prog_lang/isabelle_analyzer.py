# Isabelle/HOL (.thy) theory-file analyzer.
#
# Real parser for Isabelle theory files:
#
#     theory Foo
#       imports Main HOL.List "HOL-Library.Multiset"   -> imports
#     begin
#     type_synonym addr = nat                           -> class (type alias)
#     datatype 'a tree = Leaf | Node 'a "'a tree"       -> class (datatype)
#     record point = x :: int  y :: int                 -> class (record)
#     locale group = ...                                -> class
#     definition incr :: "nat => nat" where "incr n = n + 1"   -> function
#     fun fib :: "nat => nat" where ...                 -> function
#     lemma foo_bar: "..."                              -> function (proof obligation)
#     theorem main[simp]: "..."                         -> function
#
# imports become imports, type/datatype/record/locale/class become classes and
# definition/fun/lemma/theorem/... become functions.
import re

from .regex_base import RegexCodeAnalyzer


class IsabelleAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "isabelle"
    EXTENSIONS = (".thy",)
    LINE_COMMENTS = ()  # Isabelle uses (* *) only
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _IMPORTS = re.compile(r"\bimports\b(.*?)\bbegin\b", re.DOTALL)
    _IMP_TOK = re.compile(r'"([^"]+)"|([A-Za-z_][\w.\-]*)')
    # value/proof declarations -> functions
    _DEF = re.compile(
        r"^[ \t]*(definition|fun|primrec|function|abbreviation|inductive|"
        r"coinductive|inductive_set|axiomatization|termination|"
        r"lemma|theorem|corollary|proposition|schematic_goal)\b"
        r"[ \t]+([A-Za-z_][\w.']*)?",
        re.MULTILINE,
    )
    # type declarations -> classes.  optional type params ('a  or  ('a,'b)) first.
    _TYPE = re.compile(
        r"^[ \t]*(datatype|codatatype|record|type_synonym|typedef|typedecl|"
        r"locale|class|instantiation|nominal_datatype)\b[ \t]+"
        r"(?:\([^)]*\)[ \t]*)?(?:'[A-Za-z_]\w*[ \t]+)*"
        r"([A-Za-z_][\w.']*)",
        re.MULTILINE,
    )

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        im = self._IMPORTS.search(clean)
        if im:
            for tm in self._IMP_TOK.finditer(im.group(1)):
                name = tm.group(1) or tm.group(2)
                if not name:
                    continue
                self._add_import(
                    file_id, name.replace("\\", "/").split("/")[-1].split(".")[-1], name
                )

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(2), description=f"isabelle {m.group(1)}")

        for m in self._DEF.finditer(clean):
            name = m.group(2)
            if not name:
                continue
            self._add_function(
                file_id, name, [], [], description=f"isabelle {m.group(1)}"
            )
