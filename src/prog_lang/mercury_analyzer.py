# Mercury (.mercury) analyzer.
#
# Real parser for Mercury (a pure logic/functional language; % line and /* */
# block comments; strings "..."):
#   :- module queens.                             -> module (class)
#   :- interface.  :- implementation.              -> (section markers)
#   :- import_module list, int.                     -> imports (many)
#   :- use_module string.                            -> import
#   :- type tree(T) ---> leaf ; node(T, tree(T)).    -> type (class + constructors)
#   :- pred append(list(T), list(T), list(T)).       -> predicate declaration
#   :- func fact(int) = int.                          -> function declaration
#   append([], L, L).                                 -> clause (predicate)
#   fact(N) = F :- ...                                 -> clause (function)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_NAME = r"[a-z]\w*"


class MercuryAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "mercury"
    EXTENSIONS = (".mercury",)
    LINE_COMMENTS = ("%",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _MODULE = re.compile(r":-\s*module\s+(" + _NAME + r")\s*\.", re.IGNORECASE)
    _IMPORT = re.compile(
        r":-\s*(?:import_module|use_module)\s+(.+?)\.", re.IGNORECASE | re.DOTALL)
    _TYPE = re.compile(
        r":-\s*(?:type|solver\s+type)\s+(" + _NAME + r")", re.IGNORECASE)
    _TYPECLASS = re.compile(r":-\s*typeclass\s+(" + _NAME + r")", re.IGNORECASE)
    _PRED = re.compile(r":-\s*(?:pred|mode)\s+(" + _NAME + r")", re.IGNORECASE)
    _FUNC = re.compile(r":-\s*func\s+(" + _NAME + r")", re.IGNORECASE)
    _CLAUSE = re.compile(r"^(" + _NAME + r")\s*(?:\((.*?)\))?\s*(?:=|:-|\.)",
                         re.MULTILINE | re.DOTALL)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for rx in (self._TYPE, self._TYPECLASS):
            for m in rx.finditer(text):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._IMPORT.finditer(text):
            for mod in self._split_top_level(m.group(1)):
                mod = mod.strip()
                if re.match(r"^" + _NAME, mod):
                    nm = re.match(r"(" + _NAME + r")", mod).group(1)
                    self._add_import(file_id, nm, nm)

        # types -> classes with constructors (from `---> a ; b(...) ; ...`)
        for m in self._TYPE.finditer(text):
            name = m.group(1)
            tail = text[m.end():text.find(".", m.end()) if text.find(".", m.end()) != -1
                        else len(text)]
            attrs = []
            if "--->" in tail:
                body = tail.split("--->", 1)[1]
                for alt in body.split(";"):
                    cm = re.match(r"\s*(" + _NAME + r")", alt)
                    if cm:
                        attrs.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="mercury type", attr_ids=attrs)

        for m in self._TYPECLASS.finditer(text):
            self._add_class(file_id, m.group(1), description="mercury typeclass")

        # declared predicates / functions
        declared = set()
        for m in self._PRED.finditer(text):
            if m.group(1) not in declared:
                declared.add(m.group(1))
                self._add_function(file_id, m.group(1), [], [],
                                   description="mercury predicate")
        for m in self._FUNC.finditer(text):
            if m.group(1) not in declared:
                declared.add(m.group(1))
                self._add_function(file_id, m.group(1), [], [],
                                   description="mercury function")

        # defined clause heads not already declared (dedup by name)
        reserved = {"module", "interface", "implementation", "import_module",
                    "use_module", "type", "pred", "func", "mode", "typeclass",
                    "instance", "pragma", "inst", "end_module", "solver"}
        for m in self._CLAUSE.finditer(text):
            name = m.group(1)
            if name in reserved or name in declared:
                continue
            declared.add(name)
            args = m.group(2)
            arity = len(self._split_top_level(args)) if args and args.strip() else 0
            arg_ids = [self._add_arg(f"arg{i+1}") for i in range(arity)]
            self._add_function(file_id, name, arg_ids, [], description="mercury clause")
