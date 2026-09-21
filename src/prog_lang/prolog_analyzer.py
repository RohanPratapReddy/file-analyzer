# Prolog (.prolog) analyzer.
#
# Real parser for ISO / SWI-Prolog (% line and /* */ block comments; quoted
# atoms '...' and strings "..."):
#   :- module(lists, [append/3, member/2]).      -> module (class) + exported preds
#   :- use_module(library(lists)).                 -> import
#   :- ensure_loaded(utils).                        -> import
#   :- dynamic counter/1.                            -> predicate declaration
#   append([], L, L).                                -> fact (predicate clause)
#   append([H|T], L, [H|R]) :- append(T, L, R).      -> rule (predicate clause)
#
# Predicates are grouped under the module (if declared) as its methods; a file
# with no :- module/2 emits its predicates as free functions.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ATOM = r"[a-z]\w*"


class PrologAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "prolog"
    EXTENSIONS = (".prolog",)
    LINE_COMMENTS = ("%",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _MODULE = re.compile(
        r":-\s*module\(\s*(" + _ATOM + r")\s*,\s*\[(.*?)\]\s*\)\.",
        re.IGNORECASE | re.DOTALL)
    _USE = re.compile(
        r":-\s*(?:use_module|ensure_loaded|consult|reexport)\("
        r"\s*(?:library\(\s*)?(" + _ATOM + r")", re.IGNORECASE)
    _DECL = re.compile(
        r":-\s*(?:dynamic|discontiguous|multifile|meta_predicate)\s+(.+?)\.",
        re.IGNORECASE | re.DOTALL)
    # clause head at column 0:  name(args) :-  |  name(args).  |  name.  |  name :-
    _CLAUSE = re.compile(r"^(" + _ATOM + r")\s*(?:\((.*?)\))?\s*(?::-|-->|\.)",
                         re.MULTILINE | re.DOTALL)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._MODULE.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._USE.finditer(text):
            self._add_import(file_id, m.group(1), m.group(1))

        mod = self._MODULE.search(text)
        mod_name = mod.group(1) if mod else None
        cid = self._class_registry.get(mod_name) if mod_name else None

        # exported predicate specs declared in the module directive
        exported = []
        if mod:
            for spec in self._split_top_level(mod.group(2)):
                nm = re.match(r"(" + _ATOM + r")\s*/\s*(\d+)", spec.strip())
                if nm:
                    exported.append((nm.group(1), int(nm.group(2))))

        # collect every defined clause head (dedup by name/arity), preserving order
        preds = {}   # (name, arity) -> arg count
        order = []
        for m in self._CLAUSE.finditer(text):
            name = m.group(1)
            if name in ("module", "use_module", "dynamic", "discontiguous"):
                continue
            args = m.group(2)
            arity = len(self._split_top_level(args)) if args and args.strip() else 0
            key = (name, arity)
            if key not in preds:
                preds[key] = arity
                order.append(key)

        method_ids = []
        for name, arity in order:
            arg_ids = [self._add_arg(f"arg{i+1}") for i in range(arity)]
            fid = self._add_function(file_id, name, arg_ids, [], class_id=cid,
                                     description="prolog predicate")
            method_ids.append(fid)

        # also register any exported predicate that has no in-file clause
        defined_names = {n for (n, _a) in order}
        for name, arity in exported:
            if name not in defined_names:
                arg_ids = [self._add_arg(f"arg{i+1}") for i in range(arity)]
                method_ids.append(self._add_function(
                    file_id, name, arg_ids, [], class_id=cid,
                    description="prolog exported predicate"))

        if mod_name:
            self._add_class(file_id, mod_name, description="prolog module",
                            method_ids=method_ids)
