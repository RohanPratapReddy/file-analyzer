# Magik (.magik) analyzer -- Smallworld GIS object-oriented language.
#
#     _package sw                                -> import
#     def_slotted_exemplar(:my_class, {...})     -> class
#     def_indexed_exemplar(:vec, ...)            -> class
#     _pragma(...)                               -> (ignored)
#     _method my_class.do_thing(a, b) ... _endmethod  -> function
#     _private _method foo.bar() _endmethod      -> function
#     _proc @named (a, b) ... _endproc           -> function
#     x << 5                                     -> variable (assignment)
#     _local y << 3                              -> variable
#     _dynamic !current! << x                    -> variable
#
# Comments are '#'; strings use '"'. Magik is case-insensitive on keywords.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_!][A-Za-z0-9_!?]*"


class MagikAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "magik"
    EXTENSIONS = (".magik",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _PACKAGE = re.compile(r"(?im)^\s*_package\s+(" + _ID + r")")
    # alternate package declaration:  def_package(:name)
    _DEFPACKAGE = re.compile(r"def_package\s*\(\s*:(" + _ID + r")")
    _EXEMPLAR = re.compile(r"def_(?:slotted|indexed|mixin)?_?exemplar\s*\(\s*:(" + _ID + r")")
    _METHOD = re.compile(r"(?im)^\s*(?:_abstract\s+|_private\s+|_iter\s+|_pragma\s+)*"
                         r"_method\s+(" + _ID + r")\s*\.\s*(" + _ID + r")")
    _PROC = re.compile(r"(?im)_proc\s*(?:@\s*(" + _ID + r"))?\s*\(")
    _ASSIGN = re.compile(r"(?im)^\s*(?:_local\s+|_dynamic\s+|_global\s+|_constant\s+|"
                         r"_import\s+)*(" + _ID + r")\s*<<")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._EXEMPLAR.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._PACKAGE.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))
        for m in self._DEFPACKAGE.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        for m in self._EXEMPLAR.finditer(clean):
            self._add_class(file_id, m.group(1), description="magik exemplar")

        for m in self._METHOD.finditer(clean):
            owner, name = m.group(1), m.group(2)
            cls_id = self._register_class(owner)
            args = self._method_args(clean, m.end())
            self._add_function(file_id, name, args, [], class_id=cls_id,
                               description="magik method on " + owner)

        for m in self._PROC.finditer(clean):
            name = m.group(1) or "_anon_proc"
            open_paren = clean.index("(", m.end() - 1)
            args = self._paren_args(clean, open_paren)
            self._add_function(file_id, name, args, [],
                               description="magik proc")

        seen = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name.lower() in ("_self", "_clone", "_super") or name in seen:
                continue
            seen.add(name)
            self._add_variable(file_id, name, scope="local")

    def _method_args(self, clean, after_name):
        open_paren = clean.find("(", after_name)
        nl = clean.find("\n", after_name)
        if open_paren == -1 or (nl != -1 and open_paren > nl):
            return []
        return self._paren_args(clean, open_paren)

    def _paren_args(self, clean, open_paren):
        end = self._find_matching(clean, open_paren, "(", ")")
        body = clean[open_paren + 1:end - 1]
        arg_ids = []
        for part in self._split_top_level(body):
            name = part.strip().lstrip("_optional").lstrip("_gather").strip()
            name = part.strip().split()[-1] if part.strip().split() else ""
            if name and re.match(r"[A-Za-z_!]", name):
                arg_ids.append(self._add_arg(name))
        return arg_ids
