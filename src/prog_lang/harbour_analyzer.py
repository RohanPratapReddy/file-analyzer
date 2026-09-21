# Harbour / Clipper / xBase (.prg) analyzer -- classic xBase dialect.
#
#     #include "hbclass.ch"                          -> import
#     #require "hbwin"                               -> import
#     FUNCTION Main( cArg )                          -> function
#         LOCAL nX := 1                              -> variable
#         RETURN nil
#     PROCEDURE Greet( cName )                       -> function
#         ? "Hello", cName
#     RETURN
#     STATIC FUNCTION helper()                       -> function
#     CLASS TBrowse FROM TObject                     -> class (+ parent)
#         VAR nTop                                   -> variable
#         METHOD New()                               -> function (method)
#     ENDCLASS
#     METHOD TBrowse:New() CLASS TBrowse             -> function (method, owner)
#
# Comments are '//', '&&', '*' (line-lead) and '/* */'; strings '"', '\'', '['.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class HarbourAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "harbour"
    EXTENSIONS = (".prg",)
    LINE_COMMENTS = ("//", "&&")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _INCLUDE = re.compile(r'(?im)^\s*#\s*(?:include|require)\s+["<]([^">]+)[">]')
    # linker dependency directives -- module symbols pulled in / declared external
    #   REQUEST DBFNTX          -> import (force-link symbol)
    #   EXTERNAL foo, bar       -> import (external symbol refs)
    #   DYNAMIC f1, f2          -> import (dynamically-called symbols)
    _REQUEST = re.compile(r"(?im)^\s*(?:REQUEST|EXTERNAL|DYNAMIC)\s+(.+)$")
    #   ANNOUNCE RDDSYS         -> module symbol this file provides
    _ANNOUNCE = re.compile(r"(?im)^\s*ANNOUNCE\s+(" + _ID + r")")
    _FUNC = re.compile(r"(?im)^\s*(?:STATIC\s+|INIT\s+|EXIT\s+)?"
                       r"(?:FUNCTION|FUNC|PROCEDURE|PROC)\s+(" + _ID +
                       r")\s*(\([^)]*\))?")
    # method, both forms in one pass:
    #   METHOD Class:Name( args )              -> owner=Class, name=Name
    #   METHOD Name( args ) [CLASS Class]      -> name=Name, owner=Class?
    _METHOD = re.compile(r"(?im)^\s*METHOD\s+(" + _ID + r")"
                         r"(?:\s*:\s*(" + _ID + r"))?"
                         r"\s*(\([^)]*\))?"
                         r"(?:\s+CLASS\s+(" + _ID + r"))?")
    _CLASS = re.compile(r"(?im)^\s*CREATE\s+CLASS\s+(" + _ID + r")|"
                        r"^\s*CLASS\s+(" + _ID + r")\b"
                        r"(?:\s+(?:FROM|INHERIT)\s+([\w, ]+))?")
    _VAR = re.compile(r"(?im)^\s*(?:LOCAL|STATIC|PUBLIC|PRIVATE|MEMVAR|FIELD|"
                      r"PARAMETERS|VAR|DATA|CLASSVAR|CLASSDATA|INSTANCE)\s+"
                      r"(?!FUNCTION\b|PROCEDURE\b|FUNC\b|PROC\b|CLASS\b|METHOD\b)"
                      r"(.+)$")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            name = m.group(1) or m.group(2)
            if name:
                self._register_class(name)

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        seen_req = set()
        for m in self._REQUEST.finditer(clean):
            for part in self._split_top_level(m.group(1)):
                mm = re.match(_ID, part.strip())
                if mm and mm.group(0) not in seen_req:
                    seen_req.add(mm.group(0))
                    self._add_import(file_id, mm.group(0), mm.group(0))
        for m in self._ANNOUNCE.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")

        class_names = set()
        for m in self._CLASS.finditer(clean):
            name = m.group(1) or m.group(2)
            if not name:
                continue
            class_names.add(name)
            pids = None
            if m.group(3):
                pids = []
                for p in self._split_top_level(m.group(3)):
                    p = p.strip()
                    if p:
                        pids.append(self._register_class(p))
            self._add_class(file_id, name, description="xbase class",
                            parent_ids=pids or None)

        for m in self._FUNC.finditer(clean):
            args = self._prg_args(m.group(2))
            self._add_function(file_id, m.group(1), args, [],
                               description="xbase function")

        for m in self._METHOD.finditer(clean):
            if m.group(2):                        # METHOD Class:Name(...)
                owner, name, argsrc = m.group(1), m.group(2), m.group(3)
            else:                                 # METHOD Name(...) [CLASS X]
                owner, name, argsrc = m.group(4), m.group(1), m.group(3)
            if name.upper() in ("CLASS", "FUNCTION", "PROCEDURE"):
                continue
            cls_id = self._register_class(owner) if owner else None
            args = self._prg_args(argsrc)
            self._add_function(file_id, name, args, [], class_id=cls_id,
                               description="xbase method")

        seen = set()
        for m in self._VAR.finditer(clean):
            for name in self._var_names(m.group(1)):
                if name and name not in seen:
                    seen.add(name)
                    self._add_variable(file_id, name, scope="module")

    def _var_names(self, body):
        names = []
        for part in self._split_top_level(body):
            part = part.strip()
            # name may carry `:= value`, `AS type`, `IN workarea`
            part = re.split(r":=|\bAS\b|\bIN\b|\bINIT\b", part, flags=re.I)[0]
            m = re.match(_ID, part.strip())
            if m and m.group(0).upper() not in ("AS", "IN", "INIT"):
                names.append(m.group(0))
        return names

    def _prg_args(self, group):
        if not group or not group.strip("() "):
            return []
        inner = group.strip()[1:-1]
        arg_ids = []
        for part in self._split_top_level(inner):
            part = part.strip()
            part = re.split(r"\bAS\b|:=", part, flags=re.I)[0].strip()
            m = re.match(_ID, part)
            if m:
                arg_ids.append(self._add_arg(m.group(0)))
        return arg_ids
