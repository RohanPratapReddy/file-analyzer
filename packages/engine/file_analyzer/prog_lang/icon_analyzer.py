# Icon / Unicon (.icn) analyzer.
#
# Real parser for the Icon language and its Unicon OO extension:
#
#     procedure main(args)                 -> function (with args)
#         ...
#     end
#     procedure fib(n)                     -> function
#     record point(x, y, z)                -> class (fields as attrs)
#     class Stack(items, size)             -> class (Unicon)
#         method push(x)                   -> method
#         end
#     end
#     global count, total                  -> variables
#     link graphics                        -> import
#     import util                          -> import (Unicon package)
#     $include "definitions.icn"           -> import (preprocessor)
#
# Comments are '#'; strings use '"' and "'".  Bodies run to a matching 'end'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class IconAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "icon"
    EXTENSIONS = (".icn",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _PROC = re.compile(r"(?m)^\s*procedure\s+(" + _ID + r")\s*\(([^)]*)\)")
    _METHOD = re.compile(r"(?m)^\s*method\s+(" + _ID + r")\s*\(([^)]*)\)")
    _RECORD = re.compile(r"(?m)^\s*record\s+(" + _ID + r")\s*\(([^)]*)\)")
    _CLASS = re.compile(r"(?m)^\s*class\s+(" + _ID + r")\s*(?:\(([^)]*)\))?")
    _GLOBAL = re.compile(r"(?m)^\s*global\s+(.+)$")
    _LINK = re.compile(r"(?m)^\s*link\s+(.+)$")
    _IMPORT = re.compile(r"(?m)^\s*import\s+(.+)$")
    _INCLUDE = re.compile(r'(?m)^\s*\$include\s+"([^"]+)"')
    _DEFINE = re.compile(r"(?m)^\s*\$define\s+(" + _ID + r")")

    def _args(self, inner):
        ids = []
        for a in self._split_top_level(inner):
            nm = re.match(_ID, a.strip())
            if nm:
                ids.append(self._add_arg(nm.group(0)))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._RECORD.finditer(clean):
            self._register_class(m.group(1))
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._LINK.finditer(clean):
            for nm in re.split(r"[,\s]+", m.group(1).strip()):
                nm = nm.strip().strip('"')
                if re.match(_ID, nm):
                    self._add_import(file_id, nm, nm)
        for m in self._IMPORT.finditer(clean):
            for nm in re.split(r"[,\s]+", m.group(1).strip()):
                if re.match(_ID, nm):
                    self._add_import(file_id, nm, nm)
        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for m in self._RECORD.finditer(clean):
            attr_ids = [
                self._add_arg(a.strip())
                for a in self._split_top_level(m.group(2))
                if a.strip()
            ]
            self._add_class(
                file_id,
                m.group(1),
                description="icon record",
                attr_ids=attr_ids or None,
            )

        for m in self._CLASS.finditer(clean):
            attr_ids = [
                self._add_arg(a.strip())
                for a in self._split_top_level(m.group(2) or "")
                if a.strip()
            ]
            self._add_class(
                file_id,
                m.group(1),
                description="unicon class",
                attr_ids=attr_ids or None,
            )

        for m in self._PROC.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._args(m.group(2)),
                [],
                description="icon procedure",
            )
        for m in self._METHOD.finditer(clean):
            self._add_function(
                file_id,
                m.group(1),
                self._args(m.group(2)),
                [],
                description="unicon method",
            )

        for m in self._GLOBAL.finditer(clean):
            for nm in m.group(1).split(","):
                nn = re.match(_ID, nm.strip())
                if nn:
                    self._add_variable(file_id, nn.group(0), scope="global")
        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="define")
