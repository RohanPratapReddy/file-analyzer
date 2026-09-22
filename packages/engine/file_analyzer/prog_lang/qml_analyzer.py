# QML (.qml) analyzer -- Qt Modeling Language.
#
# Real parser for QML documents.  A QML file *is* a component whose name is the
# file stem and whose base type is its single root object.  We surface:
#
#     import QtQuick 2.15                     -> import
#     import QtQuick.Controls 2.5 as Ctrl     -> import (aliased)
#     import "./widgets"                       -> import (relative dir)
#     Rectangle { ... }                        -> class  (the component, base=Rectangle)
#     component Badge : Rectangle { ... }      -> class  (inline component, QML 6)
#     property int count : 0                   -> attr + variable
#     property alias inner : x.inner           -> attr + variable
#     signal clicked(int index)                -> method (signal)
#     function doIt(a, b) { ... }              -> method (function)
#
# Comments are '//' and '/* */'; strings use '"' and "'".
import re
from pathlib import Path

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_QUAL = r"[A-Za-z_][A-Za-z0-9_.]*"


class QMLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "qml"
    EXTENSIONS = (".qml",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _IMPORT_MOD = re.compile(
        r"(?m)^\s*import\s+(" + _QUAL + r")\s*([0-9.]+)?\s*(?:as\s+(" + _ID + r"))?\s*$"
    )
    _IMPORT_STR = re.compile(r'(?m)^\s*import\s+"([^"]+)"\s*(?:as\s+(' + _ID + r"))?")
    _COMPONENT = re.compile(
        r"(?m)^\s*component\s+(" + _ID + r")\s*:\s*(" + _QUAL + r")\s*\{"
    )
    _PROPERTY = re.compile(
        r"(?m)^\s*(?:default\s+|readonly\s+|required\s+)*property\s+"
        r"(alias\s+)?(list\s*<\s*" + _QUAL + r"\s*>|" + _QUAL + r")\s+(" + _ID + r")"
    )
    _SIGNAL = re.compile(r"(?m)^\s*signal\s+(" + _ID + r")\s*(?:\(([^)]*)\))?")
    _FUNCTION = re.compile(r"(?m)^\s*function\s+(" + _ID + r")\s*\(([^)]*)\)")
    _ROOT = re.compile(r"(?m)^\s*(" + _QUAL + r")\s*\{")

    def _root_type(self, clean):
        """First object type after the import block (the component's base)."""
        for m in self._ROOT.finditer(clean):
            name = m.group(1)
            if name.split(".")[0][0:1].isupper():
                return name
        return None

    def _params(self, inner):
        ids = []
        for a in self._split_top_level(inner):
            a = a.strip()
            if not a:
                continue
            # QML params may be typed: "int index" or just "index"
            parts = a.split()
            nm = parts[-1]
            typ = parts[0] if len(parts) > 1 else None
            if re.match(_ID + r"$", nm):
                ids.append(self._add_arg(nm, arg_type=typ))
        return ids

    def _register_types(self, file_id, text, path):
        stem = Path(path).stem
        if stem and stem[0:1].isalpha():
            self._register_class(stem)
        clean = self._strip_comments(text)
        for m in self._COMPONENT.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT_MOD.finditer(clean):
            src = m.group(1)
            leaf = src.split(".")[-1]
            self._add_import(file_id, leaf, src, alias=m.group(3))
        for m in self._IMPORT_STR.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src.rstrip("/"))[-1] or src
            self._add_import(file_id, leaf, src, alias=m.group(2))

        # inline components (QML 6)
        for m in self._COMPONENT.finditer(clean):
            self._add_class(
                file_id,
                m.group(1),
                description="qml component",
                parent_ids=[self._register_class(m.group(2))],
            )

        # the file itself is a component -> one class, base = root object type
        stem = Path(path).stem
        prop_ids, method_ids = [], []
        for m in self._PROPERTY.finditer(clean):
            nm = m.group(3)
            prop_ids.append(self._add_arg(nm, arg_type=(m.group(2) or "").strip()))
            self._add_variable(file_id, nm, scope="property")
        for m in self._SIGNAL.finditer(clean):
            method_ids.append(
                self._add_function(
                    file_id,
                    m.group(1),
                    self._params(m.group(2) or ""),
                    [],
                    description="qml signal",
                )
            )
        for m in self._FUNCTION.finditer(clean):
            method_ids.append(
                self._add_function(
                    file_id,
                    m.group(1),
                    self._params(m.group(2)),
                    [],
                    description="qml function",
                )
            )

        if stem and stem[0:1].isalpha():
            base = self._root_type(clean)
            parents = [self._register_class(base)] if base else None
            self._add_class(
                file_id,
                stem,
                description="qml component (file)",
                parent_ids=parents,
                method_ids=method_ids or None,
                attr_ids=prop_ids or None,
            )
