# Smali (.smali) analyzer  (Dalvik/ART bytecode assembly).
#
# Real parser for smali (baksmali output):
#
#     .class public Lcom/foo/Bar;          -> class (name = last path segment)
#     .super Lcom/foo/Base;                -> parent (registered as a class name)
#     .implements Lcom/foo/Iface;          -> parent (registered)
#     .source "Bar.java"                   -> import
#     .field public static N:I             -> variable (name before ':')
#     .method public run(ILjava/lang/String;)V ... .end method
#                                          -> function (name + descriptor args)
#
# Comments are '#' to end of line; strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_TYPE = r"L[\w/$]+;"


def _simple_name(desc):
    """Turn a Dalvik type 'Lcom/foo/Bar$Inner;' into 'Bar$Inner'."""
    s = desc.strip()
    if s.startswith("L") and s.endswith(";"):
        s = s[1:-1]
    return s.split("/")[-1]


# scan a method descriptor's parameter list, e.g. "I[Ljava/lang/String;Z"
_PARAM_SCAN = re.compile(r"\[*(?:[VZBSCIJFD]|L[\w/$]+;)")


class SmaliAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "smali"
    EXTENSIONS = (".smali",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _CLASS = re.compile(r"^[ \t]*\.class\b[^\n]*?(" + _TYPE + r")", re.MULTILINE)
    _SUPER = re.compile(r"^[ \t]*\.super\s+(" + _TYPE + r")", re.MULTILINE)
    _IMPL = re.compile(r"^[ \t]*\.implements\s+(" + _TYPE + r")", re.MULTILINE)
    _SOURCE = re.compile(r'^[ \t]*\.source\s+"([^"]+)"', re.MULTILINE)
    _FIELD = re.compile(
        r"^[ \t]*\.field\b[^\n]*?\b([\w$]+):(\[*(?:[VZBSCIJFD]|L[\w/$]+;))",
        re.MULTILINE,
    )
    _METHOD = re.compile(
        r"^[ \t]*\.method\b[^\n(]*?([\w$<>]+)\(([^)]*)\)", re.MULTILINE
    )

    def _desc_args(self, params):
        ids = []
        for i, m in enumerate(_PARAM_SCAN.finditer(params)):
            ids.append(self._add_arg(f"p{i}", arg_type=m.group(0)))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (self._CLASS, self._SUPER, self._IMPL):
            for m in rx.finditer(clean):
                self._register_class(_simple_name(m.group(1)))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._SOURCE.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(1))

        parent_ids = []
        for m in self._SUPER.finditer(clean):
            parent_ids.append(self._register_class(_simple_name(m.group(1))))
        for m in self._IMPL.finditer(clean):
            parent_ids.append(self._register_class(_simple_name(m.group(1))))

        cls_id = None
        for m in self._CLASS.finditer(clean):
            cls_id = self._add_class(
                file_id,
                _simple_name(m.group(1)),
                description="smali class",
                parent_ids=parent_ids,
            )

        for m in self._FIELD.finditer(clean):
            self._add_variable(file_id, m.group(1), value=m.group(2), scope="class")

        for m in self._METHOD.finditer(clean):
            arg_ids = self._desc_args(m.group(2))
            self._add_function(
                file_id,
                m.group(1),
                arg_ids,
                [],
                class_id=cls_id,
                description="smali method",
            )
