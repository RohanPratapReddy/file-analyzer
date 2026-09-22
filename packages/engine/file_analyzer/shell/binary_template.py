# Binary-format template languages: 010 Editor Binary Templates (.bt) and ImHex
# pattern language (.hexpat).  Both are C-like: struct/union/enum type
# definitions, functions, and #include directives describe a binary layout.
import re

from .shell_base import ShellScriptBase


class BinaryTemplateAnalyzer(ShellScriptBase):
    """010 Editor Binary Templates (.bt) and ImHex patterns (.hexpat).

    ``struct Name { ... }`` / ``union`` / ``bitfield`` -> class (a layout type)
    ``enum [<T>] Name { ... }``                        -> class
    ``typedef T Name``                                 -> class (a named alias)
    ``RetType Name(args) { ... }``                     -> function
    ``#include "file"`` / ``import std.mem;``          -> import
    ``#define NAME value``                             -> variable
    """

    LANG_KEY = "binary-template"
    EXTENSIONS = (".bt", ".hexpat")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _STRUCT = re.compile(r"(?m)\b(struct|union|bitfield)[ \t]+([A-Za-z_]\w*)")
    _ENUM = re.compile(r"(?m)\benum[ \t]+(?:<[^>]+>[ \t]*)?([A-Za-z_]\w*)")
    _TYPEDEF = re.compile(r"(?m)^[ \t]*typedef[ \t]+.*?\b([A-Za-z_]\w*)[ \t]*;")
    _FUNC = re.compile(
        r"(?m)^[ \t]*(?:[\w<>\[\].]+)[ \t]+([A-Za-z_]\w*)[ \t]*\(([^)]*)\)[ \t]*\{"
    )
    _INCLUDE = re.compile(r'(?mi)^[ \t]*#include[ \t]+[<"]([^>"]+)[>"]')
    _IMPORT = re.compile(r"(?m)^[ \t]*import[ \t]+([\w.]+)")
    _DEFINE = re.compile(r"(?mi)^[ \t]*#define[ \t]+(\w+)[ \t]*(.*)")
    _KW = {"if", "for", "while", "switch", "return", "sizeof", "else"}

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._STRUCT.finditer(clean):
            self._register_class(m.group(2))
        for m in self._ENUM.finditer(clean):
            self._register_class(m.group(1))
        for m in self._TYPEDEF.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = set()
        for m in self._STRUCT.finditer(clean):
            name = m.group(2)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description=m.group(1))
        for m in self._ENUM.finditer(clean):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="enum")
        for m in self._TYPEDEF.finditer(clean):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="typedef")

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in self._KW or name in seen_fn or name in seen_cls:
                continue
            seen_fn.add(name)
            params = [
                p.strip().split()[-1].lstrip("&*")
                for p in self._split_top_level(m.group(2) or "")
                if p.strip()
            ]
            self._add_shell_function(
                file_id, name, params=params, description="template function"
            )

        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="#include")
        for m in self._IMPORT.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_import(file_id, tgt.split(".")[-1], tgt, alias="import")

        seen_var = set()
        for m in self._DEFINE.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(
                    file_id, name, m.group(2).strip()[:120] or None, scope="define"
                )

        self._record_module_meta(
            file_id,
            kind="imhex" if path.suffix.lower() == ".hexpat" else "010-editor",
            types=len(seen_cls),
            functions=len(seen_fn),
            includes=len(seen_imp),
        )
