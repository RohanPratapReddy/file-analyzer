# Cython (.pxi, .cy) analyzer.
#
# Cython is Python extended with C-level declarations; the file is indentation
# structured like Python but is not valid Python (``cdef`` etc.), so it is
# parsed with indentation-aware regex.  Real constructs:
#
#     cimport numpy as cnp                              -> import
#     from libc.math cimport sqrt, pow                  -> import (each)
#     import os                                         -> import
#     from cython.parallel import prange                -> import (each)
#     cdef extern from "vec.h":                         -> import (C header)
#     DEF MAXN = 1024                                   -> variable (compile-time)
#     ctypedef double real_t                            -> variable (type alias)
#     cdef class Matrix:                                -> class
#         cdef double* data                             -> variable (attr)
#         cpdef double trace(self):                     -> function (method)
#     cdef inline int clamp(int v, int lo, int hi):     -> function
#     cpdef double norm(double[:] x):                   -> function
#     def solve(A, b):                                  -> function
#     GLOBAL_EPS = 1e-9                                 -> variable (module)
#
# Comments are '#'.  '"'/"'" strings (incl the triple forms) protect their
# contents from the '#' stripper via STRING_DELIMS.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class CythonAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "cython"
    EXTENSIONS = (".pxi", ".cy")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _CIMPORT = re.compile(
        r"^[ \t]*cimport\s+([\w.]+)(?:\s+as\s+(" + _ID + r"))?", re.MULTILINE
    )
    _FROM_CIMPORT = re.compile(
        r"^[ \t]*from\s+([\w.]+)\s+cimport\s+(.+)$", re.MULTILINE
    )
    _IMPORT = re.compile(
        r"^[ \t]*import\s+([\w.]+)(?:\s+as\s+(" + _ID + r"))?", re.MULTILINE
    )
    _FROM_IMPORT = re.compile(r"^[ \t]*from\s+([\w.]+)\s+import\s+(.+)$", re.MULTILINE)
    _EXTERN = re.compile(
        r'^[ \t]*cdef\s+extern\s+from\s+["<]([^">]+)[">]', re.MULTILINE
    )

    _CLASS = re.compile(
        r"^([ \t]*)(?:cdef\s+|cpdef\s+)?class\s+(" + _ID + r")\s*(?:\(([^)]*)\))?\s*:",
        re.MULTILINE,
    )
    # C++ interop:  [cdef [extern] [api]] cppclass Name[T](Base):
    _CPPCLASS = re.compile(
        r"^([ \t]*)(?:cdef\s+)?(?:extern\s+)?(?:api\s+)?"
        r"cppclass\s+(" + _ID + r")\s*(?:\[[^\]]*\])?"
        r"\s*(?:\(([^)]*)\))?\s*:",
        re.MULTILINE,
    )
    _CTYPEDEF = re.compile(
        r"^[ \t]*ctypedef\b(?!\s+(?:struct|union|enum|"
        r"cppclass|class)\b)[^\n]*?\b(" + _ID + r")\s*$",
        re.MULTILINE,
    )
    _CTYPEDEF_REC = re.compile(
        r"^[ \t]*ctypedef\s+(?:struct|union|enum|cppclass)" r"\s+(" + _ID + r")",
        re.MULTILINE,
    )
    _DEF_VAL = re.compile(r"^[ \t]*DEF\s+(" + _ID + r")\s*=", re.MULTILINE)

    # def / cdef / cpdef function headers.  A cdef data declaration has no '(',
    # so requiring '(' before ':' separates functions from cdef variables.
    _FUNC = re.compile(
        r"^([ \t]*)(?:(cdef|cpdef)\s+|def\s+)"
        r"(?:[\w\*\[\]\., ]+?\s+)??"  # optional return type
        r"(" + _ID + r")\s*\(",
        re.MULTILINE,
    )

    # cdef data declaration:  cdef <type> name [, name...]  (no '(' before EOL)
    _CVAR = re.compile(
        r"^([ \t]*)cdef\s+(?!class\b|extern\b|inline\b|packed\b)"
        r"([\w\*\[\]\.\": <>]+?\s+)("
        + _ID
        + r"(?:\s*,\s*"
        + _ID
        + r")*)\s*(?:=[^\n]*)?$",
        re.MULTILINE,
    )
    _MODVAR = re.compile(r"^(" + _ID + r")\s*=\s*(?!=)", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        for m in self._CLASS.finditer(text):
            self._register_class(m.group(2))
        for m in self._CPPCLASS.finditer(text):
            self._register_class(m.group(2))
        for m in self._CTYPEDEF_REC.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        for m in self._CIMPORT.finditer(text):
            self._add_import(
                file_id, m.group(2) or m.group(1).split(".")[-1], m.group(1), m.group(2)
            )
        for m in self._FROM_CIMPORT.finditer(text):
            self._emit_from(file_id, m.group(1), m.group(2))
        for m in self._IMPORT.finditer(text):
            self._add_import(
                file_id, m.group(2) or m.group(1).split(".")[-1], m.group(1), m.group(2)
            )
        for m in self._FROM_IMPORT.finditer(text):
            self._emit_from(file_id, m.group(1), m.group(2))
        for m in self._EXTERN.finditer(text):
            self._add_import(file_id, re.split(r"[\\/]", m.group(1))[-1], m.group(1))

        # class bodies (indentation span) -> owner scope for members
        class_spans = self._class_spans(text)
        for indent, name, bases, cid, a, b in class_spans:
            parents = []
            for p in self._split_top_level(bases or ""):
                p = p.strip()
                if p:
                    pid = self._register_class(p)
                    if pid is not None:
                        parents.append(pid)
            self._add_class(
                file_id, name, description="cython class", parent_ids=parents or None
            )

        def owner_of(pos):
            best = None
            for indent, name, bases, cid, a, b in class_spans:
                if a <= pos < b:
                    best = cid
            return best

        for m in self._CTYPEDEF_REC.finditer(text):
            self._add_class(file_id, m.group(1), description="cython record type")
        for m in self._CTYPEDEF.finditer(text):
            self._add_variable(file_id, m.group(1), scope="ctypedef")
        for m in self._DEF_VAL.finditer(text):
            self._add_variable(file_id, m.group(1), scope="compile-time")

        seen_fn = set()
        for m in self._FUNC.finditer(text):
            name = m.group(3)
            if name in ("if", "for", "while", "with", "elif", "return", "print"):
                continue
            key = (m.start(), name)
            if key in seen_fn:
                continue
            seen_fn.add(key)
            lp = m.end() - 1
            rp = self._find_matching(text, lp, "(", ")")
            arg_ids = self._parse_params(text[lp + 1 : rp - 1])
            self._add_function(
                file_id,
                name,
                arg_ids,
                [],
                class_id=owner_of(m.start()),
                description="cython " + (m.group(2) or "def"),
            )

        for m in self._CVAR.finditer(text):
            oid = owner_of(m.start())
            for raw in m.group(3).split(","):
                nm = raw.strip()
                if nm:
                    self._add_variable(
                        file_id, nm, scope="attr" if oid is not None else "module"
                    )

        for m in self._MODVAR.finditer(text):
            # only genuine module-level (col-0) assignments
            self._add_variable(file_id, m.group(1), scope="module")

        # cppclass bodies use C++ signatures (no def/cdef prefix); scan them
        self._scan_cppclass_members(file_id, text)

    _CPP_QUALS = re.compile(
        r"\b(?:nogil|const)\b|except\s*\+?[^\n]*|" r"noexcept|\bwith\s+gil\b"
    )

    def _scan_cppclass_members(self, file_id, text):
        lines = text.splitlines(keepends=True)
        offsets, pos = [], 0
        for ln in lines:
            offsets.append(pos)
            pos += len(ln)
        for m in self._CPPCLASS.finditer(text):
            indent = len(m.group(1))
            cid = self._class_registry.get(m.group(2))
            # locate header line index
            li = 0
            for k, off in enumerate(offsets):
                if off <= m.start() < off + len(lines[k]):
                    li = k
                    break
            for k in range(li + 1, len(lines)):
                raw = lines[k]
                if not raw.strip():
                    continue
                if self._indent_of(raw) <= indent:
                    break  # end of cppclass body
                body = raw.strip()
                if body.startswith(
                    ("#", "cppclass", "cdef", "ctypedef", "pass", "ns_", "@")
                ):
                    continue
                body = self._CPP_QUALS.sub(" ", body).strip().rstrip(":")
                if "(" in body:  # a method / ctor signature
                    head = body[: body.index("(")].strip()
                    toks = re.findall(_ID, head)
                    if not toks:
                        continue
                    name = toks[-1]
                    if name in ("if", "for", "while", "return", "operator"):
                        continue
                    lp = raw.index("(")
                    ap = self._find_matching(raw, lp, "(", ")")
                    arg_ids = (
                        self._parse_params(raw[lp + 1 : ap - 1]) if ap > lp else []
                    )
                    self._add_function(
                        file_id,
                        name,
                        arg_ids,
                        [],
                        class_id=cid,
                        description="cython cppclass method",
                    )
                else:  # a data member: TYPE ... name
                    toks = re.findall(_ID, body)
                    if len(toks) >= 2:
                        self._add_variable(file_id, toks[-1], scope="attr")

    def _emit_from(self, file_id, module, names):
        names = names.strip()
        if names.startswith("("):
            names = names[1:]
        names = names.rstrip(")").split("#")[0]
        for part in names.split(","):
            part = part.strip()
            if not part or part == "*":
                continue
            toks = re.split(r"\s+as\s+", part)
            real = toks[0].strip()
            alias = toks[1].strip() if len(toks) > 1 else None
            if real:
                self._add_import(file_id, alias or real, module + "." + real, alias)

    def _class_spans(self, text):
        lines = text.splitlines(keepends=True)
        offsets, pos = [], 0
        for ln in lines:
            offsets.append(pos)
            pos += len(ln)
        matches = list(self._CLASS.finditer(text)) + list(self._CPPCLASS.finditer(text))
        matches.sort(key=lambda m: m.start())
        spans = []
        for m in matches:
            indent = len(m.group(1))
            name, bases = m.group(2), m.group(3)
            cid = self._class_registry.get(name)
            start = m.start()
            # find line index of the header
            li = 0
            for k, off in enumerate(offsets):
                if off <= start < off + len(lines[k]):
                    li = k
                    break
            end = len(text)
            for k in range(li + 1, len(lines)):
                s = lines[k]
                if not s.strip():
                    continue
                if self._indent_of(s) <= indent:
                    end = offsets[k]
                    break
            spans.append((indent, name, bases, cid, start, end))
        return spans

    def _parse_params(self, body):
        arg_ids = []
        for part in self._split_top_level(body):
            part = part.split("=")[0].strip()
            if not part or part in ("self", "*", "**", "..."):
                continue
            part = re.sub(r"^\*+", "", part).strip()
            toks = re.findall(_ID, part)
            if not toks:
                continue
            name = toks[-1]
            atype = part[: part.rfind(name)].strip() or None
            arg_ids.append(self._add_arg(name, atype))
        return arg_ids
