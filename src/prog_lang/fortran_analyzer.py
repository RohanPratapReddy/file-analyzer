# Fortran (.f03 / .f08 / .hpf / .cuf) analyzer -- modern free-form Fortran.
#
# Real parser for Fortran 2003/2008 (+ High Performance Fortran, CUDA Fortran),
# case-insensitive, '!' line comments:
#   module geometry                                     -> module (class row)
#     use iso_fortran_env                               -> import
#     use grid, only: nx, ny                            -> import (each symbol)
#     type :: point ; real :: x, y ; end type point     -> derived type (class)
#     integer, parameter :: n = 10                       -> variable
#   contains
#     subroutine translate(p, dx)                        -> subroutine (method)
#     function area(r) result(a)                         -> function (method)
#   end module geometry
#   program main ... end program                         -> program (class row)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class FortranAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "fortran"
    EXTENSIONS = (".f03", ".f08", ".hpf", ".cuf")
    LINE_COMMENTS = ("!",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _USE = re.compile(
        r"^\s*use\s+(?:,\s*\w+\s*::\s*)?([A-Za-z]\w*)"
        r"(?:\s*,\s*only\s*:\s*(.+))?", re.IGNORECASE)
    _MODULE = re.compile(r"^\s*module\s+([A-Za-z]\w*)\s*$", re.IGNORECASE)
    _PROGRAM = re.compile(r"^\s*program\s+([A-Za-z]\w*)", re.IGNORECASE)
    _TYPE = re.compile(
        r"^\s*type(?:\s*,\s*[\w()=, ]+?)?\s*(?:::\s*)?([A-Za-z]\w*)\s*$",
        re.IGNORECASE)
    _END_TYPE = re.compile(r"^\s*end\s*type\b", re.IGNORECASE)
    _SUBROUTINE = re.compile(
        r"^\s*(?:(?:pure|elemental|recursive|module|attributes\([^)]*\))\s+)*"
        r"subroutine\s+([A-Za-z]\w*)\s*(?:\(([^)]*)\))?", re.IGNORECASE)
    _FUNCTION = re.compile(
        r"^\s*(?:(?:pure|elemental|recursive|module|[\w*()]+(?:\s*\([^)]*\))?)\s+)*?"
        r"function\s+([A-Za-z]\w*)\s*\(([^)]*)\)"
        r"(?:\s*result\s*\(\s*([A-Za-z]\w*)\s*\))?", re.IGNORECASE)
    _END_UNIT = re.compile(
        r"^\s*end\s*(module|program|subroutine|function)?\b", re.IGNORECASE)
    _DECL = re.compile(
        r"^\s*(integer|real|double\s+precision|complex|logical|character|type\s*\([^)]*\)|"
        r"class\s*\([^)]*\))"
        r"(?:\s*\([^)]*\))?"                                   # kind/len selector
        r"((?:\s*,\s*[\w()=.*: ]+)*)"                         # attributes
        r"\s*::\s*(.+)$", re.IGNORECASE)

    _INTRINSIC_TYPES = re.compile(
        r"^(integer|real|double|complex|logical|character|type|class)$", re.IGNORECASE)

    def _register_types(self, file_id, text, path):
        for line in text.splitlines():
            for rx in (self._MODULE, self._PROGRAM, self._TYPE):
                m = rx.match(line)
                if m:
                    self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        lines = self._strip_comments(text).splitlines()
        n = len(lines)

        # imports
        for line in lines:
            m = self._USE.match(line)
            if m:
                mod = m.group(1)
                if m.group(2):
                    for sym in m.group(2).split(","):
                        sym = sym.split("=>")[0].strip()
                        if sym:
                            self._add_import(file_id, sym, f"{mod}.{sym}")
                else:
                    self._add_import(file_id, mod, mod)

        # container stack: modules/programs (own procedures); types (own fields)
        containers = []      # dicts with name/kind/methods/attrs
        stack = []           # (kind, dict-or-None) for nesting incl. procedures/types
        i = 0
        while i < n:
            line = lines[i]

            mm = self._MODULE.match(line)
            pm = self._PROGRAM.match(line)
            if mm or pm:
                name = (mm or pm).group(1)
                kind = "module" if mm else "program"
                d = {"name": name, "kind": kind, "methods": [], "attrs": []}
                containers.append(d)
                stack.append((kind, d))
                i += 1
                continue

            tm = self._TYPE.match(line)
            if tm and not re.match(r"^\s*type\s+is\b", line, re.IGNORECASE):
                name = tm.group(1)
                d = {"name": name, "kind": "type", "methods": [], "attrs": []}
                containers.append(d)
                stack.append(("type", d))
                i += 1
                continue
            if self._END_TYPE.match(line):
                if stack and stack[-1][0] == "type":
                    stack.pop()
                i += 1
                continue

            sm = self._SUBROUTINE.match(line)
            fm = self._FUNCTION.match(line)
            if sm or fm:
                if sm:
                    name, params, result = sm.group(1), sm.group(2), None
                else:
                    name, params, result = fm.group(1), fm.group(2), fm.group(3)
                arg_ids = self._params(params or "")
                out_ids = [self._add_output(result)] if result else []
                # method of nearest enclosing module/type, else free function
                owner = None
                for kind, d in reversed(stack):
                    if kind in ("module", "type", "program"):
                        owner = d
                        break
                cid = self._class_registry.get(owner["name"]) if owner else None
                fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
                if owner is not None:
                    owner["methods"].append(fid)
                stack.append(("subroutine" if sm else "function", None))
                i += 1
                continue

            if self._END_UNIT.match(line):
                em = self._END_UNIT.match(line)
                what = em.group(1)
                if stack:
                    # pop matching kind (or the top if bare 'end')
                    if what:
                        for j in range(len(stack) - 1, -1, -1):
                            if stack[j][0] == what.lower():
                                del stack[j:]
                                break
                        else:
                            stack.pop()
                    else:
                        stack.pop()
                i += 1
                continue

            # declarations -> attrs of enclosing type / vars of module|program
            dm = self._DECL.match(line)
            if dm:
                attrs = dm.group(2) or ""
                is_param = "parameter" in attrs.lower()
                rhs = dm.group(3)
                names = self._decl_names(rhs)
                owner = stack[-1][1] if stack and stack[-1][0] == "type" else None
                # find enclosing module/program if not directly in a procedure
                mod_owner = None
                in_proc = any(k in ("subroutine", "function") for k, _ in stack)
                for kind, d in reversed(stack):
                    if kind in ("module", "program"):
                        mod_owner = d
                        break
                dtype = dm.group(1)
                for nm in names:
                    if owner is not None:
                        owner["attrs"].append(self._add_arg(nm, dtype))
                    elif mod_owner is not None and not in_proc:
                        self._add_variable(file_id, nm, None)
            i += 1

        for c in containers:
            self._add_class(file_id, c["name"], description=f"fortran {c['kind']}",
                            method_ids=c["methods"], attr_ids=c["attrs"])

    def _decl_names(self, rhs):
        names = []
        for part in self._split_top_level(rhs):
            part = part.split("=")[0]                 # drop initializer
            m = re.match(r"\s*([A-Za-z]\w*)", part)
            if m:
                names.append(m.group(1))
        return names

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if part and re.match(r"^[A-Za-z]\w*$", part) and part.lower() != "self":
                arg_ids.append(self._add_arg(part))
        return arg_ids
