# ABAP (.abap) analyzer.
#
# Real parser for SAP ABAP (case-insensitive; statements end with '.'; '"' starts
# an inline comment to end of line; '*' in column 1 is a full-line comment; string
# literals use '...' and `...`):
#   CLASS lcl_car DEFINITION INHERITING FROM lcl_vehicle.   -> class (+ parent)
#     PUBLIC SECTION.
#       DATA mv_speed TYPE i.                                -> attribute
#       METHODS drive IMPORTING iv_km TYPE i.                -> method
#   ENDCLASS.
#   INTERFACE lif_movable.  ... ENDINTERFACE.                -> class (interface)
#   FORM calc USING p_x.  ... ENDFORM.                        -> function
#   FUNCTION z_do.  ... ENDFUNCTION.                          -> function
#   DATA gv_count TYPE i.                                     -> variable (top level)
#   TYPE-POOLS abap.                                          -> import
import re

from .regex_base import RegexCodeAnalyzer


class AbapAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "abap"
    EXTENSIONS = (".abap",)
    LINE_COMMENTS = ('"',)  # inline comment; full-line '*' handled in _clean
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'", "`")

    _CLASS = re.compile(
        r"^\s*CLASS\s+([A-Za-z_]\w*)\s+DEFINITION"
        r"(?:.*?INHERITING\s+FROM\s+([A-Za-z_]\w*))?",
        re.IGNORECASE | re.DOTALL,
    )
    _INTERFACE = re.compile(r"^\s*INTERFACE\s+([A-Za-z_]\w*)", re.IGNORECASE)
    _END_CLASS = re.compile(r"^\s*END(?:CLASS|INTERFACE)\b", re.IGNORECASE)
    _CLASS_IMPL = re.compile(
        r"^\s*CLASS\s+([A-Za-z_]\w*)\s+IMPLEMENTATION", re.IGNORECASE
    )
    _METHODS = re.compile(r"^\s*(?:CLASS-)?METHODS?\s+([A-Za-z_]\w*)", re.IGNORECASE)
    _METHOD_IMPL = re.compile(
        r"^\s*METHOD\s+([A-Za-z_]\w*~)?([A-Za-z_]\w*)", re.IGNORECASE
    )
    _FORM = re.compile(r"^\s*FORM\s+([A-Za-z_]\w*)", re.IGNORECASE)
    _FUNCTION = re.compile(r"^\s*FUNCTION\s+([A-Za-z_/]\w*)", re.IGNORECASE)
    _DATA = re.compile(r"^\s*(?:CLASS-)?DATA\s*:?\s+([A-Za-z_]\w*)", re.IGNORECASE)
    _CONST = re.compile(r"^\s*CONSTANTS\s*:?\s+([A-Za-z_]\w*)", re.IGNORECASE)
    _TYPEPOOL = re.compile(
        r"^\s*TYPE-POOLS?\s+([A-Za-z_/]\w*)", re.IGNORECASE | re.MULTILINE
    )
    _IMPORTING = re.compile(
        r"\bIMPORTING\b(.*?)(?:\bEXPORTING\b|\bCHANGING\b|"
        r"\bRETURNING\b|\bRAISING\b|\bEXCEPTIONS\b|\.|$)",
        re.IGNORECASE | re.DOTALL,
    )

    def _clean(self, text):
        out = []
        for line in text.splitlines():
            if line[:1] == "*":  # column-1 full-line comment
                out.append("")
            else:
                out.append(line)
        return self._strip_comments("\n".join(out))

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for m in self._CLASS.finditer(text):
            self._register_class(m.group(1))
        for m in self._INTERFACE.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)
        lines = text.splitlines()
        n = len(lines)

        for m in self._TYPEPOOL.finditer(text):
            self._add_import(file_id, m.group(1), m.group(1))

        seen_methods = set()  # (class_id, method_name) already emitted
        i = 0
        while i < n:
            line = lines[i]

            # ---- CLASS / INTERFACE DEFINITION block ----
            cdef = self._CLASS.match(line)
            idef = self._INTERFACE.match(line)
            if (cdef and "IMPLEMENTATION" not in line.upper()) or idef:
                name = (cdef or idef).group(1)
                is_iface = bool(idef)
                parents = []
                if cdef and cdef.group(2) and cdef.group(2) in self._class_registry:
                    parents.append(self._class_registry[cdef.group(2)])
                cid = self._class_registry.get(name)
                methods, attrs = [], []
                i += 1
                while i < n and not self._END_CLASS.match(lines[i]):
                    body = lines[i]
                    mm = self._METHODS.match(body)
                    if mm:
                        stmt, k = body, i
                        while "." not in stmt and k + 1 < n:
                            k += 1
                            stmt += " " + lines[k]
                        arg_ids = self._importing_args(stmt)
                        fid = self._add_function(
                            file_id,
                            mm.group(1),
                            arg_ids,
                            [],
                            class_id=cid,
                            description="abap method",
                        )
                        methods.append(fid)
                        seen_methods.add((cid, mm.group(1).lower()))
                    else:
                        dm = self._DATA.match(body) or self._CONST.match(body)
                        if dm:
                            attrs.append(self._add_arg(dm.group(1)))
                    i += 1
                self._add_class(
                    file_id,
                    name,
                    description="abap interface" if is_iface else "abap class",
                    parent_ids=parents,
                    method_ids=methods,
                    attr_ids=attrs,
                )
                i += 1
                continue

            # ---- CLASS IMPLEMENTATION block ----
            impl = self._CLASS_IMPL.match(line)
            if impl:
                cname = impl.group(1)
                cid = self._class_registry.get(cname)
                i += 1
                while i < n and not re.match(
                    r"^\s*ENDCLASS\b", lines[i], re.IGNORECASE
                ):
                    mi = self._METHOD_IMPL.match(lines[i])
                    if mi:
                        mname = mi.group(2)
                        if (cid, mname.lower()) not in seen_methods:
                            self._add_function(
                                file_id,
                                mname,
                                [],
                                [],
                                class_id=cid,
                                description="abap method impl",
                            )
                            seen_methods.add((cid, mname.lower()))
                    i += 1
                i += 1
                continue

            # ---- top-level routines / data (outside any class) ----
            fm = self._FORM.match(line)
            if fm:
                self._add_function(
                    file_id, fm.group(1), [], [], description="abap form"
                )
                i += 1
                continue
            fn = self._FUNCTION.match(line)
            if fn:
                self._add_function(
                    file_id, fn.group(1), [], [], description="abap function"
                )
                i += 1
                continue
            dm = self._DATA.match(line) or self._CONST.match(line)
            if dm:
                self._add_variable(file_id, dm.group(1), None)
                i += 1
                continue
            i += 1

    def _importing_args(self, stmt):
        arg_ids = []
        im = self._IMPORTING.search(stmt)
        if not im:
            return arg_ids
        seg = im.group(1)
        for pm in re.finditer(
            r"(?:VALUE\()?([A-Za-z_]\w*)\)?\s+TYPE\s+([A-Za-z_/]\w*)",
            seg,
            re.IGNORECASE,
        ):
            arg_ids.append(self._add_arg(pm.group(1), pm.group(2)))
        return arg_ids
