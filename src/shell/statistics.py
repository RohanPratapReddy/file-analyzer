# Statistical / econometrics command languages: Stata (.ado/.do), SAS (.sas) and
# SPSS syntax (.sps).  These are genuine imperative languages with named
# programs / macros, macro variables and file includes -- all extracted here
# with their real grammar.
import re

from .shell_base import ShellScriptBase


class StataAnalyzer(ShellScriptBase):
    """Stata programs (.ado) and do-files (.do).

    ``program define name`` / ``program name``  -> function
    ``local x ...`` / ``global x ...`` / ``scalar x = ...`` / ``tempvar x`` -> variable
    ``do file`` / ``run file`` / ``include file``                          -> import
    """

    LANG_KEY = "stata"
    EXTENSIONS = (".ado", ".do")
    LINE_COMMENTS = ("//", "*")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _PROGRAM = re.compile(r"(?m)^[ \t]*program[ \t]+(?:define[ \t]+|drop[ \t]+)?(\w+)")
    _LOCAL = re.compile(
        r"(?m)^[ \t]*(local|global|tempvar|tempname|tempfile|scalar)"
        r"[ \t]+(\w+)(?:[ \t=]+(.*))?"
    )
    _INCLUDE = re.compile(r"(?m)^[ \t]*(?:do|run|include)[ \t]+([^\s,]+)")
    _ARGS = re.compile(r"(?m)^[ \t]*(?:syntax|args)[ \t]+(.+)$")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._PROGRAM.finditer(clean):
            name = m.group(1)
            if name in seen_fn or name in ("define", "drop", "dir", "list"):
                continue
            seen_fn.add(name)
            self._add_shell_function(file_id, name, description="stata program")

        seen_var = set()
        for m in self._LOCAL.finditer(clean):
            kind, name, val = m.group(1), m.group(2), m.group(3)
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(
                file_id, name, (val or "").strip()[:120] or None, scope=kind
            )

        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1).strip('"')
            if tgt and tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="do")

        self._record_module_meta(
            file_id,
            kind="ado-program" if path.suffix.lower() == ".ado" else "do-file",
            programs=len(seen_fn),
            macros=len(seen_var),
        )


class SasAnalyzer(ShellScriptBase):
    """SAS programs (.sas).

    ``%macro name(params); ... %mend;``   -> function
    ``data work.x; ... run;``             -> class  (a produced dataset/step)
    ``proc name ...; ... run;``           -> function (a procedure invocation)
    ``%let var = value;``                 -> variable
    ``%include 'file';``                  -> import
    """

    LANG_KEY = "sas"
    EXTENSIONS = (".sas",)
    LINE_COMMENTS = ("*",)  # `* comment ;` (statement comment)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _MACRO = re.compile(r"(?mi)^[ \t]*%macro[ \t]+(\w+)[ \t]*(?:\(([^)]*)\))?")
    _LET = re.compile(r"(?mi)^[ \t]*%let[ \t]+(\w+)[ \t]*=[ \t]*([^;]*)")
    _DATA = re.compile(r"(?mi)^[ \t]*data[ \t]+([\w.]+)")
    _PROC = re.compile(r"(?mi)^[ \t]*proc[ \t]+(\w+)")
    _INCLUDE = re.compile(r"(?mi)^[ \t]*%include[ \t]+([^;]+)")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._DATA.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._MACRO.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = self._split_top_level(m.group(2) or "")
            params = [p.split("=")[0].strip() for p in params]
            self._add_shell_function(
                file_id, name, params=params, description="sas macro"
            )
        procs = self._uniq(m.group(1).lower() for m in self._PROC.finditer(clean))
        for name in procs:
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(
                    file_id, "proc_" + name, description="sas procedure step"
                )

        seen_ds = set()
        for m in self._DATA.finditer(clean):
            name = m.group(1)
            if name not in seen_ds:
                seen_ds.add(name)
                self._add_class(file_id, name, description="sas data step")

        seen_var = set()
        for m in self._LET.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(
                    file_id, name, m.group(2).strip()[:120] or None, scope="macro"
                )

        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1).strip().strip("'\"")
            if tgt and tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="include")

        self._record_module_meta(
            file_id,
            macros=len([f for f in seen_fn if not f.startswith("proc_")]),
            data_steps=len(seen_ds),
            procedures=procs or None,
        )


class SpssAnalyzer(ShellScriptBase):
    """SPSS syntax files (.sps).

    ``DEFINE !name (...) ... !ENDDEFINE.``   -> function (a syntax macro)
    ``COMPUTE var = expr.``                  -> variable
    ``INCLUDE FILE='x'.`` / ``INSERT FILE=`` -> import
    """

    LANG_KEY = "spss"
    EXTENSIONS = (".sps",)
    LINE_COMMENTS = ("*",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _DEFINE = re.compile(r"(?mi)^[ \t]*define[ \t]+!?(\w+)[ \t]*\(([^)]*)\)")
    _COMPUTE = re.compile(r"(?mi)^[ \t]*compute[ \t]+(\w+)[ \t]*=[ \t]*([^.]*)")
    _INCLUDE = re.compile(
        r"(?mi)^[ \t]*(?:include|insert)[ \t]+file[ \t]*=[ \t]*([^\s.]+)"
    )
    _GET = re.compile(r"(?mi)^[ \t]*get[ \t]+file[ \t]*=[ \t]*([^\s.]+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._DEFINE.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = [
                p.split("=")[0].strip().lstrip("!")
                for p in self._split_top_level(m.group(2) or "")
            ]
            self._add_shell_function(
                file_id, name, params=[p for p in params if p], description="spss macro"
            )

        seen_var = set()
        for m in self._COMPUTE.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(
                    file_id, name, m.group(2).strip()[:120] or None, scope="computed"
                )

        seen_imp = set()
        for rx, kw in ((self._INCLUDE, "include"), (self._GET, "get")):
            for m in rx.finditer(clean):
                tgt = m.group(1).strip().strip("'\"")
                if tgt and tgt not in seen_imp:
                    seen_imp.add(tgt)
                    self._add_sourced(file_id, tgt, keyword=kw)

        self._record_module_meta(
            file_id, macros=len(seen_fn), computed_vars=len(seen_var)
        )
