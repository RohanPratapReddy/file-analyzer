# Mainframe / minicomputer command & job-control languages: IBM JCL (.jcl,
# .proclib), REXX (.rexx), TSO CLIST (.clist), IBM i Control Language (.clp) and
# DEC/OpenVMS DCL (.dcl).  Each is parsed with its genuine, column- or
# sigil-oriented syntax.
import re

from .shell_base import ShellScriptBase


class JclAnalyzer(ShellScriptBase):
    """IBM Job Control Language (.jcl) and procedure libraries (.proclib).

    ``//NAME JOB ...``            -> class  (the job / a proc definition)
    ``//STEP EXEC PGM=prog``       -> function (a job step; PGM/PROC recorded)
    ``//DD DD DSN=...``            -> variable (a DD statement)
    ``// INCLUDE MEMBER=x``        -> import
    """
    LANG_KEY = "jcl"
    EXTENSIONS = (".jcl", ".proclib")
    LINE_COMMENTS = ("//*",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'",)

    _JOB = re.compile(r"(?m)^//(\S+)[ \t]+JOB\b")
    _PROC = re.compile(r"(?m)^//(\S+)[ \t]+PROC\b")
    _EXEC = re.compile(r"(?m)^//(\S+)[ \t]+EXEC[ \t]+(.*)")
    _DD = re.compile(r"(?m)^//(\S+)[ \t]+DD[ \t]+(.*)")
    _INCLUDE = re.compile(r"(?mi)^//[ \t]*INCLUDE[ \t]+MEMBER=(\S+)")
    _PGM = re.compile(r"(?i)\bPGM=([\w.]+)")
    _CALLPROC = re.compile(r"(?i)\bPROC=([\w.]+)")

    def _register_types(self, file_id, text, path):
        for rx in (self._JOB, self._PROC):
            for m in rx.finditer(text):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = set()
        for rx, kind in ((self._JOB, "job"), (self._PROC, "proc")):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name not in seen_cls:
                    seen_cls.add(name)
                    self._add_class(file_id, name, description="jcl " + kind)

        seen_fn = set()
        seen_imp = set()
        for m in self._EXEC.finditer(clean):
            name, rest = m.group(1), m.group(2)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            self._add_shell_function(file_id, name, description="jcl exec step")
            pgm = self._PGM.search(rest)
            proc = self._CALLPROC.search(rest)
            # EXEC PGM=x -> program dependency; EXEC PROC=x / EXEC x -> proc call.
            if pgm and pgm.group(1) not in seen_imp:
                seen_imp.add(pgm.group(1))
                self._add_command_dep(file_id, pgm.group(1))
            elif proc and proc.group(1) not in seen_imp:
                seen_imp.add(proc.group(1))
                self._add_sourced(file_id, proc.group(1), keyword="EXEC-PROC")

        seen_var = set()
        for m in self._DD.finditer(clean):
            name = m.group(1)
            if name in seen_var or name == "*":
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                               scope="dd")

        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="INCLUDE")

        self._record_module_meta(file_id, jobs_or_procs=sorted(seen_cls) or None,
                                 steps=len(seen_fn), dd_statements=len(seen_var))


class RexxAnalyzer(ShellScriptBase):
    """REXX scripts (.rexx).

    ``name: PROCEDURE`` / ``name:`` labels  -> function
    ``call name``                           -> import (internal/external routine)
    ``var = expr``                          -> variable
    """
    LANG_KEY = "rexx"
    EXTENSIONS = (".rexx",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _LABEL = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*:(?![=])[ \t]*(PROCEDURE)?",
                        re.IGNORECASE)
    _ASSIGN = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*=(?!=)[ \t]*(.+)")
    _CALL = re.compile(r"(?mi)^[ \t]*call[ \t]+([A-Za-z_]\w*)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._LABEL.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            self._add_shell_function(
                file_id, name,
                description="rexx procedure" if m.group(2) else "rexx label")

        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in seen_var or name.upper() in ("IF", "DO", "END", "THEN", "ELSE"):
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                               scope="rexx")

        seen_imp = set()
        for m in self._CALL.finditer(clean):
            name = m.group(1)
            if name.lower() in ("on", "off") or name in seen_imp:
                continue
            seen_imp.add(name)
            self._add_command_dep(file_id, name)

        self._record_module_meta(file_id, routines=len(seen_fn),
                                 variables=len(seen_var), calls=len(seen_imp))


class ClistAnalyzer(ShellScriptBase):
    """TSO CLIST command lists (.clist).

    ``PROC n POSITIONAL KEYWORD(...)``  -> function (the CLIST entry proc)
    ``SET &var = value``                -> variable
    ``&label:`` / ``DO ... END`` blocks -> metadata
    """
    LANG_KEY = "clist"
    EXTENSIONS = (".clist",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ("'",)

    _PROC = re.compile(r"(?mi)^[ \t]*PROC[ \t]+(\d+)[ \t]*(.*)")
    _SET = re.compile(r"(?mi)^[ \t]*SET[ \t]+&?(\w+)[ \t]*=[ \t]*(.*)")
    _CONTROL = re.compile(r"(?mi)^[ \t]*(DO|SELECT|IF)\b")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        params = []
        for m in self._PROC.finditer(clean):
            params = m.group(2).split()
            self._add_shell_function(file_id, path.stem, params=params,
                                     description="clist proc")
            break     # a CLIST has a single PROC header

        seen_var = set()
        for m in self._SET.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                                   scope="clist")

        controls = len(self._CONTROL.findall(clean))
        self._record_module_meta(file_id, parameters=params or None,
                                 variables=len(seen_var), control_blocks=controls)


class ClpAnalyzer(ShellScriptBase):
    """IBM i Control Language programs (.clp).

    ``PGM PARM(&A &B)``                 -> function (the program entry)
    ``DCL VAR(&X) TYPE(*CHAR) LEN(10)`` -> variable
    ``CALL PGM(name)`` / ``CALLPRC``    -> import
    ``TAG label``                       -> metadata (branch label)
    """
    LANG_KEY = "ibmi-cl"
    EXTENSIONS = (".clp",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ("'",)

    _PGM = re.compile(r"(?mi)^[ \t]*PGM\b[ \t]*(?:PARM\(([^)]*)\))?")
    _DCL = re.compile(r"(?mi)^[ \t]*DCL[ \t]+VAR\(&?(\w+)\)[ \t]*(?:TYPE\((\*?\w+)\))?")
    _CALL = re.compile(r"(?mi)^[ \t]*CALL(?:PRC)?[ \t]+(?:PGM\()?['\"]?(\w+)")
    _TAG = re.compile(r"(?mi)^[ \t]*(\w+):[ \t]+TAG\b|^[ \t]*TAG[ \t]+LABEL\((\w+)\)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._PGM.finditer(clean):
            params = re.findall(r"&(\w+)", m.group(1) or "")
            self._add_shell_function(file_id, path.stem, params=params,
                                     description="ibm-i cl program")
            break

        seen_var = set()
        for m in self._DCL.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, m.group(2) or None, scope="dcl")

        seen_imp = set()
        for m in self._CALL.finditer(clean):
            name = m.group(1)
            if name not in seen_imp:
                seen_imp.add(name)
                self._add_command_dep(file_id, name)

        self._record_module_meta(file_id, variables=len(seen_var),
                                 calls=len(seen_imp))


class DclAnalyzer(ShellScriptBase):
    """DEC / OpenVMS DCL command procedures (.dcl).

    ``$ LABEL:``                       -> function (a labelled routine)
    ``$ name = value`` / ``$ name == value`` -> variable (local / global symbol)
    ``$ @file`` / ``$ CALL routine``   -> import
    """
    LANG_KEY = "dcl"
    EXTENSIONS = (".dcl",)
    LINE_COMMENTS = ("$!",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _LABEL = re.compile(r"(?m)^[ \t]*\$[ \t]*([A-Za-z_]\w*):[ \t]*$")
    _ASSIGN = re.compile(r"(?m)^[ \t]*\$[ \t]*([A-Za-z_]\w*)[ \t]*(==?)[ \t]*(.+)")
    _AT = re.compile(r"(?m)^[ \t]*\$[ \t]*@(\S+)")
    _CALL = re.compile(r"(?mi)^[ \t]*\$[ \t]*CALL[ \t]+([A-Za-z_]\w*)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._LABEL.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="dcl label")

        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in seen_var:
                continue
            seen_var.add(name)
            scope = "global-symbol" if m.group(2) == "==" else "local-symbol"
            self._add_variable(file_id, name, m.group(3).strip()[:120] or None,
                               scope=scope)

        seen_imp = set()
        for m in self._AT.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="@")
        for m in self._CALL.finditer(clean):
            name = m.group(1)
            if name not in seen_imp:
                seen_imp.add(name)
                self._add_sourced(file_id, name, keyword="CALL")

        self._record_module_meta(file_id, labels=len(seen_fn),
                                 symbols=len(seen_var))
