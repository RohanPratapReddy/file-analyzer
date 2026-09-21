# CA-Easytrieve Plus (.easytrieve) report/data language analyzer.
#
# Easytrieve is a fixed-form data-processing / report language.  It is
# case-insensitive, statements are whitespace/newline delimited, and a '*'
# in the first column marks a comment line.  Real constructs (regex):
#
#     FILE PERSNL FB(150 1800)                          -> class (file/record)
#       EMP-NAME     17  20  A                           -> variable (field/attr)
#       PAY-GROSS    50   4  P 2                          -> variable (field/attr)
#     DEFINE PAY-NET  W  4 P 2                            -> variable (working)
#     DEFINE COUNTER  W  4 N 0 VALUE 0                    -> variable (working)
#     JOB INPUT PERSNL NAME COMPUTE-PAY                   -> function (job activity)
#     PROC EDIT-INPUT                                     -> function (procedure)
#         ...
#     END-PROC
#     REPORT PAY LINESIZE 80                              -> class (report)
#     SORT PERSNL TO SORTED USING (DEPT NAME)             -> function (sort)
#
# A FILE introduces a record whose indented field lines are its attributes;
# DEFINE binds a working/temporary field; JOB/PROC/SORT are activities.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z0-9_#@$-]*"


class EasytrieveAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "easytrieve"
    EXTENSIONS = (".easytrieve",)
    LINE_COMMENTS = ()  # '*' only when in column 1 (handled below)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'", '"')

    _FILE = re.compile(r"(?im)^[ \t]*FILE\s+(" + _ID + r")\b")
    _REPORT = re.compile(r"(?im)^[ \t]*REPORT\s+(" + _ID + r")\b")
    _DEFINE = re.compile(r"(?im)^[ \t]*DEFINE\s+(" + _ID + r")\b")
    _JOB = re.compile(r"(?im)^[ \t]*JOB\b(?:[ \t]+INPUT[ \t]+(" + _ID + r"))?")
    # canonical procedure form is `procname. PROC`; also accept `PROC procname`
    _PROC_LABEL = re.compile(r"(?im)^[ \t]*(" + _ID + r")\s*\.\s+PROC\b")
    _PROC = re.compile(r"(?im)^[ \t]*PROC\s+(" + _ID + r")\b")
    _SORT = re.compile(r"(?im)^[ \t]*SORT\s+(" + _ID + r")\b")
    # an indented field line inside a FILE:  NAME  start  len  type
    _FIELD = re.compile(
        r"(?im)^[ \t]+(" + _ID + r")\s+" r"(?:\*\s+)?\d+\s+\d+\s+[A-Za-z]\b"
    )

    _KEYWORDS = {
        "file",
        "report",
        "define",
        "job",
        "proc",
        "sort",
        "if",
        "else",
        "end-if",
        "end-proc",
        "do",
        "end-do",
        "print",
        "display",
        "input",
        "goto",
        "stop",
        "move",
        "put",
        "get",
        "select",
        "while",
        "call",
        "perform",
        "compute",
        "let",
        "parm",
        "system",
        "heading",
        "title",
        "line",
        "control",
        "sum",
    }

    def _strip_star_comments(self, text):
        out = []
        for ln in text.splitlines(keepends=True):
            if ln[:1] == "*":
                nl = ln[len(ln.rstrip("\r\n")) :]
                out.append(nl)  # preserve the newline only
            else:
                out.append(ln)
        return "".join(out)

    def _register_types(self, file_id, text, path):
        clean = self._strip_star_comments(text)
        for m in self._FILE.finditer(clean):
            self._register_class(m.group(1))
        for m in self._REPORT.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_star_comments(text)

        # FILE record spans: header line -> next top-level statement
        file_spans = self._record_spans(clean)
        for name, cid, a, b in file_spans:
            self._add_class(file_id, name, description="easytrieve file")

        def owner_of(pos):
            for name, cid, a, b in file_spans:
                if a <= pos < b:
                    return cid
            return None

        for m in self._REPORT.finditer(clean):
            self._add_class(file_id, m.group(1), description="easytrieve report")

        seen_field = set()
        for m in self._FIELD.finditer(clean):
            nm = m.group(1)
            if nm.lower() in self._KEYWORDS:
                continue
            oid = owner_of(m.start())
            key = (nm, oid)
            if key in seen_field:
                continue
            seen_field.add(key)
            self._add_variable(
                file_id, nm, scope="field" if oid is not None else "module"
            )

        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="working")

        job_n = 0
        for m in self._JOB.finditer(clean):
            job_n += 1
            inp = m.group(1)
            arg_ids = [self._add_arg(inp, "file")] if inp else []
            self._add_function(
                file_id,
                "JOB_%d" % job_n if not inp else "JOB_" + inp,
                arg_ids,
                [],
                description="easytrieve job",
            )
        seen_proc = set()
        for m in self._PROC_LABEL.finditer(clean):
            seen_proc.add(m.group(1).upper())
            self._add_function(
                file_id, m.group(1), [], [], description="easytrieve proc"
            )
        for m in self._PROC.finditer(clean):
            if m.group(1).upper() in seen_proc:
                continue
            self._add_function(
                file_id, m.group(1), [], [], description="easytrieve proc"
            )
        for m in self._SORT.finditer(clean):
            self._add_function(
                file_id,
                "SORT_" + m.group(1),
                [self._add_arg(m.group(1), "file")],
                [],
                description="easytrieve sort",
            )

    def _record_spans(self, clean):
        lines = clean.splitlines(keepends=True)
        offsets, pos = [], 0
        for ln in lines:
            offsets.append(pos)
            pos += len(ln)
        # top-level statement = FILE/DEFINE/JOB/PROC/REPORT/SORT at column start
        top = re.compile(
            r"(?i)^[ \t]*(?:(?:FILE|DEFINE|JOB|PROC|REPORT|SORT|PARM)\b"
            r"|" + _ID + r"\s*\.\s+PROC\b)"
        )
        spans = []
        for m in self._FILE.finditer(clean):
            name = m.group(1)
            cid = self._class_registry.get(name)
            start = m.start()
            li = 0
            for k, off in enumerate(offsets):
                if off <= start < off + len(lines[k]):
                    li = k
                    break
            end = len(clean)
            for k in range(li + 1, len(lines)):
                if top.match(lines[k]):
                    end = offsets[k]
                    break
            spans.append((name, cid, start, end))
        return spans
