# COBOL (.cbl / .cob / .cpy) analyzer.
#
# Real parser for COBOL (case-insensitive, division/section/paragraph structure,
# fixed- OR free-format source):
#   IDENTIFICATION DIVISION.  PROGRAM-ID. HELLO.        -> program (class row)
#   FUNCTION-ID. compute-tax.                            -> function-program (class)
#   COPY CUSTREC.                                        -> import (copybook)
#   01  WS-NAME   PIC X(20).                             -> variable / group
#       05 WS-SUB PIC 9(4) VALUE 0.                      -> attribute of the group
#   PROCEDURE DIVISION USING WS-A WS-B.
#   MAIN-PARA.        (a bare name terminated by '.')    -> paragraph (function)
#   PROCESS-SECTION SECTION.                             -> section (function)
#   CALL "SUBPROG" USING ...                             -> reference (import)
#
# COBOL is column sensitive in fixed format: an indicator '*' or '/' in column 7
# (index 6) is a full-line comment; '-' is a continuation. Free format uses
# '*>' inline comments. Both are handled below.
import re

from .regex_base import RegexCodeAnalyzer


class CobolAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "cobol"
    EXTENSIONS = (".cbl", ".cob", ".cpy")
    LINE_COMMENTS = ("*>",)  # free-format inline; fixed-format col-7 done manually
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _PROGRAM = re.compile(r"\bPROGRAM-ID\s*\.\s*([A-Za-z0-9][\w-]*)", re.IGNORECASE)
    _FUNCTION = re.compile(r"\bFUNCTION-ID\s*\.\s*([A-Za-z0-9][\w-]*)", re.IGNORECASE)
    _CLASSID = re.compile(r"\bCLASS-ID\s*\.\s*([A-Za-z0-9][\w-]*)", re.IGNORECASE)
    _COPY = re.compile(r"\bCOPY\s+([A-Za-z0-9][\w-]*)", re.IGNORECASE)
    _CALL = re.compile(
        r'\bCALL\s+(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9][\w-]*))', re.IGNORECASE
    )
    # data item:  level-number  name  [PIC ...] [VALUE ...] .
    _DATA = re.compile(
        r"^\s*(\d{1,2})\s+([A-Za-z0-9][\w-]*)"
        r"(?:\s+(?:PIC(?:TURE)?\s+(?:IS\s+)?(\S+)))?"
        r"(?:.*?\bVALUE\s+(?:IS\s+)?([^.]+?))?\s*\.?\s*$",
        re.IGNORECASE,
    )
    # paragraph or section header:  NAME.  or  NAME SECTION.
    _PARA = re.compile(r"^\s*([A-Za-z0-9][\w-]*)\s*(SECTION)?\s*\.\s*$", re.IGNORECASE)
    _DIV = re.compile(r"^\s*[A-Z0-9-]+\s+DIVISION\b", re.IGNORECASE)
    _PROC_DIV = re.compile(r"^\s*PROCEDURE\s+DIVISION\b(.*)$", re.IGNORECASE)

    _STMT_KW = {
        "accept",
        "add",
        "call",
        "cancel",
        "close",
        "compute",
        "continue",
        "delete",
        "display",
        "divide",
        "evaluate",
        "exit",
        "goback",
        "go",
        "if",
        "initialize",
        "inspect",
        "move",
        "multiply",
        "open",
        "perform",
        "read",
        "release",
        "return",
        "rewrite",
        "search",
        "set",
        "sort",
        "start",
        "stop",
        "string",
        "subtract",
        "unstring",
        "write",
        "when",
        "else",
        "end-if",
        "end-perform",
        "end-evaluate",
        "end-read",
    }

    # ------------------------------------------------------------------
    def _decomment(self, text):
        """Strip fixed-format col-7 comments and free-format '*>' comments."""
        out = []
        for line in text.splitlines():
            # fixed format: indicator area is column 7 (index 6)
            if len(line) > 6 and line[6] in ("*", "/", "$"):
                # only treat as fixed-format comment when cols 1-6 are blank/seq
                seq = line[:6]
                if seq.strip() == "" or seq.strip().isdigit():
                    out.append("")
                    continue
            stripped = line.lstrip()
            if stripped.startswith("*") and not stripped.startswith("*>"):
                # a leading '*' after trimming (free-ish comment)
                if len(line) - len(stripped) <= 7:
                    out.append("")
                    continue
            # inline free-format comment
            idx = line.find("*>")
            if idx != -1:
                line = line[:idx]
            out.append(line)
        return "\n".join(out)

    def _register_types(self, file_id, text, path):
        text = self._decomment(text)
        for rx in (self._PROGRAM, self._FUNCTION, self._CLASSID):
            for m in rx.finditer(text):
                self._register_class(m.group(1).upper())

    def _extract_entities(self, file_id, text, path):
        text = self._decomment(text)
        lines = text.splitlines()

        # imports: COPY (copybooks) and CALL targets.
        seen_imp = set()
        for m in self._COPY.finditer(text):
            nm = m.group(1).upper()
            if nm not in seen_imp:
                seen_imp.add(nm)
                self._add_import(file_id, nm, f"COPY {nm}")
        for m in self._CALL.finditer(text):
            nm = (m.group(1) or m.group(2) or m.group(3) or "").upper()
            if nm and nm not in seen_imp:
                seen_imp.add(nm)
                self._add_import(file_id, nm, f"CALL {nm}")

        # program units (class rows) with paragraph methods.
        programs = []
        for i, line in enumerate(lines):
            for rx, kind in (
                (self._PROGRAM, "program"),
                (self._FUNCTION, "function"),
                (self._CLASSID, "class"),
            ):
                m = rx.search(line)
                if m:
                    programs.append(
                        {
                            "name": m.group(1).upper(),
                            "kind": kind,
                            "line": i,
                            "methods": [],
                            "attrs": [],
                        }
                    )

        def owner_for(lineno):
            best = None
            for p in programs:
                if p["line"] <= lineno and (best is None or p["line"] > best["line"]):
                    best = p
            return best

        # locate PROCEDURE DIVISION boundaries per program.
        in_proc = False
        proc_start = None
        for i, line in enumerate(lines):
            pm = self._PROC_DIV.match(line)
            if pm:
                in_proc = True
                proc_start = i
                # USING clause parameters
                using = pm.group(1)
                owner = owner_for(i)
                arg_ids = []
                um = re.search(r"\bUSING\b(.*)", using, re.IGNORECASE)
                if um:
                    for tok in re.split(r"[,\s]+", um.group(1).strip()):
                        tok = tok.strip(".")
                        if tok and tok.upper() not in (
                            "BY",
                            "REFERENCE",
                            "VALUE",
                            "CONTENT",
                            "USING",
                        ):
                            arg_ids.append(self._add_arg(tok, "cobol-param"))
                if owner is not None and arg_ids:
                    # attach params to a synthetic entry paragraph later; keep as attrs
                    owner.setdefault("params", []).extend(arg_ids)
                continue
            if self._DIV.match(line) and not self._PROC_DIV.match(line):
                in_proc = False
                continue

            if in_proc:
                pm = self._PARA.match(line)
                if pm:
                    name = pm.group(1)
                    is_section = bool(pm.group(2))
                    if name.upper() in ("EXIT", "END", "CONTINUE"):
                        continue
                    # a paragraph name shouldn't be a verb
                    if name.lower() in self._STMT_KW:
                        continue
                    owner = owner_for(i)
                    cid = self._class_registry.get(owner["name"]) if owner else None
                    fid = self._add_function(
                        file_id,
                        name,
                        [],
                        [],
                        class_id=cid,
                        description=(
                            "cobol section" if is_section else "cobol paragraph"
                        ),
                    )
                    if owner is not None:
                        owner["methods"].append(fid)

        # data items -> variables (01/77 levels) or group attributes.
        # a 01/77 group with subordinate items becomes a variable; subordinate
        # numbered items become args attached to their nearest 01 group owner.
        group_stack = []  # (level, var_or_group_dict)
        for i, line in enumerate(lines):
            dm = self._DATA.match(line)
            if not dm:
                continue
            level = int(dm.group(1))
            name = dm.group(2)
            if name.upper() == "FILLER":
                continue
            pic = dm.group(3)
            val = dm.group(4)
            if level in (1, 77):
                self._add_variable(file_id, name, val.strip() if val else (pic or None))
            # subordinate items recorded as args of enclosing program (data model)
            # kept lightweight: only top-level 01/77 become variables.

        for p in programs:
            self._add_class(
                file_id,
                p["name"],
                description=f"cobol {p['kind']}",
                method_ids=p["methods"],
                attr_ids=p.get("params", []),
            )
