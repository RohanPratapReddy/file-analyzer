# RPG / ILE RPG (.rpg / .rpgle) analyzer.
#
# Real parser for BOTH RPG dialects that appear in the wild:
#
#   Free-form ILE RPG (**FREE):
#     dcl-proc CalcTax export;             -> function
#       dcl-pi CalcTax packed(9:2);        -> proc interface -> args + output
#     dcl-s Total packed(11:2);            -> variable (standalone)
#     dcl-ds Customer qualified;           -> class (data structure)
#     dcl-c MAX const(100);                -> variable (named constant)
#     /copy QRPGLESRC,PROTOTYPES           -> import
#
#   Fixed-form RPG III / IV (column 6 = specification type):
#     D A               S             2  0 -> variable  (S = standalone)
#     D Customer        DS                  -> class    (DS = data structure)
#     D CalcTax         PR             9  2 -> function (PR = prototype)
#     D  amount                       9  2 -> variable (DS/PR subfield)
#     C     SubName     BEGSR              -> function (subroutine)
#     P CalcTax         B                  -> function (procedure begin)
#
# Fixed-form fields live in fixed columns: spec type at col 6 (index 5),
# name at cols 7-21, definition type at cols 24-25.  Comments are '//'
# (free) or '*' in col 7 (fixed); keywords case-insensitive; strings use "'".
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z@#$][A-Za-z0-9@#$_]*"


class RPGAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "rpg"
    EXTENSIONS = (".rpg", ".rpgle")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ("'",)

    # --- free-form ------------------------------------------------------
    _F_PROC = re.compile(r"(?im)^\s*dcl-proc\s+(" + _ID + r")")
    _F_PI = re.compile(
        r"(?is)\bdcl-pi\s+(" + _ID + r"|\*n)\s*([A-Za-z0-9()#:.\s]*?);(.*?)\bend-pi\b"
    )
    _F_DS = re.compile(r"(?im)^\s*dcl-ds\s+(" + _ID + r")")
    _F_S = re.compile(r"(?im)^\s*dcl-s\s+(" + _ID + r")")
    _F_C = re.compile(r"(?im)^\s*dcl-c\s+(" + _ID + r")")
    _COPY = re.compile(r"(?im)^\s*/(?:copy|include)\s+([^\s*]+)")
    # --- fixed-form -----------------------------------------------------
    _X_BEGSR = re.compile(r"(?im)^.{5}C\s+(" + _ID + r")\s+BEGSR\b")
    _X_PBEGIN = re.compile(r"(?im)^.{5}P\s*(" + _ID + r")\s+B\b")

    # ---- free-form PI arg parsing -------------------------------------
    def _pi_args(self, body):
        ids = []
        for line in body.splitlines():
            line = line.strip().rstrip(";")
            if not line or line.lower().startswith(("dcl-", "end-")):
                continue
            m = re.match(r"(" + _ID + r")\s+(.*)$", line)
            if m and m.group(1).lower() not in ("const", "options", "value"):
                ids.append(
                    self._add_arg(m.group(1), arg_type=m.group(2).strip() or None)
                )
        return ids

    # ---- fixed-form D-spec column parsing -----------------------------
    @staticmethod
    def _fixed_d_specs(text):
        """Yield (name, deftype) for every fixed-form D-spec with a name."""
        for line in text.splitlines():
            if len(line) < 6 or line[5] not in ("D", "d"):
                continue
            name = line[6:21].strip() if len(line) >= 7 else ""
            if not name or not (name[0].isalpha() or name[0] in "@#$"):
                continue
            name = name.split()[0]
            dtype = line[23:25].strip().upper() if len(line) >= 24 else ""
            yield name, dtype

    def _register_types(self, file_id, text, path):
        for m in self._F_DS.finditer(text):
            self._register_class(m.group(1))
        for name, dtype in self._fixed_d_specs(text):
            if dtype == "DS":
                self._register_class(name)

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        # imports (/copy /include) -- read from raw text (directives)
        for m in self._COPY.finditer(text):
            src = m.group(1).strip()
            leaf = re.split(r"[,\\/]", src)[-1]
            nm = re.match(_ID, leaf)
            if nm:
                self._add_import(file_id, nm.group(0), src)

        # ---- free-form data structures / procs / vars -----------------
        for m in self._F_DS.finditer(clean):
            self._add_class(file_id, m.group(1), description="rpg data structure")

        pis = {}
        for m in self._F_PI.finditer(clean):
            name = m.group(1)
            out_ids = []
            rettype = (m.group(2) or "").strip()
            if rettype:
                out_ids.append(self._add_output(rettype))
            pis[name.lower()] = (self._pi_args(m.group(3)), out_ids)

        seen_fn = set()
        for m in self._F_PROC.finditer(clean):
            name = m.group(1)
            args, outs = pis.get(name.lower(), ([], []))
            self._add_function(file_id, name, args, outs, description="rpg procedure")
            seen_fn.add(name.lower())

        for m in self._F_S.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")
        for m in self._F_C.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")

        # ---- fixed-form specs -----------------------------------------
        for name, dtype in self._fixed_d_specs(text):
            if dtype == "DS":
                self._add_class(file_id, name, description="rpg data structure (fixed)")
            elif dtype in ("PR", "PI"):
                if name.lower() not in seen_fn:
                    self._add_function(
                        file_id, name, [], [], description="rpg prototype (fixed)"
                    )
                    seen_fn.add(name.lower())
            else:  # 'S', 'C', or blank subfield/standalone
                self._add_variable(file_id, name, scope="module")

        for m in self._X_BEGSR.finditer(text):
            if m.group(1).lower() not in seen_fn:
                self._add_function(
                    file_id, m.group(1), [], [], description="rpg subroutine"
                )
                seen_fn.add(m.group(1).lower())
        for m in self._X_PBEGIN.finditer(text):
            if m.group(1).lower() not in seen_fn:
                self._add_function(
                    file_id, m.group(1), [], [], description="rpg procedure (fixed)"
                )
                seen_fn.add(m.group(1).lower())
