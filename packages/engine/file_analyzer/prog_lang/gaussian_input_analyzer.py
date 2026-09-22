# Gaussian input file (.gjf / .com).
#
# A Gaussian job deck has a fixed block layout:
#
#     %mem=4GB                 <- Link-0 commands (resources / files)
#     %nprocshared=8
#     %chk=water.chk
#     # B3LYP/6-31G(d) Opt Freq SCF=Tight    <- route section (the job)
#
#     water molecule geometry               <- title
#
#     0 1                                    <- charge & spin multiplicity
#     O   0.000000   0.000000   0.117300     <- Cartesian geometry
#     H   0.000000   0.757200  -0.469200
#     H   0.000000  -0.757200  -0.469200
#
# The recoverable named symbols:
#   * `%chk=` / `%rwf=` / `%oldchk=` / `%kjob`  -> a referenced file  -> import
#   * other `%key=value` Link-0 commands        -> variable (resource setting)
#   * route-section tokens on the `#` line       -> variables (the method, basis
#     and each job keyword such as `Opt`, `Freq`, `SCF=Tight`)
# The title, charge/multiplicity and Cartesian coordinates name nothing.
# `!` starts a comment.
import re

from .regex_base import RegexCodeAnalyzer


class GaussianInputAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "gaussian_input"
    EXTENSIONS = (".gjf", ".com")
    LINE_COMMENTS = ("!",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    _LINK0 = re.compile(r"(?mi)^[ \t]*%(\w+)(?:\s*=\s*(\S+))?")
    _FILE_KEYS = {"chk", "rwf", "oldchk", "oldmatrix", "kjob", "int", "d2e"}
    _ROUTE = re.compile(r"(?m)^[ \t]*#(?:[pPnNtT]\b)?\s*(.*)$")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_v = set()
        for m in self._LINK0.finditer(clean):
            key, val = m.group(1), m.group(2)
            if key.lower() in self._FILE_KEYS and val:
                self._add_import(file_id, val.replace("\\", "/").split("/")[-1], val)
            else:
                if key.lower() not in seen_v:
                    seen_v.add(key.lower())
                    self._add_variable(file_id, key, val, scope="link0")

        # route section (may span several `#` continuation lines before the
        # first blank line); tokenise each keyword.
        for m in self._ROUTE.finditer(clean):
            for tok in m.group(1).split():
                # a keyword may be `Name`, `Name=Val`, or `Name(a,b)`
                base = re.split(r"[=(]", tok, 1)[0].strip()
                if not base or base in seen_v:
                    continue
                seen_v.add(base)
                self._add_variable(file_id, base, tok, scope="route")
