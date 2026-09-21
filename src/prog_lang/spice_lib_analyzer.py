# SPICE model library (.lib).
#
# A SPICE `.lib` file collects reusable device models, subcircuits, parameters
# and function definitions that other netlists pull in with `.lib file name`:
#
#     * BSIM4 NMOS model card
#     .lib nom
#     .param vdd = 1.8  temp = 27
#     .model nch_25 nmos (level=54 version=4.5 tox=1.8n vth0=0.35)
#     .subckt inv in out vdd vss
#       m1 out in vss vss nch_25 w=1u l=0.18u
#     .ends
#     .func square(x) {x*x}
#     .include process_corners.inc
#     .endl
#
# The recovered symbols:
#   * `.model NAME TYPE(...)`         -> class (a named parameter set; TYPE is
#     its description)
#   * `.subckt NAME node ...`         -> class (a named subcircuit block)
#   * `.func NAME(args) {expr}`       -> function
#   * `.param NAME=VAL ...`           -> variable (one per assignment)
#   * `.include`/`.inc`/`.lib file`   -> import
# `*` starts a comment line; `$` and `;` start in-line comments; a leading `+`
# continues the previous logical line.  Directives are case-insensitive.
import re

from .regex_base import RegexCodeAnalyzer

_NM = r"[A-Za-z0-9_]+"


class SpiceLibAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "spice_lib"
    EXTENSIONS = (".lib",)
    LINE_COMMENTS = ("*", ";", "$")
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    _MODEL = re.compile(r"(?mi)^[ \t]*\.model\s+(" + _NM + r")\s+(" + _NM + r")")
    _SUBCKT = re.compile(r"(?mi)^[ \t]*\.subckt\s+(" + _NM + r")\b")
    _FUNC = re.compile(r"(?mi)^[ \t]*\.func\s+(" + _NM + r")\s*\(([^)]*)\)")
    _PARAM = re.compile(r"(?mi)^[ \t]*\.param\s+(.+)$")
    _KV = re.compile(r"(" + _NM + r")\s*=\s*([^\s=]+)")
    _INCLUDE = re.compile(r"(?mi)^[ \t]*\.(?:include|inc)\s+['\"]?([^'\"\s]+)")
    _LIB = re.compile(r"(?mi)^[ \t]*\.lib\s+['\"]?([^'\"\s]+)['\"]?\s+(" + _NM + r")")

    def _join_continuations(self, text):
        # SPICE line continuation: a line whose first non-blank char is `+`
        # continues the previous line.
        out = []
        for ln in text.splitlines():
            if ln.lstrip().startswith("+") and out:
                out[-1] = out[-1] + " " + ln.lstrip()[1:]
            else:
                out.append(ln)
        return "\n".join(out)

    def _extract_entities(self, file_id, text, path):
        clean = self._join_continuations(self._strip_comments(text))

        seen_c = set()
        for m in self._MODEL.finditer(clean):
            name = m.group(1)
            if name.lower() not in seen_c:
                seen_c.add(name.lower())
                self._add_class(file_id, name, description=f"SPICE .model {m.group(2)}")
        for m in self._SUBCKT.finditer(clean):
            name = m.group(1)
            if name.lower() not in seen_c:
                seen_c.add(name.lower())
                self._add_class(file_id, name, description="SPICE subcircuit")

        for m in self._FUNC.finditer(clean):
            arg_ids = [
                self._add_arg(a.split("=")[0].strip())
                for a in self._split_top_level(m.group(2))
            ]
            self._add_function(
                file_id, m.group(1), arg_ids, [], description="SPICE .func"
            )

        seen_v = set()
        for m in self._PARAM.finditer(clean):
            for kv in self._KV.finditer(m.group(1)):
                name = kv.group(1)
                if name.lower() in seen_v:
                    continue
                seen_v.add(name.lower())
                self._add_variable(file_id, name, kv.group(2), scope="param")

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.replace("\\", "/").split("/")[-1], src)
        for m in self._LIB.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, m.group(2), src, alias=m.group(2))
