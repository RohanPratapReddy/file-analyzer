# Classiq Qmod (.qmod) analyzer -- high-level quantum modeling language.
#
#     qfunc main(output x: QNum) {                  -> function (+ output)
#         allocate(4, x);
#     }
#     qfunc my_oracle(x: QArray<QBit>, permutable) {-> function
#     }
#     struct MoleculeProblem {                      -> class
#         mapping: FermionMapping;                  -> (field)
#     }
#     qstruct QsvmData {                            -> class
#     }
#     enum Pauli { I, X, Y, Z }                     -> class
#
# Comments '//' and '/* */'; strings '"'. (Also tolerates JSON-model .qmod:
#   "function_name": "..." pairs are NOT parsed -- native syntax only.)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class QmodAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "qmod"
    EXTENSIONS = (".qmod",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _QFUNC = re.compile(r"(?m)^\s*qfunc\s+(" + _ID + r")\s*\(")
    _CLASS = re.compile(r"(?m)^\s*(?:struct|qstruct|enum)\s+(" + _ID + r")\b")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._CLASS.finditer(clean):
            self._add_class(file_id, m.group(1), description="qmod type")

        for m in self._QFUNC.finditer(clean):
            popen = clean.index("(", m.start())
            pclose = self._find_matching(clean, popen, "(", ")")
            args = self._qmod_args(clean[popen + 1:pclose - 1])
            outs = self._qmod_outputs(clean[popen + 1:pclose - 1])
            self._add_function(file_id, m.group(1), args, outs,
                               description="qmod qfunc")

    def _qmod_args(self, inner):
        arg_ids = []
        for part in self._split_top_level(inner, opens="([{<", closes=")]}>"):
            part = part.strip()
            if not part:
                continue
            # direction qualifiers / plain flags: `output x: QNum`, `permutable`
            m = re.match(r"(?:(input|output|inout)\s+)?(" + _ID + r")\s*"
                         r"(?::\s*(.+))?$", part)
            if not m:
                continue
            name, atype = m.group(2), (m.group(3) or "").strip() or None
            # bare `permutable`/`qperm` with no type is a modifier, not an arg
            if atype is None and name in ("permutable", "qperm"):
                continue
            arg_ids.append(self._add_arg(name, atype))
        return arg_ids

    def _qmod_outputs(self, inner):
        outs = []
        for part in self._split_top_level(inner, opens="([{<", closes=")]}>"):
            m = re.match(r"\s*output\s+" + _ID + r"\s*:\s*(.+)$", part.strip())
            if m:
                outs.append(self._add_output(m.group(1).strip()))
        return outs
