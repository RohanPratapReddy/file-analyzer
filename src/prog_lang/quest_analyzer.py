# QuEST simulation script (.quest).
#
# QuEST (Quantum Exact Simulation Toolkit) programs are C source written against
# the QuEST.h API: they `#include` headers, define ordinary C functions, and
# allocate quantum registers with `createQureg(...)` / `createDensityQureg(...)`.
# This analyzer recovers the C-level named entities plus the QuEST-specific
# register allocations:
#
#     #include <QuEST.h>                       -> import
#     typedef struct { qreal p; } Config;      -> class
#     Qureg qubits = createQureg(3, env);      -> variable (scope "qureg")
#     qreal prob = 0.0;                         -> variable
#     void applyOracle(Qureg q, int n) { ... } -> function
#     int main() { ... }                        -> function
#
# `//` and `/* */` are comments; `"` / `'` delimit strings; the C control
# keywords (if/for/while/switch/return/sizeof) are never read as function names.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_]\w*"
_TYPE = r"[A-Za-z_]\w*(?:\s*\*+|\s+\*+)?"
_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "else",
    "do",
    "case",
    "default",
    "typedef",
    "struct",
    "union",
    "enum",
    "static",
    "inline",
    "const",
    "extern",
    "void",
}
# QuEST register / handle types whose declarations are worth surfacing as data.
_QUREG_TYPES = (
    "Qureg",
    "DensityMatrix",
    "QuESTEnv",
    "PauliHamil",
    "ComplexMatrixN",
    "DiagonalOp",
    "SubDiagonalOp",
)


class QuestAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "quest"
    EXTENSIONS = (".quest",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _INCLUDE = re.compile(r'(?m)^[ \t]*#\s*include\s+[<"]([^>"]+)[>"]')
    # function definition:  RET name(args) {
    _FUNC = re.compile(
        r"(?m)^[ \t]*(?:static\s+|inline\s+|extern\s+)*"
        r"(?:" + _TYPE + r")\s+(" + _ID + r")\s*\(([^;{]*)\)\s*\{"
    )
    # QuEST register / handle declaration
    _QUREG = re.compile(
        r"(?m)^[ \t]*(?:" + "|".join(_QUREG_TYPES) + r")\s+(" + _ID + r")\s*[=;]"
    )
    # typedef struct { ... } Name;   and   struct Name {
    _TYPEDEF = re.compile(
        r"(?ms)\btypedef\s+(?:struct|union|enum)\b[^;{]*\{.*?\}\s*(" + _ID + r")\s*;"
    )
    _RECORD = re.compile(r"(?m)^[ \t]*(?:struct|union|enum)\s+(" + _ID + r")\s*\{")
    # plain top-level scalar declaration:  qreal x = ...;  int n;
    _VARDECL = re.compile(
        r"(?m)^[ \t]*(?:qreal|qcomp|int|long|unsigned|double|"
        r"float|char|short|Complex|enum\s+\w+)\s+(" + _ID + r")\s*(?:=|;|\[)"
    )

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.replace("\\", "/").split("/")[-1], src)

        seen_c = set()
        for rx in (self._TYPEDEF, self._RECORD):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name not in seen_c:
                    seen_c.add(name)
                    self._add_class(file_id, name, description="C record")

        seen_v = set()

        def add_var(name, scope):
            if name and name not in seen_v and name not in _KEYWORDS:
                seen_v.add(name)
                self._add_variable(file_id, name, None, scope=scope)

        for m in self._QUREG.finditer(clean):
            add_var(m.group(1), "qureg")
        for m in self._VARDECL.finditer(clean):
            add_var(m.group(1), "module")

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in _KEYWORDS or name in seen_fn:
                continue
            seen_fn.add(name)
            arg_ids = []
            args = m.group(2).strip()
            if args and args != "void":
                for a in self._split_top_level(args):
                    a = a.strip()
                    if not a:
                        continue
                    parts = a.replace("*", " ").split()
                    pname = parts[-1] if len(parts) > 1 else a
                    ptype = " ".join(parts[:-1]) if len(parts) > 1 else None
                    arg_ids.append(self._add_arg(pname, ptype))
            self._add_function(
                file_id, name, arg_ids, [], description="QuEST/C function"
            )
