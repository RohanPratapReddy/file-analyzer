# ZIMPL (.zpl) mathematical-programming modelling language analyzer.
#
# ZIMPL builds linear / (mixed-)integer programs.  Statements end in ';';
# comments are '#', '//' and '/* */'.  Real constructs (regex):
#
#     set A := { 1 .. 10 };                             -> variable (set)
#     set P[A] := ...;                                  -> variable (indexed set)
#     param cost[A] := <1> 3, <2> 5;                    -> variable (param)
#     param demand := 42;                               -> variable (param)
#     var x[A] binary;                                  -> variable (decision var)
#     var flow[A*A] >= 0 <= cap;                        -> variable (decision var)
#     maximize profit: sum <i> in A: p[i]*x[i];         -> function (objective)
#     minimize cost: ...;                               -> function (objective)
#     subto capacity: forall <i> in A: x[i] <= u[i];    -> function (constraint)
#     defnumb dist(a,b) := sqrt((a-b)^2);               -> function (user numeric)
#     defstrg label(i) := "n" ~ i;                      -> function (user string)
#     defset  neigh(v) := { <w> in V with adj[v,w] };   -> function (user set)
#     defbool near(a,b) := dist(a,b) < 3;               -> function (user bool)
#
# `set`/`param`/`var` bind named symbols; `maximize`/`minimize`/`subto` and the
# `def*` families are named callable definitions.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class ZIMPLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "zimpl"
    EXTENSIONS = (".zpl",)
    LINE_COMMENTS = ("#", "//")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _SET = re.compile(r"(?m)^\s*set\s+(" + _ID + r")\b")
    _PARAM = re.compile(r"(?m)^\s*param\s+(" + _ID + r")\b")
    _VAR = re.compile(r"(?m)^\s*var\s+(" + _ID + r")\b")
    _OBJ = re.compile(r"(?im)^\s*(maximize|minimize)\s+(" + _ID + r")\s*:")
    _SUBTO = re.compile(r"(?im)^\s*subto\s+(" + _ID + r")\s*:")
    _DEF = re.compile(
        r"(?im)^\s*(defnumb|defstrg|defset|defbool)\s+("
        + _ID
        + r")\s*(\([^)]*\))?\s*:="
    )
    _READ = re.compile(r"(?im)^\s*(?:param|set)\s+" + _ID + r'[^;]*?\bread\s+"([^"]+)"')

    def _register_types(self, file_id, text, path):
        return  # ZIMPL has no user-defined aggregate/record types

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._READ.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, re.split(r"[\\/]", src)[-1], src)

        for m in self._SET.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="set")
        for m in self._PARAM.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="param")
        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="var")

        for m in self._OBJ.finditer(clean):
            self._add_function(
                file_id,
                m.group(2),
                [],
                [self._add_output("objective")],
                description="zimpl " + m.group(1).lower(),
            )
        for m in self._SUBTO.finditer(clean):
            self._add_function(
                file_id, m.group(1), [], [], description="zimpl constraint"
            )
        for m in self._DEF.finditer(clean):
            kind, name, params = m.group(1), m.group(2), m.group(3)
            arg_ids = self._parse_params(params)
            ret = {
                "defnumb": "number",
                "defstrg": "string",
                "defset": "set",
                "defbool": "bool",
            }[kind.lower()]
            self._add_function(
                file_id,
                name,
                arg_ids,
                [self._add_output(ret)],
                description="zimpl " + kind.lower(),
            )

    def _parse_params(self, group):
        if not group:
            return []
        inner = group.strip().lstrip("(").rstrip(")")
        arg_ids = []
        for part in self._split_top_level(inner):
            part = part.strip()
            if not part:
                continue
            nm = re.findall(_ID, part)
            if nm:
                arg_ids.append(self._add_arg(nm[0]))
        return arg_ids
