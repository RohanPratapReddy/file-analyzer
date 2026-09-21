# SPICE netlist (.cir / .sp / .spi / .subckt) analyzer.
#
# SPICE circuit netlists are line oriented and case-insensitive.  A whole-line
# comment starts with '*' in column 0; instance ("element") cards start with a
# device letter; dot-directives configure the simulation:
#
#     * a comment line                          -> (ignored)
#     .subckt inv in out vdd                    -> class (subcircuit; nodes=attrs)
#     .model nmos NMOS (level=1 vto=0.7)        -> class (device model)
#     .param vdd=1.8 temp=27                    -> variable (each)
#     .func sq(x) {x*x}                          -> function
#     .global vdd gnd                            -> variable (scope global)
#     .include "models.lib"                      -> import
#     .lib "cmos.lib" tt                         -> import
#     M1 d g s b nmos w=1u l=0.18u               -> variable (instance)
#     Xinv a y vdd inv                           -> variable (instance)
#     .ends / .end                               -> (markers, ignored)
#
# A leading '+' continues the previous logical line.  Strings use '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
# Element / node tokens may carry these netlist-legal punctuation chars.
_TOK = r"[A-Za-z0-9_:!$#.+/\\-]+"


class SpiceAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "spice"
    EXTENSIONS = (".cir", ".sp", ".spi", ".subckt")
    LINE_COMMENTS = ()          # '*' is column-0 only -> handled in _decomment
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _SUBCKT = re.compile(r"(?im)^[ \t]*\.subckt\s+(" + _ID + r")\s*(.*)$")
    _MODEL = re.compile(r"(?im)^[ \t]*\.model\s+(" + _ID + r")\b")
    _PARAM = re.compile(r"(?im)^[ \t]*\.param(?:s)?\s+(.*)$")
    _FUNC = re.compile(r"(?im)^[ \t]*\.func\s+(" + _ID + r")\s*\(([^)]*)\)")
    _GLOBAL = re.compile(r"(?im)^[ \t]*\.global\s+(.*)$")
    _INCLUDE = re.compile(r"(?im)^[ \t]*\.(?:include|inc|lib)\s+(.*)$")
    _ELEMENT = re.compile(r"(?im)^([A-Za-z][A-Za-z0-9_:!$#]*)\s+(\S.*)$")
    _ASSIGN = re.compile(r"(" + _ID + r")\s*=")

    def _decomment(self, text):
        """Blank whole-line '*' comments (keep newlines) and drop trailing
        '$'/';' inline comments, leaving '*' inside expressions untouched."""
        out = []
        for line in text.split("\n"):
            s = line.lstrip()
            if s.startswith("*"):
                out.append("")
                continue
            # HSPICE inline comments: '$' or ';' introduce a comment to EOL.
            for c in ("$", ";"):
                pos = line.find(c)
                if pos != -1:
                    line = line[:pos]
            out.append(line)
        return "\n".join(out)

    def _nodes_and_params(self, rest):
        """Split a subckt header tail into leading node names (attrs) and the
        trailing ``name=value`` parameter list (variables)."""
        nodes, params = [], []
        seen_param = False
        for tok in rest.split():
            if "=" in tok or seen_param:
                seen_param = True
                params.append(tok)
            else:
                nodes.append(tok)
        return nodes, " ".join(params)

    def _register_types(self, file_id, text, path):
        clean = self._decomment(text)
        for m in self._SUBCKT.finditer(clean):
            self._register_class(m.group(1))
        for m in self._MODEL.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._decomment(text)

        for m in self._INCLUDE.finditer(clean):
            tail = m.group(1).strip()
            fname = tail.split()[0].strip('"\'') if tail else ""
            if fname:
                leaf = re.split(r"[\\/]", fname)[-1]
                self._add_import(file_id, leaf, fname)

        for m in self._SUBCKT.finditer(clean):
            nodes, params = self._nodes_and_params(m.group(2))
            attrs = [self._add_arg(n) for n in nodes]
            self._add_class(file_id, m.group(1), description="spice subcircuit",
                            attr_ids=attrs or None)
            for pm in self._ASSIGN.finditer(params):
                self._add_variable(file_id, pm.group(1), scope="param")

        for m in self._MODEL.finditer(clean):
            self._add_class(file_id, m.group(1), description="spice model")

        for m in self._FUNC.finditer(clean):
            args = [self._add_arg(a.strip()) for a in m.group(2).split(",")
                    if a.strip()]
            self._add_function(file_id, m.group(1), args, [],
                               description="spice function")

        for m in self._PARAM.finditer(clean):
            for pm in self._ASSIGN.finditer(m.group(1)):
                self._add_variable(file_id, pm.group(1), scope="param")

        for m in self._GLOBAL.finditer(clean):
            for tok in m.group(1).split():
                if re.match(_ID + r"$", tok):
                    self._add_variable(file_id, tok, scope="global")

        for m in self._ELEMENT.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="instance")
