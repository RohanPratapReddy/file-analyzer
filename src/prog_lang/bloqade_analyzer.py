# Bloqade neutral-atom program (.blq).
#
# Bloqade describes analog neutral-atom (Rydberg) quantum programs: an atom
# register / lattice, time-dependent Rabi and detuning waveforms, and pulse
# sequences / Hamiltonians built from them.  This analyzer recovers the named
# constructs of a Bloqade program:
#
#     using Bloqade                              -> import
#     import Yao                                 -> import
#     register atoms = AtomList([(0,0),(0,5)])   -> variable (scope "register")
#     lattice chain = rectangular(4, 1)          -> variable (scope "register")
#     waveform Omega(t) = piecewise_linear(...)  -> function (parametric waveform)
#     waveform Delta = constant(1.0)             -> variable (constant waveform)
#     sequence rabi_drive                        -> class (pulse sequence)
#     hamiltonian h_ising                        -> class
#     function evolve(reg, T)                     -> function
#         ...
#     end
#
# `#` starts a comment; `"` delimits strings; keywords are case-sensitive.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_]\w*"


class BloqadeAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "bloqade"
    EXTENSIONS = (".blq",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(r"(?m)^[ \t]*(?:using|import)\s+(" + _ID + r")")
    _SEQ = re.compile(
        r"(?m)^[ \t]*(?:sequence|hamiltonian|program|protocol)\s+(" + _ID + r")\b"
    )
    _FUNC = re.compile(r"(?m)^[ \t]*function\s+(" + _ID + r")\s*\(([^)]*)\)")
    # waveform NAME(args) = ...   -> function ;   waveform NAME = ...  -> variable
    _WAVEFORM = re.compile(r"(?m)^[ \t]*waveform\s+(" + _ID + r")\s*(\(([^)]*)\))?\s*=")
    _REGISTER = re.compile(
        r"(?m)^[ \t]*(?:register|lattice|atoms)\s+(" + _ID + r")\s*="
    )

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_i = set()
        for m in self._IMPORT.finditer(clean):
            name = m.group(1)
            if name not in seen_i:
                seen_i.add(name)
                self._add_import(file_id, name, name)

        seen_c = set()
        for m in self._SEQ.finditer(clean):
            name = m.group(1)
            if name not in seen_c:
                seen_c.add(name)
                self._add_class(file_id, name, description="Bloqade sequence")

        seen_v = set()

        def add_var(name, scope):
            if name and name not in seen_v:
                seen_v.add(name)
                self._add_variable(file_id, name, None, scope=scope)

        for m in self._REGISTER.finditer(clean):
            add_var(m.group(1), "register")

        seen_fn = set()

        def add_fn(name, argstr, desc):
            if not name or name in seen_fn:
                return
            seen_fn.add(name)
            arg_ids = []
            if argstr and argstr.strip():
                for a in self._split_top_level(argstr):
                    a = a.strip()
                    if a:
                        arg_ids.append(self._add_arg(a))
            self._add_function(file_id, name, arg_ids, [], description=desc)

        for m in self._WAVEFORM.finditer(clean):
            name, has_args, args = m.group(1), m.group(2), m.group(3)
            if has_args:
                add_fn(name, args, "Bloqade waveform")
            else:
                add_var(name, "waveform")
        for m in self._FUNC.finditer(clean):
            add_fn(m.group(1), m.group(2), "Bloqade function")
