# NetLogo source (.nl / .nls).
#
# NetLogo is the agent-based-modelling language; its `.nls` include files and
# the code tab of a `.nlogo` model share the same grammar:
#
#     extensions [ nw table ]
#     __includes [ "helpers.nls" ]
#     globals [ score ticks-left ]
#     breed [ wolves wolf ]
#     turtles-own [ energy ]
#     to setup
#       clear-all
#     end
#     to-report distance-to [ target ]
#       report distancexy target
#     end
#
#   to NAME [ args ]            -> function
#   to-report NAME [ args ]    -> function (+ a report output)
#   breed [ plural singular ]  -> class (an agent breed)
#   globals / <x>-own [ ... ]  -> variables
#   extensions / __includes    -> imports
#
# Comments run from `;` to end of line.  Identifiers are rich: letters, digits
# and `-_?!.+*<>=` are all legal in a NetLogo name.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_?!.\-+*<>=]*"


class NetLogoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "netlogo"
    EXTENSIONS = (".nl",)  # NetLogo `.nls`/`.nlogo` siblings appended at test time
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _PROC = re.compile(r"(?m)^\s*(to-report|to)\s+(" + _ID + r")\s*(\[[^\]]*\])?")
    _BREED = re.compile(r"(?m)^\s*breed\s*\[\s*(" + _ID + r")\s+(" + _ID + r")\s*\]")
    _GLOBALS = re.compile(r"(?m)^\s*(globals|" + _ID + r"-own)\s*\[([^\]]*)\]")
    _INCLUDES = re.compile(r"(?m)^\s*__includes\s*\[([^\]]*)\]")
    _EXTENSIONS = re.compile(r"(?m)^\s*extensions\s*\[([^\]]*)\]")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._BREED.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDES.finditer(clean):
            for tok in re.findall(r'"([^"]+)"', m.group(1)):
                self._add_import(file_id, tok.split("/")[-1], tok)
        for m in self._EXTENSIONS.finditer(clean):
            for tok in m.group(1).split():
                if re.fullmatch(_ID, tok):
                    self._add_import(file_id, tok, tok)

        for m in self._BREED.finditer(clean):
            plural, singular = m.group(1), m.group(2)
            self._add_class(
                file_id, plural, description=f"NetLogo breed (singular: {singular})"
            )

        seen_v = set()
        for m in self._GLOBALS.finditer(clean):
            scope = "global" if m.group(1) == "globals" else m.group(1)
            for tok in m.group(2).split():
                if re.fullmatch(_ID, tok) and tok not in seen_v:
                    seen_v.add(tok)
                    self._add_variable(file_id, tok, None, scope=scope)

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            kind, nm, args = m.group(1), m.group(2), m.group(3)
            if nm in seen_fn:
                continue
            seen_fn.add(nm)
            arg_ids = []
            if args:
                for tok in args.strip("[] ").split():
                    if re.fullmatch(_ID, tok):
                        arg_ids.append(self._add_arg(tok))
            outs = [self._add_output("reporter")] if kind == "to-report" else []
            self._add_function(
                file_id, nm, arg_ids, outs, description="NetLogo " + kind
            )
