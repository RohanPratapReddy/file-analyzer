# OpenDSS distribution-system script (.dss).
#
# OpenDSS (the EPRI Distribution System Simulator) is driven by a script of
# element-definition and control commands:
#
#     Clear
#     New Circuit.IEEE13   basekv=115 pu=1.0001 phases=3 bus1=SourceBus
#     New Line.650632  phases=3 bus1=RG60.1.2.3 bus2=632.1.2.3 length=2000
#     New Load.671  bus1=671.1.2.3  kV=4.16 kW=1155 kvar=660
#     Redirect  Loads.dss
#     Compile   Master.dss
#     Set Voltagebases=[115, 4.16, 0.48]
#     Solve
#
# The recovered symbols:
#   * `New  <Class>.<Name> ...`   -> a class (a named circuit element; the
#     OpenDSS element class such as Line/Load/Transformer is its description).
#     `Edit`/`~` (More) mutate an existing element and add no new symbol.
#   * `Redirect <file>` / `Compile <file>`   -> import
#   * `Set option=value`                     -> variable
# Commands are case-insensitive; `!` and `//` start comments.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_NM = r"[A-Za-z0-9_.\-]+"


class OpenDSSAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "opendss"
    EXTENSIONS = (".dss",)
    LINE_COMMENTS = ("!", "//")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    # `New object=Line.650632 ...` or `New Line.650632 ...`
    _NEW = re.compile(r"(?mi)^[ \t]*New\s+(?:object\s*=\s*)?"
                      r"(" + _NM + r")\.(" + _NM + r")")
    _REDIR = re.compile(r"(?mi)^[ \t]*(?:Redirect|Compile)\s+([^\s!/]+)")
    _SET = re.compile(r"(?mi)^[ \t]*Set\s+(" + _NM + r")\s*=\s*(\S+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen = set()
        for m in self._NEW.finditer(clean):
            klass, name = m.group(1), m.group(2)
            key = (klass.lower(), name.lower())
            if key in seen:
                continue
            seen.add(key)
            self._add_class(file_id, name, description=f"OpenDSS {klass}")

        for m in self._REDIR.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.replace("\\", "/").split("/")[-1], src)

        seen_v = set()
        for m in self._SET.finditer(clean):
            name = m.group(1)
            if name.lower() in seen_v:
                continue
            seen_v.add(name.lower())
            self._add_variable(file_id, name, m.group(2), scope="option")
