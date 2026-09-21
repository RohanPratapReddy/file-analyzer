# Scilla (.scilla) Zilliqa smart-contract analyzer.
#
# Real parser for Scilla:
#
#     scilla_version 0
#     import BoolUtils ListUtils                 -> imports
#     library MyLib                              -> class (library)
#     let one = Uint128 1                         -> variable
#     let id = fun (x : Uint128) => x             -> function (functional let)
#     type Color = | Red | Green | Blue           -> class (ADT)
#     contract Wallet (owner : ByStr20)           -> class (params -> nothing)
#     field balance : Uint128 = Uint128 0         -> variable (mutable field)
#     transition Pay (to : ByStr20, amt : Uint128)  -> function
#       ... end
#     procedure Check (cond : Bool)                 -> function
#       ... end
#
# Comments are '(* *)' only.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class ScillaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "scilla"
    EXTENSIONS = (".scilla",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(r"^[ \t]*import\s+(.+)$", re.MULTILINE)
    _LIBRARY = re.compile(r"^[ \t]*library\s+([A-Za-z_]\w*)", re.MULTILINE)
    _CONTRACT = re.compile(r"^[ \t]*contract\s+([A-Za-z_]\w*)\s*\(([^)]*)\)",
                           re.MULTILINE)
    _TYPE = re.compile(r"^[ \t]*type\s+([A-Za-z_]\w*)", re.MULTILINE)
    _FIELD = re.compile(r"^[ \t]*field\s+([A-Za-z_]\w*)\s*:", re.MULTILINE)
    _TRANS = re.compile(r"^[ \t]*(transition|procedure)\s+([A-Za-z_]\w*)\s*"
                        r"\(([^)]*)\)", re.MULTILINE)
    _LET = re.compile(r"^[ \t]*let\s+([A-Za-z_]\w*)\s*(?::[^=]*)?=\s*(.*)$",
                      re.MULTILINE)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._LIBRARY.finditer(clean):
            self._register_class(m.group(1))
        for m in self._CONTRACT.finditer(clean):
            self._register_class(m.group(1))
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            for name in m.group(1).split():
                self._add_import(file_id, name, name)

        for m in self._LIBRARY.finditer(clean):
            self._add_class(file_id, m.group(1), description="scilla library")
        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="scilla type")

        for m in self._CONTRACT.finditer(clean):
            arg_ids = []
            for part in re.split(r",", m.group(2)):
                pm = re.search(r"([A-Za-z_]\w*)\s*:", part)
                if pm:
                    arg_ids.append(self._add_arg(pm.group(1)))
            self._add_class(file_id, m.group(1), description="scilla contract",
                            attr_ids=arg_ids)

        for m in self._FIELD.finditer(clean):
            self._add_variable(file_id, m.group(1), "field")

        for m in self._LET.finditer(clean):
            name, val = m.group(1), m.group(2).lstrip()
            if val.startswith(("fun ", "fun(", "tfun ", "tfun(")):
                self._add_function(file_id, name, [], [],
                                   description="scilla let-function")
            else:
                self._add_variable(file_id, name, "let")

        for m in self._TRANS.finditer(clean):
            arg_ids = []
            for part in re.split(r",", m.group(3)):
                pm = re.search(r"([A-Za-z_]\w*)\s*:", part)
                if pm:
                    arg_ids.append(self._add_arg(pm.group(1)))
            self._add_function(file_id, m.group(2), arg_ids, [],
                               description=f"scilla {m.group(1)}")
