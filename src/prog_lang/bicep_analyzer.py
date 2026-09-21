# Bicep (.bicep) analyzer  (Azure Resource Manager IaC DSL).
#
# Real parser for Bicep declarations:
#
#     import 'br/public:...'                        -> import
#     import { foo } from './shared.bicep'          -> import
#     param location string = resourceGroup().location   -> variable
#     var storageName = 'st${uniqueString(...)}'    -> variable
#     output endpoint string = stg.properties...    -> variable
#     type Sku = { name : string }                  -> class (user-defined type)
#     resource stg 'Microsoft.Storage/...@2023-01-01' = { }  -> class (resource)
#     module net './network.bicep' = { }            -> class (module)
#     func buildName(prefix string) string => '${prefix}x'   -> function
#
# Bicep strings use single quotes.  Comments are '//' and '/* */'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class BicepAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "bicep"
    EXTENSIONS = (".bicep",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ("'",)

    _IMPORT = re.compile(r"^[ \t]*import\s+(.+)$", re.MULTILINE)
    _PARAM = re.compile(r"^[ \t]*param\s+([A-Za-z_]\w*)\b", re.MULTILINE)
    _VAR = re.compile(r"^[ \t]*var\s+([A-Za-z_]\w*)\b", re.MULTILINE)
    _OUTPUT = re.compile(r"^[ \t]*output\s+([A-Za-z_]\w*)\b", re.MULTILINE)
    _RESOURCE = re.compile(r"^[ \t]*resource\s+([A-Za-z_]\w*)\b", re.MULTILINE)
    _MODULE = re.compile(r"^[ \t]*module\s+([A-Za-z_]\w*)\b", re.MULTILINE)
    _TYPE = re.compile(r"^[ \t]*type\s+([A-Za-z_]\w*)\b", re.MULTILINE)
    _FUNC = re.compile(r"^[ \t]*func\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
    _QUOTED = re.compile(r"'([^']+)'")
    _NAMES = re.compile(r"\{([^}]*)\}")

    def _args(self, blob):
        ids = []
        for part in self._split_top_level(blob or ""):
            toks = part.split()
            if toks:
                ids.append(self._add_arg(toks[0], toks[1] if len(toks) > 1 else None))
        return ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for rx in (self._RESOURCE, self._MODULE, self._TYPE):
            for m in rx.finditer(clean):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            line = m.group(1)
            q = self._QUOTED.search(line)
            src = q.group(1) if q else line.strip()
            nm = self._NAMES.search(line)
            self._add_import(file_id, src.split("/")[-1].split(":")[-1], src)

        for m in self._PARAM.finditer(clean):
            self._add_variable(file_id, m.group(1), "param")
        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1))
        for m in self._OUTPUT.finditer(clean):
            self._add_variable(file_id, m.group(1), "output")

        for m in self._RESOURCE.finditer(clean):
            self._add_class(file_id, m.group(1), description="bicep resource")
        for m in self._MODULE.finditer(clean):
            self._add_class(file_id, m.group(1), description="bicep module")
        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="bicep type")

        for m in self._FUNC.finditer(clean):
            lp = m.end() - 1
            rp = self._find_matching(clean, lp, "(", ")")
            self._add_function(file_id, m.group(1),
                               self._args(clean[lp + 1:rp - 1]), [],
                               description="bicep func")
