# LookML (.lkml) analyzer -- Looker's modelling / semantic-layer DSL.
#
# LookML is a nested ``key: name { ... }`` config language:
#
#     include: "*.view.lkml"                     -> import
#     view: orders { ... }                       -> class
#     explore: orders { ... }                    -> class
#     datagroup: nightly { ... }                 -> class
#     dimension: status { type: string }         -> function (field)
#     measure: total { type: sum }               -> function (field)
#     dimension_group: created { ... }           -> function
#     filter: date_filter { ... }                -> function
#     parameter: metric { ... }                  -> function
#     join: users { ... }                        -> function
#     set: detail { fields: [...] }              -> variable
#     constant: name { value: "x" }              -> variable
#
# Comments are '#'; strings use '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"

_CLASS_KW = {"view", "explore", "model", "dashboard", "datagroup", "map_layer",
             "access_grant", "named_value_format", "query", "test"}
_FUNC_KW = {"dimension", "dimension_group", "measure", "filter", "parameter",
            "join", "element", "field", "action", "form_param"}
_VAR_KW = {"set", "constant"}


class LookMLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "lookml"
    EXTENSIONS = (".lkml",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _INCLUDE = re.compile(r'(?m)^\s*include\s*:\s*"([^"]+)"')
    _BLOCK = re.compile(r"(?m)^\s*(" + _ID + r")\s*:\s*(" + _ID + r")\s*\{")
    # top-level scalar params (connection:, project_name:, label:, ...): no name+brace
    _TOPPARAM = re.compile(r"(?m)^(" + _ID + r")\s*:\s*(?!\s*(?:" + _ID + r"\s*)?\{)\S")
    _TOP_SKIP = {"include", "dimension", "measure", "dimension_group", "filter",
                 "parameter", "set", "sql", "html", "type"}

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._BLOCK.finditer(clean):
            if m.group(1).lower() in _CLASS_KW:
                self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for m in self._BLOCK.finditer(clean):
            kw, name = m.group(1).lower(), m.group(2)
            if kw in _CLASS_KW:
                self._add_class(file_id, name, description="lookml " + kw)
            elif kw in _FUNC_KW:
                self._add_function(file_id, name, [], [],
                                   description="lookml " + kw)
            elif kw in _VAR_KW:
                self._add_variable(file_id, name, scope=kw)

        # top-level scalar model/view params (connection:, project_name:, ...)
        for m in self._TOPPARAM.finditer(clean):
            key = m.group(1).lower()
            if key not in self._TOP_SKIP:
                self._add_variable(file_id, m.group(1), scope="param")
