# Universal Robots URScript (.script) analyzer -- readable robot program format.
#
#     def my_program():                             -> function
#         global tcp_speed = 0.25                   -> variable (global)
#         local counter = 0                          -> variable (local)
#         movej([0,-1.57,0,0,0,0], a=1.2, v=0.5)
#     end
#     thread watchdog():                            -> function
#     end
#     sec safety():                                 -> function
#     tool_offset = p[0,0,0.1,0,0,0]                -> variable (module)
#
# Python-like: comments '#'; strings '"' and "'". No imports/classes.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class URScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "urscript"
    EXTENSIONS = (".script",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _FUNC = re.compile(r"(?m)^\s*(?:def|thread|sec)\s+(" + _ID +
                       r")\s*\(([^)]*)\)\s*:")
    _GLOBAL = re.compile(r"(?m)^\s*(?:global|local)\s+(" + _ID + r")\s*=(?!=)")
    _ASSIGN = re.compile(r"(?m)^\s*(" + _ID + r")\s*=(?!=)")

    def _register_types(self, file_id, text, path):
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        func_names = set()
        for m in self._FUNC.finditer(clean):
            args = self._ur_args(m.group(2))
            self._add_function(file_id, m.group(1), args, [],
                               description="urscript function")
            func_names.add(m.group(1))

        seen = set()
        for m in self._GLOBAL.finditer(clean):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                self._add_variable(file_id, name, scope="global")
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in seen or name in func_names:
                continue
            seen.add(name)
            self._add_variable(file_id, name, scope="module")

    def _ur_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip().split("=")[0].strip()
            m = re.match(_ID, part)
            if m:
                arg_ids.append(self._add_arg(m.group(0)))
        return arg_ids
