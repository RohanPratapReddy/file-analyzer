# RAPID (.rapid) analyzer -- ABB industrial-robot language.
#
#     MODULE MainModule                             -> class (module)
#         VAR num counter := 0;                     -> variable
#         PERS bool flag := TRUE;                   -> variable
#         CONST robtarget home := [...];            -> variable
#         PROC main()                               -> function
#             MoveJ home, v100, fine, tool0;
#         ENDPROC
#         FUNC num Add(num a, num b)                -> function (+ num output)
#             RETURN a + b;
#         ENDFUNC
#         TRAP emergencyStop                        -> function
#     ENDMODULE
#
# Comments are '!'; strings use '"'. Case-insensitive keywords.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_TYPE = r"[A-Za-z_][A-Za-z0-9_]*"


class RAPIDAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "rapid"
    EXTENSIONS = (".rapid",)
    LINE_COMMENTS = ("!",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _MODULE = re.compile(r"(?im)^\s*MODULE\s+(" + _ID + r")")
    _PROC = re.compile(r"(?im)^\s*(?:LOCAL\s+|GLOBAL\s+)?PROC\s+(" + _ID +
                       r")\s*\(([^)]*)\)")
    _FUNC = re.compile(r"(?im)^\s*(?:LOCAL\s+|GLOBAL\s+)?FUNC\s+(" + _TYPE +
                       r")\s+(" + _ID + r")\s*\(([^)]*)\)")
    _TRAP = re.compile(r"(?im)^\s*(?:LOCAL\s+|GLOBAL\s+)?TRAP\s+(" + _ID + r")")
    # VAR / PERS / CONST  TYPE  name
    _DATA = re.compile(r"(?im)^\s*(?:LOCAL\s+|TASK\s+|GLOBAL\s+)?"
                       r"(?:VAR|PERS|CONST)\s+(?:" + _TYPE + r")\s+(" + _ID +
                       r")\b")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        cls_id = None
        for m in self._MODULE.finditer(clean):
            cls_id = self._register_class(m.group(1))
            self._add_class(file_id, m.group(1), description="rapid module")

        for m in self._PROC.finditer(clean):
            args = self._rapid_args(m.group(2))
            self._add_function(file_id, m.group(1), args, [], class_id=cls_id,
                               description="rapid proc")
        for m in self._FUNC.finditer(clean):
            args = self._rapid_args(m.group(3))
            outs = [self._add_output(m.group(1))]
            self._add_function(file_id, m.group(2), args, outs, class_id=cls_id,
                               description="rapid func")
        for m in self._TRAP.finditer(clean):
            self._add_function(file_id, m.group(1), [], [], class_id=cls_id,
                               description="rapid trap")

        seen = set()
        for m in self._DATA.finditer(clean):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            self._add_variable(file_id, name, scope="module")

    def _rapid_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip()
            if not part:
                continue
            # `num a` / `INOUT num a` / `\switch opt` / `PERS tool t`
            part = part.lstrip("\\").strip()
            toks = re.findall(_ID, part)
            if toks:
                name = toks[-1]
                atype = toks[-2] if len(toks) >= 2 else None
                arg_ids.append(self._add_arg(name, atype))
        return arg_ids
