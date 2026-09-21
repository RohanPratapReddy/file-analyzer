# MLIR (.mlir) multi-level-IR analyzer.
#
# Real parser for MLIR textual assembly:
#
#     module @my_module {                          -> class (named module)
#       func.func @add(%a: i32, %b: i32) -> i32 {  -> function (+ args)
#         %0 = arith.addi %a, %b : i32
#         return %0 : i32
#       }
#       func.func private @ext(%x: f32)            -> function
#       llvm.func @llfn(%p: !llvm.ptr)             -> function
#       llvm.mlir.global external @g() : i32       -> variable (global)
#       memref.global @buf : memref<4xf32>         -> variable
#     }
#
# Any `*func @name(args)` becomes a function, `module @name` a class and a
# `*global ... @name` a variable.  Comments are '//'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class MLIRAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "mlir"
    EXTENSIONS = (".mlir",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(
        r"^[ \t]*(?:[A-Za-z_][\w.]*\.)?func\b[^@\n]*@([A-Za-z_$][\w$.]*)\s*"
        r"\(([^)]*)\)", re.MULTILINE)
    _MODULE = re.compile(r"^[ \t]*module\s+@([A-Za-z_$][\w$.]*)", re.MULTILINE)
    _GLOBAL = re.compile(r"^[ \t]*(?:[A-Za-z_][\w.]*\.)*global\b[^@\n]*"
                         r"@([A-Za-z_$][\w$.]*)", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._MODULE.finditer(clean):
            self._add_class(file_id, m.group(1), description="mlir module")

        for m in self._GLOBAL.finditer(clean):
            self._add_variable(file_id, m.group(1), "global")

        for m in self._FUNC.finditer(clean):
            arg_ids = []
            for part in self._split_top_level(m.group(2)):
                pm = re.match(r"(%[\w$.]+)", part.strip())
                if pm:
                    ty = part.split(":", 1)[1].strip() if ":" in part else None
                    arg_ids.append(self._add_arg(pm.group(1).lstrip("%"), ty))
            self._add_function(file_id, m.group(1), arg_ids, [],
                               description="mlir func")
