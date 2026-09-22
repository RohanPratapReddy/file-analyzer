# LLVM IR (.ll) textual-assembly analyzer.
#
# Real parser for LLVM IR:
#
#     source_filename = "x.c"
#     %struct.Point = type { i32, i32 }        -> class (named struct type)
#     @global_counter = global i32 0            -> variable (global)
#     @.str = private constant [4 x i8] c"hi\00"
#     declare i32 @printf(i8*, ...)             -> function (external decl)
#     define i32 @add(i32 %a, i32 %b) {         -> function (+ named args)
#       %sum = add i32 %a, %b
#       ret i32 %sum
#     }
#
# `define`/`declare @name` become functions, top-level `@name =` globals become
# variables and `%name = type ...` become classes.  Comments are ';'.
import re

from .regex_base import RegexCodeAnalyzer


class LLVMIRAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "llvmir"
    EXTENSIONS = (".ll",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(
        r"^[ \t]*(define|declare)\b[^@\n]*@([A-Za-z_$.][\w$.]*)\s*\(", re.MULTILINE
    )
    _GLOBAL = re.compile(r"^[ \t]*@([A-Za-z_$.][\w$.]*)\s*=", re.MULTILINE)
    _TYPE = re.compile(r"^[ \t]*%([A-Za-z_$.][\w$.]*)\s*=\s*type\b", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="llvm named type")

        for m in self._GLOBAL.finditer(clean):
            self._add_variable(file_id, m.group(1), "global")

        for m in self._FUNC.finditer(clean):
            lp = clean.find("(", m.end() - 1)
            rp = self._find_matching(clean, lp, "(", ")")
            args = clean[lp + 1 : rp - 1]
            arg_ids = []
            for part in self._split_top_level(args):
                nm = re.search(r"%([\w$.]+)\s*$", part.strip())
                if nm:
                    ty = part.strip().rsplit("%", 1)[0].strip() or None
                    arg_ids.append(self._add_arg(nm.group(1), ty))
            self._add_function(
                file_id, m.group(2), arg_ids, [], description=f"llvm {m.group(1)}"
            )
