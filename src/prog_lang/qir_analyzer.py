# QIR (.qir) -- Quantum Intermediate Representation analyzer.
#
# QIR is a profile of textual LLVM IR that adds the quantum type/intrinsic
# surface (`%Qubit`, `%Result`, the `__quantum__qis__*` / `__quantum__rt__*`
# runtime).  The grammar is LLVM IR, so the named entities are the same:
#
#     source_filename = "bell.qir"
#     %Qubit = type opaque                              -> class (named type)
#     %Array = type opaque
#     @0 = internal constant [3 x i8] c"()\00"          -> variable (global)
#     declare void @__quantum__qis__h__body(%Qubit*)    -> function (intrinsic decl)
#     define void @Bell__main() #0 {                     -> function (+ args)
#     entry:
#       call void @__quantum__qis__h__body(%Qubit* null)
#       ret void
#     }
#     attributes #0 = { "entry_point" }
#
# `define`/`declare @name` -> functions, `@name =` globals -> variables and
# `%name = type ...` -> classes.  Line comments are ';'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class QIRAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "qir"
    EXTENSIONS = (".qir",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    # define/declare [attrs] <ret> @name(
    _FUNC = re.compile(r"^[ \t]*(define|declare)\b[^@\n]*@([A-Za-z_$.][\w$.]*)\s*\(",
                       re.MULTILINE)
    # @name = [linkage] global/constant ...
    _GLOBAL = re.compile(r"^[ \t]*@([A-Za-z_$.][\w$.]*)\s*=", re.MULTILINE)
    # %name = type { ... }  |  %name = type opaque
    _TYPE = re.compile(r"^[ \t]*%([A-Za-z_$.][\w$.]*)\s*=\s*type\b", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="qir named type")

        for m in self._GLOBAL.finditer(clean):
            self._add_variable(file_id, m.group(1), "global")

        for m in self._FUNC.finditer(clean):
            lp = clean.find("(", m.end() - 1)
            rp = self._find_matching(clean, lp, "(", ")")
            args = clean[lp + 1:rp - 1]
            arg_ids = []
            for part in self._split_top_level(args):
                part = part.strip()
                # named params end in `%q`; bare typed params (`%Qubit*`) do not
                nm = re.search(r"%([\w$.]+)\s*$", part)
                if nm:
                    ty = part.rsplit("%", 1)[0].strip() or None
                    arg_ids.append(self._add_arg(nm.group(1), ty))
            self._add_function(file_id, m.group(2), arg_ids, [],
                               description=f"qir {m.group(1)}")
