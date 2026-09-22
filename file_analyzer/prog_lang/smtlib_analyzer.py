# SMT-LIB 2 (.smt2) solver-script analyzer.
#
# Real parser for SMT-LIB v2 S-expression commands:
#
#     (set-logic QF_LIA)
#     (declare-const x Int)                         -> variable
#     (define-const c Int 5)                        -> variable
#     (declare-fun f (Int Int) Bool)                -> function (+ ret output)
#     (define-fun g ((a Int) (b Int)) Int (+ a b))  -> function (+ named args)
#     (declare-sort S 0)                            -> class (uninterpreted sort)
#     (define-sort Pair (X) (Array X X))            -> class
#     (declare-datatype Nat ((zero) (succ (pred Nat)))) -> class
#     (declare-datatypes ((Lst 1)) (...))           -> class (each declared sort)
#
# Symbols may be plain tokens or |quoted|.  Comments are ';'.
import re

from .regex_base import RegexCodeAnalyzer

_SYM = r"(\|[^|]*\||[^\s()]+)"


class SMTLibAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "smtlib"
    EXTENSIONS = (".smt2",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _DECL_FUN = re.compile(r"\(\s*declare-fun\s+" + _SYM)
    _DEF_FUN = re.compile(r"\(\s*define-fun(?:-rec)?\s+" + _SYM + r"\s*\(")
    _DECL_CONST = re.compile(r"\(\s*declare-const\s+" + _SYM)
    _DEF_CONST = re.compile(r"\(\s*define-const\s+" + _SYM)
    _DECL_SORT = re.compile(r"\(\s*declare-sort\s+" + _SYM)
    _DEF_SORT = re.compile(r"\(\s*define-sort\s+" + _SYM)
    _DECL_DT = re.compile(r"\(\s*declare-datatype\s+" + _SYM)
    _DECL_DTS = re.compile(r"\(\s*declare-datatypes\s*\(\s*(.*?)\)\s*\(", re.DOTALL)
    _PARAM = re.compile(r"\(\s*(\|[^|]*\||[^\s()]+)\s")

    @staticmethod
    def _clean_sym(s):
        return s[1:-1] if s.startswith("|") and s.endswith("|") else s

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._DECL_SORT.finditer(clean):
            self._register_class(self._clean_sym(m.group(1)))
        for m in self._DEF_SORT.finditer(clean):
            self._register_class(self._clean_sym(m.group(1)))
        for m in self._DECL_DT.finditer(clean):
            self._register_class(self._clean_sym(m.group(1)))
        for m in self._DECL_DTS.finditer(clean):
            for pm in re.finditer(r"\(\s*(\|[^|]*\||[^\s()]+)", m.group(1)):
                self._register_class(self._clean_sym(pm.group(1)))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._DECL_SORT.finditer(clean):
            self._add_class(
                file_id, self._clean_sym(m.group(1)), description="smt sort"
            )
        for m in self._DEF_SORT.finditer(clean):
            self._add_class(
                file_id, self._clean_sym(m.group(1)), description="smt sort-def"
            )
        for m in self._DECL_DT.finditer(clean):
            self._add_class(
                file_id, self._clean_sym(m.group(1)), description="smt datatype"
            )
        for m in self._DECL_DTS.finditer(clean):
            for pm in re.finditer(r"\(\s*(\|[^|]*\||[^\s()]+)", m.group(1)):
                self._add_class(
                    file_id, self._clean_sym(pm.group(1)), description="smt datatype"
                )

        for m in self._DECL_CONST.finditer(clean):
            self._add_variable(file_id, self._clean_sym(m.group(1)), "const")
        for m in self._DEF_CONST.finditer(clean):
            self._add_variable(file_id, self._clean_sym(m.group(1)), "const")

        for m in self._DECL_FUN.finditer(clean):
            name = self._clean_sym(m.group(1))
            # Argument sorts are a balanced ( ... ) list whose entries may be
            # nested sorts such as (_ BitVec 128); the return sort follows it.
            lp = clean.find("(", m.end())
            if lp < 0:
                self._add_function(file_id, name, [], [], description="smt declare-fun")
                continue
            rp = self._find_matching(clean, lp, "(", ")")
            arg_ids = [
                self._add_arg(s, "sort")
                for s in self._split_top_level(clean[lp + 1 : rp - 1], sep=" ")
            ]
            rest = clean[rp:].lstrip()
            if rest.startswith("("):
                re_end = self._find_matching(rest, 0, "(", ")")
                ret = rest[:re_end].strip()
            else:
                rm = re.match(r"[^\s()]+", rest)
                ret = rm.group(0) if rm else "?"
            out_ids = [self._add_output(ret)]
            self._add_function(
                file_id, name, arg_ids, out_ids, description="smt declare-fun"
            )

        for m in self._DEF_FUN.finditer(clean):
            name = self._clean_sym(m.group(1))
            lp = clean.find("(", m.end() - 1)
            rp = self._find_matching(clean, lp, "(", ")")
            params = clean[lp + 1 : rp - 1]
            arg_ids = [
                self._add_arg(self._clean_sym(pm.group(1)))
                for pm in self._PARAM.finditer(params)
            ]
            self._add_function(file_id, name, arg_ids, [], description="smt define-fun")
