# Q# (.qs / .qsharp) quantum-program analyzer.
#
# Real parser for Microsoft Q# (C-family surface; '//' line comments, no block
# comments, "..." strings; '///' doc comments are just line comments):
#
#     namespace Quantum.Sample {                      -> namespace marker
#         open Microsoft.Quantum.Intrinsic;            -> import
#         open Microsoft.Quantum.Canon as Canon;       -> import (aliased)
#         newtype Complex = (Re : Double, Im : Double); -> class (named fields)
#         operation ApplyX(q : Qubit) : Unit is Adj+Ctl { ... }  -> function
#         function Square(x : Int) : Int { return x*x; }         -> function
#         internal operation Helper() : Unit { ... }
#     }
import re

from .regex_base import RegexCodeAnalyzer


class QSharpAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "qsharp"
    EXTENSIONS = (".qs", ".qsharp")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _OPEN = re.compile(
        r"^[ \t]*open\s+([\w.]+)(?:\s+as\s+([A-Za-z_]\w*))?", re.MULTILINE
    )
    _CALLABLE = re.compile(
        r"^[ \t]*(?:internal\s+|public\s+)?(operation|function)\s+"
        r"([A-Za-z_]\w*)(?:<[^>]*>)?\s*\(",
        re.MULTILINE,
    )
    _NEWTYPE = re.compile(
        r"^[ \t]*(?:internal\s+|public\s+)?newtype\s+([A-Za-z_]\w*)\s*=", re.MULTILINE
    )

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._NEWTYPE.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._OPEN.finditer(text):
            mod, alias = m.group(1), m.group(2)
            self._add_import(file_id, alias or mod.split(".")[-1], mod, alias)

        # newtype declarations -> classes with named tuple fields
        for m in self._NEWTYPE.finditer(text):
            name = m.group(1)
            eq = text.find("=", m.end() - 1)
            lb = text.find("(", eq)
            attrs = []
            if lb != -1 and (text.find(";", eq) == -1 or lb < text.find(";", eq)):
                rb = self._find_matching(text, lb, "(", ")")
                for fld in self._split_top_level(text[lb + 1 : rb - 1]):
                    fm = re.match(r"([A-Za-z_]\w*)\s*:\s*(.+)", fld.strip())
                    if fm:
                        attrs.append(self._add_arg(fm.group(1), fm.group(2).strip()))
            self._add_class(file_id, name, description="qsharp newtype", attr_ids=attrs)

        # operations / functions
        for m in self._CALLABLE.finditer(text):
            kind, name = m.group(1), m.group(2)
            lb = text.find("(", m.end() - 1)
            rb = self._find_matching(text, lb, "(", ")")
            arg_ids = []
            for p in self._split_top_level(text[lb + 1 : rb - 1]):
                pm = re.match(r"([A-Za-z_]\w*)\s*:\s*(.+)", p.strip())
                if pm:
                    arg_ids.append(self._add_arg(pm.group(1), pm.group(2).strip()))
            out_ids = []
            rm = re.match(r"\s*:\s*([^\{\n]+?)(?:\bis\b|\{|$)", text[rb:])
            if rm and rm.group(1).strip():
                out_ids.append(self._add_output(rm.group(1).strip()))
            self._add_function(
                file_id, name, arg_ids, out_ids, description=f"qsharp {kind}"
            )
