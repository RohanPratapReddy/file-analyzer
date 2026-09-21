# Haskell (.hs) and Literate Haskell (.lhs) analyzer.
#
# Real parser for Haskell layout syntax (`--` line, `{- -}` nesting comments):
#   module Data.Foo (a, b) where            -> module      (class row)
#   import qualified Data.Map as M (foo)     -> import
#   data Tree a = Leaf | Node a (Tree a)     -> data type   (class row, ctors)
#   newtype Wrap = Wrap Int                   -> newtype     (class row)
#   type Name = String                        -> type alias  (class row)
#   class Functor f where fmap :: ...         -> type class  (class row)
#   name :: Int -> Int                        -> function signature (declares fn)
#   name x = x + 1                            -> function binding
#   x = 5                                     -> value binding (variable)
#
# Literate Haskell (.lhs): only bird-track lines (starting with "> ") and
# \begin{code}..\end{code} blocks are source; everything else is prose.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class HaskellAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "haskell"
    EXTENSIONS = (".hs", ".lhs")
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = (("{-", "-}"),)

    _MODULE = re.compile(r"^\s*module\s+([\w.]+)", re.MULTILINE)
    _IMPORT = re.compile(
        r"^\s*import\s+(?:qualified\s+)?([\w.]+)"
        r"(?:\s+as\s+([\w.]+))?", re.MULTILINE)
    _DATA = re.compile(
        r"^\s*(data|newtype)\s+(\w+)([^\n=]*)(?:=(.*?))?(?=^\s*\S|\Z)",
        re.MULTILINE | re.DOTALL)
    _TYPE = re.compile(r"^\s*type\s+(\w+)", re.MULTILINE)
    _CLASS = re.compile(r"^\s*class\s+(?:.*?=>\s*)?(\w+)", re.MULTILINE)
    _INSTANCE = re.compile(r"^\s*instance\s+(?:.*?=>\s*)?([\w.]+)", re.MULTILINE)
    # Signatures may be indented (type-class methods); bindings are top-level.
    _SIG = re.compile(r"^\s*([a-z_][\w']*)\s*::", re.MULTILINE)
    # A function binding has >=1 argument token between the name and '='.
    _BIND = re.compile(r"^([a-z_][\w']*)[ \t]+[^\n=]*[^\s=][ \t]*=(?!=)",
                       re.MULTILINE)
    # A value binding has only whitespace between the name and '='.
    _VAL = re.compile(r"^([a-z_][\w']*)[ \t]*=(?!=)", re.MULTILINE)

    _KEYWORDS = {"module", "import", "data", "newtype", "type", "class",
                 "instance", "where", "deriving", "infixl", "infixr", "infix",
                 "foreign", "default", "let", "in", "do", "if", "then",
                 "else", "case", "of"}

    def _delit(self, text, path):
        if path.suffix.lower() != ".lhs":
            return text
        out, in_code = [], False
        for line in text.splitlines():
            if line.strip() == r"\begin{code}":
                in_code = True
                out.append("")
                continue
            if line.strip() == r"\end{code}":
                in_code = False
                out.append("")
                continue
            if in_code:
                out.append(line)
            elif line.startswith("> "):
                out.append(line[2:])
            elif line.startswith(">"):
                out.append(line[1:])
            else:
                out.append("")
        return "\n".join(out)

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(self._delit(text, path))
        for m in self._MODULE.finditer(t):
            self._register_class(m.group(1).split(".")[-1])
        for m in self._DATA.finditer(t):
            self._register_class(m.group(2))
        for m in self._TYPE.finditer(t):
            self._register_class(m.group(1))
        for m in self._CLASS.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(self._delit(text, path))

        for m in self._IMPORT.finditer(t):
            self._add_import(file_id, m.group(1).split(".")[-1], m.group(1),
                             alias=m.group(2))

        for m in self._MODULE.finditer(t):
            self._add_class(file_id, m.group(1).split(".")[-1],
                            description="haskell module")

        for m in self._DATA.finditer(t):
            kind, name, rhs = m.group(1), m.group(2), m.group(4) or ""
            attr_ids = []
            for ctor in rhs.split("|"):
                cm = re.match(r"\s*([A-Z]\w*)", ctor)
                if cm:
                    attr_ids.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description=f"haskell {kind}",
                            attr_ids=attr_ids)

        for m in self._TYPE.finditer(t):
            self._add_class(file_id, m.group(1), description="haskell type alias")

        for m in self._CLASS.finditer(t):
            cid = self._add_class(file_id, m.group(1),
                                  description="haskell type class")

        # Function signatures declare the callable; bindings realise it.
        declared = set()
        for m in self._SIG.finditer(t):
            name = m.group(1)
            if name in self._KEYWORDS or name in declared:
                continue
            declared.add(name)
            self._add_function(file_id, name)
        for m in self._BIND.finditer(t):
            name = m.group(1)
            if name in self._KEYWORDS or name in declared:
                continue
            declared.add(name)
            self._add_function(file_id, name)
        for m in self._VAL.finditer(t):
            name = m.group(1)
            if name in self._KEYWORDS or name in declared:
                continue
            declared.add(name)
            self._add_variable(file_id, name)
