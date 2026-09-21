# Agda (.agda) analyzer.
#
# Real parser for Agda (a dependently-typed language, Haskell-like layout; '--'
# line and nested '{- -}' block comments, '{-# ... #-}' pragmas; strings "..."):
#   module Foo.Bar where                            -> (module marker)
#   open import Data.Nat                             -> import
#   open import Data.List using (List; _++_)         -> import (+ names)
#   import Data.Maybe as M                            -> import (aliased)
#   data Nat : Set where                              -> class (+ constructors)
#     zero : Nat
#     suc  : Nat -> Nat
#   record Pair (A B : Set) : Set where               -> class (+ fields)
#     field  fst : A
#            snd : B
#   postulate  f : A -> B                              -> function
#   _+_ : Nat -> Nat -> Nat                            -> (type signature)
#   zero  + n = n                                       -> function
import re

from .regex_base import RegexCodeAnalyzer

# an Agda name is a run of non-space, non-reserved-punctuation glyphs; this keeps
# mixfix / unicode operator names such as _+_ , _∷_ , ↑_ intact.
_NAME = r"[^\s(){}@\";.]+"


class AgdaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "agda"
    EXTENSIONS = (".agda",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()  # nested {- -} (and {-# #-}) handled below
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r"^[ \t]*(?:open\s+import|import|open)\s+([\w.]+)"
        r"(?:\s+as\s+([\w.]+))?(?:.*?\busing\s*\(([^)]*)\))?",
        re.MULTILINE,
    )
    _DATA = re.compile(r"^[ \t]*data\s+(" + _NAME + r")", re.MULTILINE)
    _RECORD = re.compile(r"^[ \t]*record\s+(" + _NAME + r")", re.MULTILINE)
    _POSTULATE = re.compile(r"^[ \t]*postulate\b", re.MULTILINE)
    _SIG = re.compile(r"^([ \t]*)(" + _NAME + r")\s*:(?!:)\s*(.+)$", re.MULTILINE)
    _DEF = re.compile(r"^(" + _NAME + r")\s+([^=\n]*?)=(?!=)", re.MULTILINE)

    # --- nested block-comment / pragma stripping -----------------------
    def _strip_block(self, text):
        out, i, n, depth = [], 0, len(text), 0
        while i < n:
            if depth == 0 and text[i] == '"':
                out.append('"')
                i += 1
                while i < n:
                    c = text[i]
                    out.append(c)
                    if c == "\\" and i + 1 < n:
                        out.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    if c == '"':
                        break
                continue
            if text[i : i + 2] == "{-":  # covers {- and {-#
                depth += 1
                out.append("  ")
                i += 2
                continue
            if text[i : i + 2] == "-}" and depth > 0:
                depth -= 1
                out.append("  ")
                i += 2
                continue
            if depth > 0:
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
                continue
            out.append(text[i])
            i += 1
        return "".join(out)

    def _clean(self, text):
        return self._strip_comments(self._strip_block(text))

    def _indent_body(self, text, decl_start):
        nl = text.find("\n", decl_start)
        if nl == -1:
            return ""
        base = self._indent_of(text[decl_start:nl])
        out = []
        for line in text[nl + 1 :].splitlines(keepends=True):
            if line.strip() and self._indent_of(line) <= base:
                break
            out.append(line)
        return "".join(out)

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for rx in (self._DATA, self._RECORD):
            for m in rx.finditer(text):
                self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        for m in self._IMPORT.finditer(text):
            mod, alias, using = m.group(1), m.group(2), m.group(3)
            self._add_import(file_id, (alias or mod).split(".")[-1], mod, alias)
            if using:
                for nm in using.split(";"):
                    nm = nm.strip()
                    if nm:
                        self._add_import(file_id, nm, f"{mod}.{nm}")

        # data types -> constructors as attrs (from the indented where-block)
        for m in self._DATA.finditer(text):
            name = m.group(1)
            body = self._indent_body(text, m.start())
            cons = []
            for cm in re.finditer(r"^\s+(" + _NAME + r")\s*:(?!:)", body, re.MULTILINE):
                cons.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="agda data", attr_ids=cons)

        # records -> field names as attrs
        for m in self._RECORD.finditer(text):
            name = m.group(1)
            body = self._indent_body(text, m.start())
            attrs = []
            fm = re.search(r"^\s*field\b", body, re.MULTILINE)
            if fm:
                fblock = self._indent_body(body, fm.start())
                for f in re.finditer(
                    r"^\s*(" + _NAME + r")\s*:(?!:)", fblock, re.MULTILINE
                ):
                    attrs.append(self._add_arg(f.group(1), "field"))
            self._add_class(file_id, name, description="agda record", attr_ids=attrs)

        # postulate blocks -> declared names become functions
        for m in self._POSTULATE.finditer(text):
            body = self._indent_body(text, m.start())
            for pm in re.finditer(r"^\s*(" + _NAME + r")\s*:(?!:)", body, re.MULTILINE):
                self._add_function(
                    file_id, pm.group(1), [], [], description="agda postulate"
                )

        # top-level signatures (indent 0) + definitions
        reserved = {
            "module",
            "where",
            "data",
            "record",
            "field",
            "postulate",
            "open",
            "import",
            "using",
            "hiding",
            "renaming",
            "with",
            "mutual",
            "abstract",
            "private",
            "instance",
            "primitive",
            "infixl",
            "infixr",
            "infix",
            "syntax",
            "let",
            "in",
        }
        sigs = {}
        for m in self._SIG.finditer(text):
            if len(m.group(1)) == 0 and m.group(2) not in reserved:
                sigs.setdefault(m.group(2), m.group(3).strip())

        emitted = set()
        for name, sig in sigs.items():
            out_ids = (
                [self._add_output(sig.split("->")[-1].strip()[:80])]
                if "->" in sig or "→" in sig
                else []
            )
            if "->" in sig or "→" in sig:
                self._add_function(
                    file_id, name, [], out_ids, description="agda function"
                )
            else:
                self._add_variable(file_id, name, sig[:80])
            emitted.add(name)
        # definitions whose signature was not at indent 0 (local sigs etc.)
        for m in self._DEF.finditer(text):
            name = m.group(1)
            if name in emitted or name in reserved:
                continue
            emitted.add(name)
            self._add_function(file_id, name, [], [], description="agda function")
