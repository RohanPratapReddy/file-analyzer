# Lean 4 (.lean) analyzer.
#
# Real parser for Lean 4 ('--' line and nested '/- -/' block comments; strings
# "..."):
#   import Mathlib.Data.Nat.Basic                        -> import
#   open Nat Function                                      -> import (opened namespace)
#   namespace Geometry ... end Geometry                    -> (namespace scope)
#   structure Point where x : Nat  y : Nat                 -> structure (class + fields)
#   inductive Color | red | green | blue                   -> inductive (class + cons)
#   class Monad (m : Type -> Type) where ...               -> type class (class + members)
#   def area (r : Float) : Float := ...                    -> function
#   theorem foo : P := ...   lemma / abbrev / instance     -> function
import re

from .regex_base import RegexCodeAnalyzer

_DEFKW = (
    "def",
    "theorem",
    "lemma",
    "abbrev",
    "instance",
    "example",
    "noncomputable def",
    "partial def",
)


class LeanAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "lean"
    EXTENSIONS = (".lean",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()  # nested /- -/ handled below
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(r"^import\s+([\w.]+)", re.MULTILINE)
    _OPEN = re.compile(r"^open\s+(.+)$", re.MULTILINE)
    _NAMESPACE = re.compile(r"^namespace\s+([\w.]+)", re.MULTILINE)
    _STRUCT = re.compile(
        r"^(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+)?structure\s+([\w.]+)",
        re.MULTILINE,
    )
    _INDUCT = re.compile(
        r"^(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+)?inductive\s+([\w.]+)",
        re.MULTILINE,
    )
    _CLASS = re.compile(
        r"^(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+)?class\s+([\w.]+)",
        re.MULTILINE,
    )
    _DEF = re.compile(
        r"^(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+|noncomputable\s+|"
        r"partial\s+|unsafe\s+|scoped\s+)*"
        r"(def|theorem|lemma|abbrev|instance)\s+([\w.']+)?\s*",
        re.MULTILINE,
    )

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
            if text[i : i + 2] == "/-":
                depth += 1
                out.append("  ")
                i += 2
                continue
            if text[i : i + 2] == "-/" and depth > 0:
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

    def _leaf(self, dotted):
        return dotted.split(".")[-1]

    def _indent_body(self, text, decl_start):
        nl = text.find("\n", decl_start)
        if nl == -1:
            return ""
        out, end = [], nl + 1
        for line in text[nl + 1 :].splitlines(keepends=True):
            if line.strip() and self._indent_of(line) == 0:
                break
            out.append(line)
        return "".join(out)

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for rx in (self._STRUCT, self._INDUCT, self._CLASS):
            for m in rx.finditer(text):
                self._register_class(self._leaf(m.group(1)))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        for m in self._IMPORT.finditer(text):
            mod = m.group(1)
            self._add_import(file_id, self._leaf(mod), mod)
        for m in self._OPEN.finditer(text):
            for tok in re.findall(r"[\w.]+", m.group(1)):
                if tok not in ("in",):
                    self._add_import(file_id, self._leaf(tok), tok)

        # structure -> fields as attrs
        for m in self._STRUCT.finditer(text):
            name = self._leaf(m.group(1))
            body = self._indent_body(text, m.start())
            attrs = []
            for fm in re.finditer(r"^\s+([\w']+)\s*:\s+", body, re.MULTILINE):
                attrs.append(self._add_arg(fm.group(1)))
            # inline `extends Parent`
            parents = []
            head_end = text.find("\n", m.end())
            head = text[m.end() : head_end if head_end != -1 else len(text)]
            for pm in re.finditer(r"extends\s+([\w.]+)", head):
                pn = self._leaf(pm.group(1))
                if pn in self._class_registry:
                    parents.append(self._class_registry[pn])
            self._add_class(
                file_id,
                name,
                description="lean structure",
                parent_ids=parents,
                attr_ids=attrs,
            )

        # inductive -> constructors as attrs
        for m in self._INDUCT.finditer(text):
            name = self._leaf(m.group(1))
            body = self._indent_body(text, m.start())
            cons = []
            for cm in re.finditer(r"^\s*\|\s*([\w']+)", body, re.MULTILINE):
                cons.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="lean inductive", attr_ids=cons)

        # class -> member fields/methods
        for m in self._CLASS.finditer(text):
            name = self._leaf(m.group(1))
            body = self._indent_body(text, m.start())
            methods = []
            for mm in re.finditer(r"^\s+([\w']+)\s*:\s+", body, re.MULTILINE):
                methods.append(
                    self._add_function(
                        file_id,
                        mm.group(1),
                        [],
                        [],
                        class_id=self._class_registry.get(name),
                        description="lean class member",
                    )
                )
            self._add_class(file_id, name, description="lean class", method_ids=methods)

        # def / theorem / lemma / abbrev / instance
        for m in self._DEF.finditer(text):
            kind, name = m.group(1), m.group(2)
            if not name:
                continue
            name = self._leaf(name)
            # parse binders up to ':' or ':=' for args
            tail = text[
                m.end() : (
                    text.find("\n", m.end())
                    if text.find("\n", m.end()) != -1
                    else len(text)
                )
            ]
            arg_ids = []
            for bm in re.finditer(r"[\(\{\[]\s*([\w'\s]+?)\s*:", tail):
                for v in bm.group(1).split():
                    if re.match(r"^[\w']+$", v):
                        arg_ids.append(self._add_arg(v))
            self._add_function(file_id, name, arg_ids, [], description=f"lean {kind}")
