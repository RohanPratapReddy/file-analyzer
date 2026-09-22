# Script dialects of general-purpose languages: C# script (.csx), Elixir Mix
# project files (.mix) and NimScript (.nims).  Each is parsed with the real
# grammar of its parent language (restricted to the script surface).
import re

from .shell_base import ShellScriptBase


class CsxAnalyzer(ShellScriptBase):
    """C# scripts (.csx).

    ``using X;`` / ``#r "assembly"`` / ``#load "file.csx"``  -> import
    ``class Name`` / ``struct Name`` / ``record Name``       -> class
    ``[modifiers] RetType Name(args) { ... }``               -> function
    ``var x = ...`` / ``const T x = ...`` (top level)        -> variable
    """

    LANG_KEY = "csharp-script"
    EXTENSIONS = (".csx",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _USING = re.compile(r"(?m)^[ \t]*using[ \t]+(?:static[ \t]+)?([\w.]+)[ \t]*;")
    _REF = re.compile(r'(?m)^[ \t]*#r[ \t]+"([^"]+)"')
    _LOAD = re.compile(r'(?m)^[ \t]*#load[ \t]+"([^"]+)"')
    _CLASS = re.compile(
        r"(?m)\b(class|struct|record|interface|enum)[ \t]+([A-Za-z_]\w*)"
    )
    _METHOD = re.compile(
        r"(?m)^[ \t]*(?:public|private|protected|internal|static|async|"
        r"override|virtual|sealed|[ \t])*[\w<>\[\],.]+[ \t]+"
        r"([A-Za-z_]\w*)[ \t]*\(([^)]*)\)[ \t]*\{"
    )
    _VAR = re.compile(
        r"(?m)^[ \t]*(?:var|const[ \t]+[\w<>\[\]]+)[ \t]+([A-Za-z_]\w*)[ \t]*="
    )
    _KW = {
        "if",
        "for",
        "foreach",
        "while",
        "switch",
        "catch",
        "using",
        "return",
        "lock",
    }

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_imp = set()
        for m in self._USING.finditer(clean):
            ns = m.group(1)
            if ns not in seen_imp:
                seen_imp.add(ns)
                self._add_import(file_id, ns.split(".")[-1], ns, alias="using")
        for m in self._REF.finditer(clean):
            asm = m.group(1)
            if asm not in seen_imp:
                seen_imp.add(asm)
                self._add_import(file_id, asm, "assembly", alias="#r")
        for m in self._LOAD.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="#load")

        seen_cls = set()
        for m in self._CLASS.finditer(clean):
            name = m.group(2)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="csharp " + m.group(1))

        seen_fn = set()
        for m in self._METHOD.finditer(clean):
            name = m.group(1)
            if name in self._KW or name in seen_fn or name in seen_cls:
                continue
            seen_fn.add(name)
            params = [
                p.strip().split()[-1].lstrip("*&")
                for p in self._split_top_level(m.group(2) or "")
                if p.strip()
            ]
            self._add_shell_function(
                file_id, name, params=params, description="csharp method"
            )

        seen_var = set()
        for m in self._VAR.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, None, scope="local")

        self._record_module_meta(
            file_id, classes=len(seen_cls), methods=len(seen_fn), usings=len(seen_imp)
        )


class ElixirMixAnalyzer(ShellScriptBase):
    """Elixir Mix project files (.mix) -- Elixir.

    ``defmodule Name do``           -> class (a module)
    ``def name(args)`` / ``defp``   -> function
    ``use X`` / ``import X`` / ``alias X`` / ``require X``  -> import
    ``@attr value`` module attributes                      -> variable
    """

    LANG_KEY = "elixir-mix"
    EXTENSIONS = (".mix",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _MODULE = re.compile(r"(?m)^[ \t]*defmodule[ \t]+([\w.]+)[ \t]+do\b")
    _DEF = re.compile(
        r"(?m)^[ \t]*(defp?|defmacrop?)[ \t]+([a-z_]\w*[!?]?)" r"[ \t]*(?:\(([^)]*)\))?"
    )
    _USE = re.compile(r"(?m)^[ \t]*(use|import|alias|require)[ \t]+([\w.]+)")
    _ATTR = re.compile(r"(?m)^[ \t]*@([a-z_]\w*)[ \t]+(.+)")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = set()
        for m in self._MODULE.finditer(clean):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="elixir module")

        seen_fn = set()
        for m in self._DEF.finditer(clean):
            kind, name, args = m.group(1), m.group(2), m.group(3)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = [
                p.split("\\\\")[0].strip() for p in self._split_top_level(args or "")
            ]
            self._add_shell_function(
                file_id,
                name,
                params=[p for p in params if p],
                description="elixir " + kind,
            )

        seen_imp = set()
        for m in self._USE.finditer(clean):
            kw, mod = m.group(1), m.group(2)
            if mod not in seen_imp:
                seen_imp.add(mod)
                self._add_import(file_id, mod.split(".")[-1], mod, alias=kw)

        seen_var = set()
        for m in self._ATTR.finditer(clean):
            name = m.group(1)
            if name in ("moduledoc", "doc") or name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(
                file_id, name, m.group(2).strip()[:120] or None, scope="attribute"
            )

        self._record_module_meta(
            file_id,
            modules=len(seen_cls),
            functions=len(seen_fn),
            imports=len(seen_imp),
        )


class NimScriptAnalyzer(ShellScriptBase):
    """NimScript files (.nims) -- Nim.

    ``proc name(args)`` / ``func`` / ``template`` / ``macro``  -> function
    ``type Name = object/ref/enum``                            -> class
    ``var x`` / ``let x`` / ``const x``                        -> variable
    ``import x`` / ``include y`` / ``from x import y``         -> import
    """

    LANG_KEY = "nimscript"
    EXTENSIONS = (".nims",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("#[", "]#"),)
    STRING_DELIMS = ('"',)

    _PROC = re.compile(
        r"(?m)^[ \t]*(proc|func|template|macro|method|iterator)[ \t]+"
        r"([A-Za-z_]\w*)\*?[ \t]*(?:\(([^)]*)\))?"
    )
    # Both the inline ``type Name = object`` and the indented block member
    # ``  Name = object`` forms (the ``type`` keyword is optional).
    _TYPE = re.compile(
        r"(?m)^[ \t]*(?:type[ \t]+)?([A-Za-z_]\w*)\*?[ \t]*=[ \t]*"
        r"(?:object|ref[ \t]+object|enum|tuple|distinct)"
    )
    _VAR = re.compile(r"(?m)^[ \t]*(var|let|const)[ \t]+([A-Za-z_]\w*)")
    # Keep the module list on a single line -- `\s` would span newlines and
    # swallow following statements (`from`, `type`, ...) into the import list.
    _IMPORT = re.compile(r"(?m)^[ \t]*(import|include)[ \t]+([\w/,. \t]+)")
    _FROM = re.compile(r"(?m)^[ \t]*from[ \t]+([\w/]+)[ \t]+import\b")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = set()
        for m in self._TYPE.finditer(clean):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="nim type")

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            kind, name, args = m.group(1), m.group(2), m.group(3)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = [
                p.split(":")[0].strip() for p in self._split_top_level(args or "")
            ]
            self._add_shell_function(
                file_id,
                name,
                params=[p for p in params if p],
                description="nim " + kind,
            )

        seen_var = set()
        for m in self._VAR.finditer(clean):
            name = m.group(2)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, None, scope=m.group(1))

        seen_imp = set()
        for m in self._IMPORT.finditer(clean):
            for mod in re.split(r"[,\s]+", m.group(2).strip()):
                mod = mod.strip()
                if mod and mod not in seen_imp:
                    seen_imp.add(mod)
                    self._add_import(file_id, mod.split("/")[-1], mod, alias=m.group(1))
        for m in self._FROM.finditer(clean):
            mod = m.group(1)
            if mod not in seen_imp:
                seen_imp.add(mod)
                self._add_import(file_id, mod.split("/")[-1], mod, alias="from")

        self._record_module_meta(
            file_id, types=len(seen_cls), routines=len(seen_fn), imports=len(seen_imp)
        )
