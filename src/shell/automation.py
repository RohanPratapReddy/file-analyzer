# Desktop-automation and debugger scripting languages: AutoIt (.au3),
# AutoHotkey v1/v2 (.ahk/.ahk2) and GDB init scripts (.gdbinit).
import re

from .shell_base import ShellScriptBase


class AutoItAnalyzer(ShellScriptBase):
    """AutoIt scripts (.au3).

    ``Func name(args) ... EndFunc``     -> function
    ``Global $x`` / ``Local $x`` / ``Dim $x`` / ``Const $x = v`` -> variable
    ``#include <file>`` / ``#include "file"``  -> import
    """
    LANG_KEY = "autoit"
    EXTENSIONS = (".au3",)
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = (("#cs", "#ce"), ("#comments-start", "#comments-end"))
    STRING_DELIMS = ('"', "'")

    _FUNC = re.compile(r"(?mi)^[ \t]*func[ \t]+([A-Za-z_]\w*)[ \t]*\(([^)]*)\)")
    _VAR = re.compile(r"(?mi)^[ \t]*(global|local|dim|const)[ \t]+(?:const[ \t]+)?"
                      r"(\$[A-Za-z_]\w*)(?:[ \t]*=[ \t]*(.*))?")
    _INCLUDE = re.compile(r'(?mi)^[ \t]*#include[ \t]+[<"]([^>"]+)[>"]')

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = [p.replace("ByRef", "").strip()
                      for p in self._split_top_level(m.group(2) or "")]
            self._add_shell_function(file_id, name, params=params,
                                     description="autoit func")

        seen_var = set()
        for m in self._VAR.finditer(clean):
            name = m.group(2)
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, (m.group(3) or "").strip()[:120] or None,
                               scope=m.group(1).lower())

        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="#include")

        self._record_module_meta(file_id, functions=len(seen_fn),
                                 variables=len(seen_var))


class AutoHotkeyAnalyzer(ShellScriptBase):
    """AutoHotkey scripts (.ahk v1, .ahk2 v2).

    ``name(params) { ... }``         -> function (v2 / v1 function syntax)
    ``label:`` and ``^!k::`` hotkeys  -> function (a labelled entry point)
    ``#Include file`` / ``#IncludeAgain``  -> import
    ``global x`` / ``x := value`` at top level  -> variable
    """
    LANG_KEY = "autohotkey"
    EXTENSIONS = (".ahk", ".ahk2")
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _FUNC = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*\(([^)]*)\)[ \t]*\{")
    _HOTKEY = re.compile(r"(?m)^[ \t]*([^\s:;][^:;\n]*)::")
    _LABEL = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*):[ \t]*$")
    _INCLUDE = re.compile(r'(?mi)^[ \t]*#include(?:again)?[ \t]+(?:\*i[ \t]+)?[<"]?([^>"\n]+)[>"]?')
    _ASSIGN = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*:=[ \t]*(.+)")
    _GLOBAL = re.compile(r"(?m)^[ \t]*global[ \t]+([A-Za-z_]\w*)")

    # AHK keywords that look like a `name(...)` call but are control flow.
    _KW = {"if", "while", "for", "loop", "return", "switch", "catch", "else"}

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name.lower() in self._KW or name in seen_fn:
                continue
            seen_fn.add(name)
            params = [p.split(":=")[0].strip()
                      for p in self._split_top_level(m.group(2) or "")]
            self._add_shell_function(file_id, name, params=[p for p in params if p],
                                     description="ahk function")
        for m in self._HOTKEY.finditer(clean):
            key = m.group(1).strip()
            if key and key not in seen_fn and "::" not in key:
                seen_fn.add(key)
                self._add_shell_function(file_id, key, description="ahk hotkey")
        for m in self._LABEL.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="ahk label")

        seen_var = set()
        for rx, scope in ((self._GLOBAL, "global"), (self._ASSIGN, "module")):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name in seen_var or name in seen_fn:
                    continue
                seen_var.add(name)
                val = m.group(2).strip()[:120] if rx is self._ASSIGN else None
                self._add_variable(file_id, name, val, scope=scope)

        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1).strip()
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="#Include")

        version = "v2" if path.suffix.lower() == ".ahk2" else "v1"
        self._record_module_meta(file_id, version=version,
                                 callables=len(seen_fn), variables=len(seen_var))


class GdbInitAnalyzer(ShellScriptBase):
    """GDB init / command scripts (.gdbinit).

    ``define name ... end``   -> function (a user-defined command)
    ``set var = value`` / ``set $reg = ...``  -> variable
    ``source file`` / ``python ... end``      -> import / metadata
    """
    LANG_KEY = "gdb"
    EXTENSIONS = (".gdbinit",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _DEFINE = re.compile(r"(?m)^[ \t]*define[ \t]+([A-Za-z_][\w-]*)")
    _SET = re.compile(r"(?m)^[ \t]*set[ \t]+(?:var[ \t]+)?(\$?[A-Za-z_]\w*)[ \t]*=[ \t]*(.*)")
    _SOURCE = re.compile(r"(?m)^[ \t]*source[ \t]+(\S+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._DEFINE.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="gdb command")

        seen_var = set()
        for m in self._SET.finditer(clean):
            name = m.group(1)
            # `set` also configures gdb options (e.g. `set pagination off`) which
            # have no `=`; those never reach here because the regex requires `=`.
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                               scope="convenience" if name.startswith("$") else "gdb")

        seen_imp = set()
        for m in self._SOURCE.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="source")

        has_python = bool(re.search(r"(?m)^[ \t]*python\b", clean))
        self._record_module_meta(file_id, commands=len(seen_fn),
                                 variables=len(seen_var),
                                 embeds_python=has_python or None)
