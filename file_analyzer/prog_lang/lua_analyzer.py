# Lua (.lua) analyzer.
#
# Real parser for Lua (`--` line, `--[[ ]]` block comments):
#   local socket = require("socket")          -> import + variable
#   function Obj.method(a, b) ... end          -> function (method of Obj)
#   function name(a, b) ... end                -> function
#   local function helper(x) ... end           -> function (local)
#   Account = {}                               -> table variable (class-ish)
#   local M = {}                               -> local variable
#   x = 5                                       -> variable
import re

from .regex_base import RegexCodeAnalyzer


class LuaAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "lua"
    EXTENSIONS = (".lua",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = (("--[[", "]]"),)
    STRING_DELIMS = ('"', "'")

    _REQUIRE = re.compile(r'\brequire\s*\(?\s*["\']([^"\']+)["\']')
    _FUNC = re.compile(
        r"^\s*(local\s+)?function\s+([\w.:]+)\s*\(([^)]*)\)", re.MULTILINE
    )
    _ASSIGN_FUNC = re.compile(
        r"^\s*(local\s+)?([\w.]+)\s*=\s*function\s*\(([^)]*)\)", re.MULTILINE
    )
    _TABLE = re.compile(r"^\s*(local\s+)?([A-Za-z_]\w*)\s*=\s*\{", re.MULTILINE)
    _VAR = re.compile(
        r"^\s*(local\s+)?([A-Za-z_][\w]*)\s*=\s*(?!function\b|\{)([^\n]+)", re.MULTILINE
    )

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._TABLE.finditer(t):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        seen_imp = set()
        for m in self._REQUIRE.finditer(t):
            mod = m.group(1)
            if mod not in seen_imp:
                seen_imp.add(mod)
                self._add_import(file_id, mod.split(".")[-1], mod)

        table_names = {m.group(2) for m in self._TABLE.finditer(t)}
        for name in table_names:
            self._add_class(file_id, name, description="lua table")

        emitted_fn = set()
        for m in self._FUNC.finditer(t):
            local, name, params = m.group(1), m.group(2), m.group(3)
            owner = re.split(r"[.:]", name)
            fname = owner[-1]
            cls_id = None
            if len(owner) > 1:
                cls_id = self._class_registry.get(owner[0])
            arg_ids = self._args(params)
            self._add_function(
                file_id,
                fname,
                arg_ids,
                class_id=cls_id,
                description="lua function" if not local else "lua local function",
            )
            emitted_fn.add(name)
        for m in self._ASSIGN_FUNC.finditer(t):
            name, params = m.group(2), m.group(3)
            if name in emitted_fn:
                continue
            self._add_function(
                file_id,
                name.split(".")[-1],
                self._args(params),
                description="lua function value",
            )

        for m in self._VAR.finditer(t):
            name = m.group(2)
            if name in table_names:
                continue
            val = m.group(3).strip().rstrip(";")
            scope = "local" if m.group(1) else "module"
            self._add_variable(file_id, name, val[:120], scope=scope)

    def _args(self, params):
        ids = []
        for p in params.split(","):
            p = p.strip()
            if p:
                ids.append(self._add_arg(p))
        return ids
