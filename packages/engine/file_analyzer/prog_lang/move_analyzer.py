# Move (.move) analyzer.
#
# Real parser for Move (a Rust-like smart-contract language used by Sui/Aptos;
# '//' line, '/* */' block comments; strings "...", hex/byte b"..." x"..."):
#   module 0x1::coin {                              -> (module marker)
#   module my_addr::pool;                            -> (module marker, 2024 form)
#   use std::vector;                                 -> import
#   use sui::object::{Self, UID};                    -> import (grouped)
#   use std::string as str;                          -> import (aliased)
#   const MAX_SUPPLY: u64 = 1000000;                 -> variable
#   struct Coin has key, store { id: UID, value: u64 } -> class (+ fields)
#   struct Balance<phantom T> has store { value: u64 } -> class (generic)
#   public fun mint(value: u64): Coin { ... }        -> function
#   public entry fun transfer(c: Coin, to: address) { ... } -> function
#   public(friend) fun internal(): u64 { ... }        -> function
#   fun helper<T>(x: T): T { ... }                    -> function
import re

from .regex_base import RegexCodeAnalyzer


class MoveAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "move"
    EXTENSIONS = (".move",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _USE = re.compile(
        r"\buse\s+([\w:]+)(?:::\{([^}]*)\})?(?:\s+as\s+(\w+))?\s*;", re.MULTILINE
    )
    _CONST = re.compile(r"\bconst\s+([A-Za-z_]\w*)\s*:\s*([^=;]+)=", re.MULTILINE)
    _STRUCT = re.compile(
        r"\bstruct\s+([A-Za-z_]\w*)(?:<([^>]*)>)?[^{;]*?[{;]", re.MULTILINE
    )
    _FUN = re.compile(
        r"\b(?:public\s*(?:\(\s*(?:friend|package)\s*\)\s*)?|entry\s+|native\s+|"
        r"public\s+entry\s+|inline\s+)*fun\s+([A-Za-z_]\w*)"
        r"(?:<[^>]*>)?\s*\(",
        re.MULTILINE,
    )

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._STRUCT.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        for m in self._USE.finditer(text):
            base, group, alias = m.group(1), m.group(2), m.group(3)
            if group:
                for item in self._split_top_level(group):
                    it = item.strip()
                    am = re.match(r"(\w+)\s+as\s+(\w+)", it)
                    if am:
                        self._add_import(
                            file_id, am.group(2), f"{base}::{am.group(1)}", am.group(2)
                        )
                    elif it == "Self":
                        self._add_import(file_id, base.split("::")[-1], base)
                    elif it:
                        self._add_import(file_id, it, f"{base}::{it}")
            else:
                leaf = alias or base.split("::")[-1]
                self._add_import(file_id, leaf, base, alias)

        for m in self._CONST.finditer(text):
            self._add_variable(file_id, m.group(1), None, scope="module")

        for m in self._STRUCT.finditer(text):
            name = m.group(1)
            attrs = []
            brace = text.find("{", m.start())
            semi = text.find(";", m.start())
            # native structs end in ';' with no body
            if brace != -1 and (semi == -1 or brace < semi):
                rb = self._find_matching(text, brace, "{", "}")
                body = text[brace + 1 : rb - 1]
                for fld in self._split_top_level(body):
                    fm = re.match(r"([A-Za-z_]\w*)\s*:\s*(.+)", fld.strip(), re.DOTALL)
                    if fm:
                        attrs.append(
                            self._add_arg(fm.group(1), fm.group(2).strip()[:80])
                        )
            self._add_class(file_id, name, description="move struct", attr_ids=attrs)

        for m in self._FUN.finditer(text):
            name = m.group(1)
            lp = text.find("(", m.start())
            rp = self._find_matching(text, lp, "(", ")")
            params = text[lp + 1 : rp - 1]
            arg_ids = []
            for part in self._split_top_level(params):
                pm = re.match(
                    r"(?:mut\s+)?([A-Za-z_]\w*)\s*:\s*(.+)", part.strip(), re.DOTALL
                )
                if pm:
                    arg_ids.append(self._add_arg(pm.group(1), pm.group(2).strip()[:80]))
            # return type after ')' up to '{' or 'acquires' or ';'
            tail = text[
                rp : text.find("{", rp) if text.find("{", rp) != -1 else rp + 200
            ]
            out_ids = []
            rm = re.match(r"\s*:\s*([^{};]+?)(?:\s+acquires\b|\s*$)", tail)
            if rm and rm.group(1).strip():
                out_ids = [self._add_output(rm.group(1).strip()[:80])]
            self._add_function(file_id, name, arg_ids, out_ids)
