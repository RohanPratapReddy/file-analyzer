# OCaml with the camlp4/camlp5 preprocessor (.ml4).
#
# `.ml4` is OCaml source carrying camlp4 syntax extensions (the historical
# implementation language of Coq tactics/plugins).  It is plain OCaml plus
# `EXTEND ... END` grammar blocks and `<:expr< ... >>` quotations:
#
#     open Names
#     let rec size = function [] -> 0 | _ :: t -> 1 + size t
#     let pi = 3.14159
#     type 'a tree = Leaf | Node of 'a tree * 'a tree
#     module M = struct ... end
#     exception Bad_arg of string
#     EXTEND Gram GLOBAL: expr; expr: [ [ "x" -> ... ] ]; END
#
#   let [rec] NAME args = e       -> function   (params captured)
#   let NAME = value              -> variable
#   type/module/exception NAME    -> class
#   open X / #load "x" / #use "x" -> import
#   EXTEND [Gram] ... END         -> function (a camlp4 grammar block)
#
# OCaml comments are nestable `(* ... *)`; a dedicated nested stripper is used so
# a comment containing `(*` does not terminate early.
import re

from .regex_base import RegexCodeAnalyzer

_LID = r"[a-z_][A-Za-z0-9_']*"
_UID = r"[A-Za-z_][A-Za-z0-9_']*"


class Ml4Analyzer(RegexCodeAnalyzer):
    LANG_KEY = "ocaml-camlp4"
    EXTENSIONS = (".ml4",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()  # nested (* *) handled by _strip_nested
    STRING_DELIMS = ('"',)

    _OPEN = re.compile(r"(?m)^\s*open\s+(" + _UID + r"(?:\.[A-Za-z0-9_']+)*)")
    _LOAD = re.compile(r'(?m)^\s*#\s*(?:load|use)\s+"([^"]+)"')
    _LETFUN = re.compile(r"(?m)^\s*let\s+(?:rec\s+)?(" + _LID + r")\s+([^=]*?)=")
    _LETVAL = re.compile(r"(?m)^\s*let\s+(?:rec\s+)?(" + _LID + r")\s*(?::[^=]+)?=")
    _TYPE = re.compile(
        r"(?m)^\s*(?:type|module|exception)\s+(?:type\s+|rec\s+)?"
        r"(?:'[a-z]+\s+|\([^)]*\)\s+)*(" + _UID + r")"
    )
    _EXTEND = re.compile(r"(?m)\b(?:G?EXTEND)\s+(?:Gram\b|" + _UID + r")?")

    def _strip_nested(self, text: str) -> str:
        out, i, n, depth = [], 0, len(text), 0
        while i < n:
            two = text[i : i + 2]
            if depth == 0 and text[i] == '"':
                out.append('"')
                i += 1
                while i < n:
                    out.append(text[i])
                    if text[i] == "\\" and i + 1 < n:
                        out.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    if text[i - 1] == '"':
                        break
                continue
            if two == "(*":
                depth += 1
                out.append("  ")
                i += 2
                continue
            if two == "*)" and depth > 0:
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

    def _ocaml_args(self, blob: str):
        arg_ids = []
        for tok in blob.split():
            t = tok.strip("()~?:")
            t = t.split(":")[0]
            if re.fullmatch(_LID, t) and t not in ("rec",):
                arg_ids.append(self._add_arg(t))
        return arg_ids

    def _register_types(self, file_id, text, path):
        clean = self._strip_nested(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_nested(text)

        for m in self._OPEN.finditer(clean):
            mod = m.group(1)
            self._add_import(file_id, mod.split(".")[-1], mod)
        for m in self._LOAD.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split("/")[-1].split(".")[0], src)

        for m in self._TYPE.finditer(clean):
            self._add_class(file_id, m.group(1), description="ocaml type/module")

        seen_fn = set()
        for m in self._LETFUN.finditer(clean):
            nm, args = m.group(1), m.group(2)
            if nm in seen_fn or not args.strip():
                continue
            seen_fn.add(nm)
            self._add_function(
                file_id, nm, self._ocaml_args(args), [], description="ocaml function"
            )
        seen_v = set()
        for m in self._LETVAL.finditer(clean):
            nm = m.group(1)
            if nm in seen_fn or nm in seen_v:
                continue
            seen_v.add(nm)
            self._add_variable(file_id, nm, None, scope="module")

        for i, m in enumerate(self._EXTEND.finditer(clean)):
            self._add_function(
                file_id, f"EXTEND_{i}", [], [], description="camlp4 grammar extension"
            )
