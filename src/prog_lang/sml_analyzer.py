# Standard ML (.sml / .sig / .fun) analyzer.
#
# Real parser for Standard ML (nested '(* *)' comments, no line comments;
# strings "..."):
#   structure Stack :> STACK = struct ... end            -> structure (class)
#   signature STACK = sig val push : ... end              -> signature (class)
#   functor Make (X : ORD) = struct ... end               -> functor (class)
#   open List; open IntMap                                 -> import
#   fun push x s = x :: s                                  -> function (method)
#   val empty = []                                         -> variable / attr
#   val add = fn (a, b) => a + b                           -> function (lambda)
#   datatype color = Red | Green | Blue                    -> datatype (class + cons)
#   type 'a stack = 'a list                                -> (type alias, skipped)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_']*"


class SMLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "sml"
    EXTENSIONS = (".sml", ".sig", ".fun")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()          # handled by a nesting-aware stripper below
    STRING_DELIMS = ('"',)

    _MODULE = re.compile(
        r"\b(structure|signature|functor)\s+(" + _ID + r")", re.IGNORECASE)
    _OPEN = re.compile(r"\bopen\s+((?:" + _ID + r"(?:\." + _ID + r")*\s*)+)")
    _FUN = re.compile(r"\bfun\s+(" + _ID + r")\s*(.*?)=", re.DOTALL)
    _VAL = re.compile(r"\bval\s+(?:rec\s+)?(" + _ID + r")\s*(?::[^=]+)?=\s*(.*?)$",
                      re.MULTILINE)
    _VALSPEC = re.compile(r"\bval\s+(" + _ID + r")\s*:")     # signature spec
    _DATATYPE = re.compile(
        r"\bdatatype\s+(?:'[\w']+\s+|\([^)]*\)\s+)?(" + _ID + r")\s*=\s*([^;]+?)"
        r"(?=\b(?:datatype|type|fun|val|structure|signature|end|and)\b|$)",
        re.DOTALL)

    def _strip_ml_comments(self, text):
        """Remove nested (* *) comments, preserving newlines and strings."""
        out = []
        i, n, depth = 0, len(text), 0
        while i < n:
            two = text[i:i + 2]
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

    def _register_types(self, file_id, text, path):
        text = self._strip_ml_comments(text)
        for m in self._MODULE.finditer(text):
            self._register_class(m.group(2))
        for m in self._DATATYPE.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_ml_comments(text)

        # module containers, ordered by position for nearest-owner assignment
        modules = []
        for m in self._MODULE.finditer(text):
            modules.append({"pos": m.start(), "name": m.group(2),
                            "kind": m.group(1).lower(), "methods": [], "attrs": []})

        def owner_at(pos):
            best = None
            for mod in modules:
                if mod["pos"] <= pos and (best is None or mod["pos"] > best["pos"]):
                    best = mod
            return best

        # imports
        for m in self._OPEN.finditer(text):
            for mod in m.group(1).split():
                mod = mod.strip()
                if mod:
                    self._add_import(file_id, mod.split(".")[-1], mod)

        # datatypes -> class with constructor attrs
        for m in self._DATATYPE.finditer(text):
            name = m.group(1)
            cons = []
            for con in m.group(2).split("|"):
                cm = re.match(r"\s*(" + _ID + r")", con)
                if cm:
                    cons.append(self._add_arg(cm.group(1), "constructor"))
            self._add_class(file_id, name, description="sml datatype", attr_ids=cons)

        # functions (fun)
        for m in self._FUN.finditer(text):
            name = m.group(1)
            params = self._fun_params(m.group(2))
            arg_ids = [self._add_arg(p) for p in params]
            owner = owner_at(m.start())
            cid = self._class_registry.get(owner["name"]) if owner else None
            fid = self._add_function(file_id, name, arg_ids, [], class_id=cid)
            if owner is not None:
                owner["methods"].append(fid)

        # val bindings: fn-valued -> function, else variable/attr
        for m in self._VAL.finditer(text):
            name, rhs = m.group(1), m.group(2).strip()
            owner = owner_at(m.start())
            fnm = re.match(r"fn\b(.*?)=>", rhs)
            if fnm:
                params = self._fun_params(fnm.group(1))
                arg_ids = [self._add_arg(p) for p in params]
                cid = self._class_registry.get(owner["name"]) if owner else None
                fid = self._add_function(file_id, name, arg_ids, [], class_id=cid)
                if owner is not None:
                    owner["methods"].append(fid)
            else:
                if owner is not None:
                    owner["attrs"].append(self._add_arg(name, None,
                                          rhs.rstrip(";").strip() or None))
                else:
                    self._add_variable(file_id, name, rhs.rstrip(";").strip() or None)

        # signature specs: `val name : type` (no '=') in .sig / sig...end
        for m in self._VALSPEC.finditer(text):
            # skip if this is actually a val binding (has '=' after the type)
            tail = text[m.end():m.end() + 200]
            # a spec has no top-level '=' before the next 'val'/'end'
            owner = owner_at(m.start())
            if owner and owner["kind"] == "signature":
                name = m.group(1)
                cid = self._class_registry.get(owner["name"])
                fid = self._add_function(file_id, name, [], [], class_id=cid,
                                         description="sml spec")
                owner["methods"].append(fid)

        for mod in modules:
            self._add_class(file_id, mod["name"], description=f"sml {mod['kind']}",
                            method_ids=mod["methods"], attr_ids=mod["attrs"])

    def _fun_params(self, raw):
        raw = raw.strip()
        params = []
        # strip a leading operator-form / clausal patterns; take identifiers at
        # the top bracket level, dropping tuple/paren punctuation
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_']*", raw):
            if tok in ("as", "of", "op"):
                continue
            params.append(tok)
        # de-duplicate while preserving order (clausal fns repeat the name pattern)
        seen, out = set(), []
        for p in params:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out
