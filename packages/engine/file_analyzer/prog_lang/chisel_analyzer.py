# Chisel (.chisel) hardware-construction-language analyzer.
#
# Chisel is a Scala-embedded HDL, so the file grammar is Scala.  Real
# constructs (regex, brace/`=`-delimited bodies; '//' and '/* */' comments):
#
#     package accelerator                              -> (namespace, skipped)
#     import chisel3._                                 -> import
#     import chisel3.util.{Decoupled, Queue}           -> import (each name)
#     class Adder(val width: Int) extends Module {     -> class (+ parent Module)
#       val io = IO(new Bundle { ... })                -> variable
#       def add(a: UInt, b: UInt): UInt = a + b        -> function (+ output)
#     }
#     object Adder extends App { ... }                 -> class (object)
#     trait HasClock { ... }                           -> class (trait)
#     case class Config(depth: Int)                    -> class (+ ctor params)
#     abstract class BaseIO extends Bundle             -> class (+ parent)
#     val DefaultWidth = 32                             -> variable (top-level)
#
# Bundle/Module/App parents are registered so `parent_ids` resolve when the
# parent is declared locally; external parents are simply absent.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_$]*"


class ChiselAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "chisel"
    EXTENSIONS = (".chisel",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _IMPORT = re.compile(
        r"(?m)^\s*import\s+([\w.]+?)(?:\.\{([^}]*)\}|\.(\w+|_))?\s*;?$"
    )
    # class / trait / object / (abstract|case|sealed) class, plus extends chain
    _TYPE = re.compile(
        r"(?m)^\s*(?:(?:abstract|final|sealed|case|implicit|private|protected|package)\s+)*"
        r"(class|trait|object)\s+(" + _ID + r")"
        r"(?:\s*\[[^\]]*\])?"  # type params
        r"(?:\s*\(([^{]*?)\))?"  # ctor params (best effort)
        r"(?:\s+extends\s+([^{]+?))?\s*(?:\{|$)"
    )
    _DEF = re.compile(
        r"(?m)^\s*(?:(?:override|final|private|protected|implicit"
        r"|def)\s+)*def\s+(" + _ID + r")\s*"
        r"(?:\[[^\]]*\])?\s*(\([^{=]*\))?\s*(?::\s*([\w.\[\], ]+))?\s*[={]"
    )
    _VAL = re.compile(
        r"(?m)^\s*(?:(?:override|final|private|protected|implicit|lazy)\s+)*"
        r"(?:val|var)\s+(" + _ID + r")\b"
    )
    # top-level / member type alias:  type Name[T] = ...
    _TYPEALIAS = re.compile(
        r"(?m)^\s*(?:(?:override|final|private|protected)\s+)*"
        r"type\s+(" + _ID + r")\b"
    )

    def _clean_type_kw(self, s):
        return re.sub(r"\b(?:with|extends)\b", ",", s)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            base = m.group(1)
            if m.group(2):  # selector list {A, B => C}
                for sel in self._split_top_level(m.group(2)):
                    nm = sel.split("=>")[-1].strip()
                    if nm and nm != "_":
                        self._add_import(file_id, nm.split(".")[-1], base + "." + nm)
            elif m.group(3) and m.group(3) != "_":
                self._add_import(file_id, m.group(3), base + "." + m.group(3))
            else:
                self._add_import(file_id, base.split(".")[-1], base)

        # class / trait / object bodies -> owner scope for their members
        class_spans = []
        for m in self._TYPE.finditer(clean):
            name = m.group(2)
            parents = []
            if m.group(4):
                for p in self._split_top_level(self._clean_type_kw(m.group(4))):
                    p = p.split("(")[0].split("[")[0].strip()
                    if p:
                        pid = self._register_class(p)
                        if pid is not None:
                            parents.append(pid)
            attr_ids = []
            if m.group(3):  # ctor params -> attributes
                for part in self._split_top_level(m.group(3)):
                    part = re.sub(
                        r"\b(?:val|var|override|private|protected|implicit)\b",
                        " ",
                        part,
                    ).strip()
                    if not part:
                        continue
                    nm = part.split(":")[0].split("=")[0].strip()
                    ty = None
                    if ":" in part:
                        ty = part.split(":", 1)[1].split("=")[0].strip()
                    if re.match(_ID + r"$", nm):
                        attr_ids.append(self._add_arg(nm, ty))
            cls_id = self._add_class(
                file_id,
                name,
                description="chisel " + m.group(1),
                parent_ids=parents or None,
                attr_ids=attr_ids or None,
            )
            # body span: only when the header actually opened a brace body
            if clean[m.end() - 1 : m.end()] == "{":
                brace = m.end() - 1
                end = self._find_matching(clean, brace, "{", "}")
                class_spans.append((brace, end, cls_id))

        def owner_of(pos):
            for a, b, cid in class_spans:
                if a < pos < b:
                    return cid
            return None

        seen_fn = set()
        for m in self._DEF.finditer(clean):
            key = (m.start(), m.group(1))
            if key in seen_fn:
                continue
            seen_fn.add(key)
            arg_ids = self._parse_scala_params(m.group(2))
            outs = [self._add_output(m.group(3).strip())] if m.group(3) else []
            self._add_function(
                file_id,
                m.group(1),
                arg_ids,
                outs,
                class_id=owner_of(m.start()),
                description="chisel def",
            )

        for m in self._VAL.finditer(clean):
            oid = owner_of(m.start())
            self._add_variable(
                file_id, m.group(1), scope="module" if oid is None else "class"
            )
        for m in self._TYPEALIAS.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="type")

    def _parse_scala_params(self, group):
        if not group:
            return []
        inner = group.strip()[1:-1] if group.strip().startswith("(") else group
        arg_ids = []
        for part in self._split_top_level(inner):
            part = re.sub(r"\b(?:val|var|implicit)\b", " ", part).strip()
            if not part:
                continue
            nm = part.split(":")[0].split("=")[0].strip()
            ty = part.split(":", 1)[1].split("=")[0].strip() if ":" in part else None
            if re.match(_ID + r"$", nm):
                arg_ids.append(self._add_arg(nm, ty))
        return arg_ids
