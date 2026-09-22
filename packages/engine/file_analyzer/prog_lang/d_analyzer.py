# D language (.d) / D interface (.di) analyzer.
#
# Real parser for D (systems language, C-family braces, D-specific /+ +/ nested
# comments approximated):
#   module foo.bar;                       -> (module decl)
#   import std.stdio;                      -> import
#   import io = std.stdio;                 -> aliased import
#   import std.conv : to, text;            -> selective import
#   class Foo : Bar, IBaz { }              -> class (+ parents)
#   struct/interface/union/enum/template   -> class row
#   RetType name(T)(args) @safe { }        -> method / function (template params ok)
#   auto name(args) { }                    -> function
#   int x = 5;  immutable y = 2;           -> field / variable
import re

from .regex_base import RegexCodeAnalyzer

_ATTR = (
    r"(?:public|private|protected|package|export|static|final|abstract|"
    r"override|const|immutable|shared|__gshared|nothrow|pure|ref|auto|"
    r"scope|extern|align|deprecated|synchronized|@\w+|@\"[^\"]*\")\s+"
)


class DAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "d"
    EXTENSIONS = (".d", ".di")
    BLOCK_COMMENTS = (("/*", "*/"), ("/+", "+/"))

    _IMPORT = re.compile(r"^\s*(?:public\s+|static\s+)*import\s+([^;]+);", re.MULTILINE)
    _TYPE = re.compile(
        r"(?:" + _ATTR + r")*"
        r"\b(class|struct|interface|union|enum|template)\s+"
        r"([A-Za-z_]\w*)"
        r"(?:\s*\([^)]*\))?"  # template params
        r"(?:\s*:\s*([^{]+?))?"  # base list / enum base
        r"\s*\{"
    )
    _METHOD = re.compile(
        r"(?:" + _ATTR + r")*"
        r"\b([\w.!]+(?:\s*\[\s*\])?[\w.!()]*(?:\s*\*)?)\s+"  # return type
        r"([A-Za-z_]\w*)\s*"
        r"(?:\([^)]*\)\s*)?"  # optional template param list
        r"\(([^{;]*?)\)\s*"  # runtime params
        r"(?:(?:@\w+|const|immutable|nothrow|pure|@safe|@trusted|@nogc|"
        r"return|scope|inout)\s*)*"
        r"\{"
    )
    _FIELD = re.compile(
        r"(?:" + _ATTR + r")*"
        r"\b([\w.]+(?:!\s*[\w.()]+)?(?:\s*\[\s*[^\]]*\])?(?:\s*\*)?)\s+"
        r"([A-Za-z_]\w*)\s*(?:=\s*([^;]+?))?\s*;"
    )

    def _register_types(self, file_id, text, path):
        for m in self._TYPE.finditer(self._strip_comments(text)):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._IMPORT.finditer(text):
            body = m.group(1).strip()
            if ":" in body:
                # selective import: `import std.conv : to, text;` -- the commas
                # belong to the imported symbol list, NOT to multiple modules.
                modpart = body.split(":", 1)[0].strip()
                alias = None
                if "=" in modpart:
                    alias, modpart = (s.strip() for s in modpart.split("=", 1))
                if modpart:
                    self._add_import(file_id, modpart.split(".")[-1], modpart, alias)
            else:
                for piece in body.split(","):
                    piece = piece.strip()
                    if not piece:
                        continue
                    alias = None
                    if "=" in piece:
                        alias, piece = (s.strip() for s in piece.split("=", 1))
                    if piece:
                        self._add_import(file_id, piece.split(".")[-1], piece, alias)

        types = []
        for m in self._TYPE.finditer(text):
            bstart = text.index("{", m.start())
            bend = self._find_matching(text, bstart)
            parents = []
            if m.group(3):
                for base in self._split_top_level(m.group(3)):
                    base = base.split("!")[0].split(".")[-1].strip()
                    if base in self._class_registry:
                        parents.append(self._class_registry[base])
            types.append(
                {
                    "name": m.group(2),
                    "kind": m.group(1),
                    "bstart": bstart,
                    "bend": bend,
                    "parents": parents,
                    "methods": [],
                    "attrs": [],
                }
            )

        def enclosing(pos):
            best = None
            for t in types:
                if t["bstart"] <= pos < t["bend"] and (
                    best is None or t["bstart"] > best["bstart"]
                ):
                    best = t
            return best

        covered = 0
        method_spans = []
        for m in self._METHOD.finditer(text):
            if m.start() < covered:
                continue
            ret, name, params = m.group(1).strip(), m.group(2), m.group(3)
            if name in (
                "if",
                "for",
                "while",
                "switch",
                "foreach",
                "with",
                "catch",
                "return",
                "version",
                "static",
                "unittest",
            ):
                continue
            if ret in ("else", "do", "in", "out", "return"):
                continue
            body = text.index("{", m.end() - 1)
            covered = self._find_matching(text, body)
            method_spans.append((body, covered))
            arg_ids = self._params(params)
            out_ids = [self._add_output(ret)] if ret and ret != "void" else []
            owner = enclosing(m.start())
            cid = self._class_registry.get(owner["name"]) if owner else None
            fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
            if owner is not None:
                owner["methods"].append(fid)

        def in_method(pos):
            return any(a <= pos < b for a, b in method_spans)

        for m in self._FIELD.finditer(text):
            if in_method(m.start()):
                continue
            vtype, name, val = m.group(1).strip(), m.group(2), m.group(3)
            if vtype in ("return", "import", "module", "else", "alias", "enum"):
                continue
            owner = enclosing(m.start())
            if owner is None:
                self._add_variable(file_id, name, val.strip() if val else None)
            else:
                owner["attrs"].append(
                    self._add_arg(name, vtype, val.strip() if val else None)
                )

        for t in types:
            self._add_class(
                file_id,
                t["name"],
                description=f"d {t['kind']}",
                parent_ids=t["parents"],
                method_ids=t["methods"],
                attr_ids=t["attrs"],
            )

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = re.sub(
                r"\b(?:ref|out|in|lazy|scope|return|const|immutable)\b", "", part
            ).strip()
            if not part or part == "...":
                continue
            default = None
            if "=" in part:
                part, default = part.split("=", 1)
                part, default = part.strip(), default.strip()
            toks = part.split()
            if len(toks) >= 2:
                atype, aname = " ".join(toks[:-1]), toks[-1]
            else:
                atype, aname = None, toks[-1] if toks else part
            arg_ids.append(self._add_arg(aname.rstrip("."), atype, default))
        return arg_ids
