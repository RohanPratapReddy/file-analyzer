# Swift textual module interfaces (.swiftinterface).
#
# A `.swiftinterface` is the compiler-emitted, source-stable public face of a
# Swift module.  It opens with `// swift-interface-format-version:` /
# `// swift-module-flags:` header comments, then holds *declaration-only* Swift:
# every `func`/`var`/`let`/`subscript`/`init` is written WITHOUT a body, e.g.
#
#     public func fetch(path: Swift.String) -> Swift.Int
#     public var baseURL: Swift.String { get set }
#     public class NetworkClient { ... }
#     public struct Config { public let timeout: Swift.Double }
#     public protocol Cacheable { func cacheKey() -> Swift.String }
#     @_hasMissingDesignatedInitializers public init(url: Swift.String)
#
# The tree-sitter Swift grammar expects statement bodies and degrades bodyless
# declarations to ERROR nodes, so the honest, robust analyzer for this format is
# a dedicated regex reader keyed to the Swift *declaration* grammar (which also
# matches ordinary `.swift` source, since `func NAME(...)` appears there too).
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_QNAME = r"[A-Za-z_][A-Za-z0-9_.]*"
# access / declaration modifiers that may precede a decl keyword
_MODS = (
    r"(?:(?:public|private|internal|fileprivate|open|final|static|class|"
    r"mutating|nonmutating|override|required|convenience|dynamic|lazy|weak|"
    r"unowned|indirect|optional|prefix|postfix|infix|distributed|"
    r"nonisolated|isolated|@\w+(?:\([^)]*\))?)\s+)*"
)
# a parenthesised parameter list allowing one level of nested parens (closures)
_PARENS = r"\(((?:[^()]|\([^()]*\))*)\)"


class SwiftInterfaceAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "swift-interface"
    EXTENSIONS = (".swiftinterface",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _IMPORT = re.compile(
        r"(?m)^\s*(?:@\w+\s+)?import\s+(?:typealias\s+|struct\s+|"
        r"class\s+|enum\s+|protocol\s+|func\s+|let\s+|var\s+)?"
        r"(" + _QNAME + r")"
    )
    _TYPE = re.compile(
        r"(?m)^\s*" + _MODS + r"(class|struct|enum|protocol|actor|extension)\s+"
        r"(" + _ID + r")(?:<[^>]*>)?"
        r"\s*(?::\s*([^{\n]+?))?\s*(?:where\b[^{\n]*)?(?:\{|$)"
    )
    _FUNC = re.compile(
        r"(?m)^\s*" + _MODS + r"func\s+"
        r"(" + _ID + r"|`[^`]+`|[-+*/%<>=!&|^~]+)"
        r"\s*(?:<[^>]*>)?\s*" + _PARENS + r"\s*(?:async\s+)?(?:(?:re)?throws\s+)?"
        r"(?:->\s*([^{\n]+?))?\s*(?:where\b[^{\n]*)?(?:\{|$)"
    )
    _INIT = re.compile(r"(?m)^\s*" + _MODS + r"init[?!]?\s*(?:<[^>]*>)?\s*" + _PARENS)
    _VAR = re.compile(
        r"(?m)^\s*" + _MODS + r"(var|let)\s+(" + _ID + r")\s*:\s*([^={\n]+)"
    )
    _SUBSCRIPT = re.compile(
        r"(?m)^\s*"
        + _MODS
        + r"subscript\s*(?:<[^>]*>)?\s*"
        + _PARENS
        + r"\s*->\s*([^{\n]+)"
    )
    _CASE = re.compile(r"(?m)^\s*(?:indirect\s+)?case\s+(" + _ID + r")")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._IMPORT.finditer(clean):
            mod = m.group(1)
            self._add_import(file_id, mod.split(".")[-1], mod)

        for m in self._TYPE.finditer(clean):
            kind, name, heritage = m.group(1), m.group(2), m.group(3)
            parents = []
            if heritage:
                for h in self._split_top_level(heritage):
                    h = h.strip().split("<")[0].strip()
                    # drop layout/availability constraints, keep type names
                    if re.fullmatch(_QNAME, h) and h not in (
                        "class",
                        "AnyObject",
                        "Sendable",
                        "where",
                    ):
                        pid = self._register_class(h.split(".")[-1])
                        if pid is not None:
                            parents.append(pid)
            self._add_class(
                file_id, name, description="swift " + kind, parent_ids=parents
            )

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            raw = m.group(1).strip("`")
            if raw in seen_fn:
                continue
            seen_fn.add(raw)
            outs = []
            if m.group(3):
                outs = [self._add_output(m.group(3).strip())]
            self._add_function(
                file_id,
                raw,
                self._swift_args(m.group(2)),
                outs,
                description="swift func",
            )
        for m in self._INIT.finditer(clean):
            self._add_function(
                file_id,
                "init",
                self._swift_args(m.group(1)),
                [],
                description="swift initializer",
            )
        for m in self._SUBSCRIPT.finditer(clean):
            outs = [self._add_output(m.group(2).strip())] if m.group(2) else []
            self._add_function(
                file_id,
                "subscript",
                self._swift_args(m.group(1)),
                outs,
                description="swift subscript",
            )

        seen_var = set()
        for m in self._VAR.finditer(clean):
            name = m.group(2)
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(
                file_id, name, (m.group(3) or "").strip()[:80], scope="module"
            )
        for m in self._CASE.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, "enum case", scope="type")

    def _swift_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip()
            if not part:
                continue
            # `externalLabel internalName: Type = default`  ->  internalName
            head = part.split(":")[0].strip()
            head = head.split("=")[0].strip()
            toks = re.findall(_ID, head)
            if not toks:
                continue
            name = toks[-1] if len(toks) >= 2 else toks[0]
            atype = None
            if ":" in part:
                atype = part.split(":", 1)[1].split("=")[0].strip().lstrip(".")
            arg_ids.append(self._add_arg(name, atype))
        return arg_ids
