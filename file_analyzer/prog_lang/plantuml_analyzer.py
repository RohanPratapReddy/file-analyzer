# PlantUML (.plantuml) analyzer.
#
# PlantUML text describes UML diagrams.  We map the type/entity declarations and
# their members onto the relational model:
#
#     @startuml / @enduml                       -> (markers, ignored)
#     !include common.iuml                       -> import
#     class Foo extends Bar { +int x; +run() }  -> class Foo (parent Bar, members)
#     interface I / abstract class A / enum E   -> class
#     participant Alice as A / actor Bob         -> class
#     package P { } / namespace N { }            -> class
#     !function $f(x) ... !endfunction           -> function
#     !procedure $p(x) ... !endprocedure         -> function
#     !define NAME val / !$v = 3                  -> variable
#     Foo --|> Bar                               -> parent link
#
# Comments are "'" (line) and "/' '/" (block); strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_QID = r'(?:"[^"]+"|[A-Za-z_][\w.]*)'


class PlantUMLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "plantuml"
    EXTENSIONS = (".plantuml",)
    LINE_COMMENTS = ("'",)
    BLOCK_COMMENTS = (("/'", "'/"),)
    STRING_DELIMS = ('"',)

    _TYPE = re.compile(
        r"(?im)^\s*(?:abstract\s+)?(class|interface|enum|abstract|entity|"
        r"struct|annotation|protocol|circle|diamond)\s+(" + _QID + r")"
        r"(?:\s+as\s+" + _ID + r")?(.*?)(\{)?\s*$"
    )
    _ACTOR = re.compile(
        r"(?im)^\s*(participant|actor|boundary|control|collections|queue|"
        r"database|usecase|component|node|artifact|folder|rectangle|object)\s+"
        r"(" + _QID + r")(?:\s+as\s+(" + _ID + r"))?"
    )
    _PACKAGE = re.compile(
        r"(?im)^\s*(?:package|namespace|frame|together)\s+(" + _QID + r")"
    )
    _INCLUDE = re.compile(r"(?im)^\s*!include(?:url|sub)?\s+(.+)$")
    _FUNC = re.compile(
        r"(?im)^\s*!(?:unquoted\s+)?(?:function|procedure)\s+\$?(" + _ID + r")\s*\("
    )
    _DEFINE = re.compile(r"(?im)^\s*!define\s+(" + _ID + r")\b")
    _VAR = re.compile(r"(?im)^\s*!\$(" + _ID + r")\s*=")
    _EXTENDS = re.compile(
        r"(?im)^\s*(" + _QID + r")\s+(?:extends|--\|>|<\|--)\s+(" + _QID + r")"
    )
    _MEMBER = re.compile(r"^\s*[+\-#~]?\s*(?:\{[a-z]+\}\s*)?([A-Za-z_]\w*)\s*(\()?")

    @staticmethod
    def _unq(s):
        return s.strip().strip('"')

    @staticmethod
    def _actor_name(name, alias):
        # `participant Bob as B` -> the entity is Bob (B is the short alias);
        # but `participant "Long Text" as Short` -> use the Short identifier.
        if name.strip().startswith('"') and alias:
            return alias
        return PlantUMLAnalyzer._unq(name)

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._TYPE.finditer(clean):
            self._register_class(self._unq(m.group(2)))
        for m in self._ACTOR.finditer(clean):
            self._register_class(self._actor_name(m.group(2), m.group(3)))
        for m in self._PACKAGE.finditer(clean):
            self._register_class(self._unq(m.group(1)))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1).strip().strip('"')
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        for m in self._FUNC.finditer(clean):
            self._add_function(
                file_id, m.group(1), [], [], description="plantuml function"
            )
        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="define")
        for m in self._VAR.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="module")

        for m in self._PACKAGE.finditer(clean):
            self._add_class(
                file_id, self._unq(m.group(1)), description="plantuml package"
            )
        for m in self._ACTOR.finditer(clean):
            self._add_class(
                file_id,
                self._actor_name(m.group(2), m.group(3)),
                description="plantuml " + m.group(1).lower(),
            )

        for m in self._TYPE.finditer(clean):
            name = self._unq(m.group(2))
            methods, attrs = [], []
            if m.group(4):  # brace body present
                body, _ = self._brace_body(clean, m.end() - 1)
                for line in body.split("\n"):
                    if not line.strip() or line.strip().startswith(
                        ("..", "--", "==", "__")
                    ):
                        continue
                    mm = self._MEMBER.match(line)
                    if not mm:
                        continue
                    if mm.group(2):
                        methods.append(
                            self._add_function(
                                file_id,
                                mm.group(1),
                                [],
                                [],
                                description="plantuml method",
                            )
                        )
                    else:
                        attrs.append(self._add_arg(mm.group(1)))
            self._add_class(
                file_id,
                name,
                description="plantuml class",
                method_ids=methods or None,
                attr_ids=attrs or None,
            )

        for m in self._EXTENDS.finditer(clean):
            a, b = self._unq(m.group(1)), self._unq(m.group(2))
            # `A extends B` and `A --|> B`: A derives from B.
            pid = self._add_class(file_id, b, description="plantuml class")
            self._add_class(file_id, a, description="plantuml class", parent_ids=[pid])

    def _brace_body(self, clean, brace_pos):
        end = self._find_matching(clean, brace_pos)
        return clean[brace_pos + 1 : end - 1], end
