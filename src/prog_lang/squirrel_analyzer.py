# Squirrel (.nut) analyzer.
#
# Real parser for Squirrel (a C-like scripting language; '//' and '#' line, '/* */'
# block comments; strings "..." and verbatim @"..."):
#   class Foo extends Bar {                          -> class (+ parent)
#       x = 0                                          -> attr
#       constructor(a) { this.x = a }                  -> method
#       function speak() { ... }                       -> method
#   }
#   function globalFn(a, b) { return a + b }         -> function
#   local x = 10                                      -> variable
#   myTable <- { ... }                                -> variable (new slot)
#   const MAX = 100                                   -> variable
#   enum Color { Red, Green, Blue }                  -> class (enum + members)
import re

from .regex_base import RegexCodeAnalyzer


class SquirrelAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "squirrel"
    EXTENSIONS = (".nut",)
    LINE_COMMENTS = ("//", "#")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _CLASS = re.compile(
        r"\bclass\s+([A-Za-z_][\w.]*)" r"(?:\s+extends\s+([A-Za-z_][\w.]*))?\s*\{",
        re.MULTILINE,
    )
    _ENUM = re.compile(r"\benum\s+([A-Za-z_]\w*)\s*\{", re.MULTILINE)
    _FUNC = re.compile(r"\bfunction\s+([A-Za-z_][\w:.]*)\s*\(([^)]*)\)", re.MULTILINE)
    _LOCAL = re.compile(r"\blocal\s+([A-Za-z_]\w*)\s*(?:=|;|,)", re.MULTILINE)
    _CONST = re.compile(r"\bconst\s+([A-Za-z_]\w*)", re.MULTILINE)
    _SLOT = re.compile(r"^\s*([A-Za-z_]\w*)\s*<-", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._CLASS.finditer(text):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        # classes: members = attrs, function/constructor = methods
        class_ranges = []
        for m in self._CLASS.finditer(text):
            name, parent = m.group(1), m.group(2)
            lb = text.find("{", m.start())
            rb = self._find_matching(text, lb, "{", "}")
            class_ranges.append((lb, rb))
            body = text[lb + 1 : rb - 1]
            parents = []
            if parent and parent in self._class_registry:
                parents.append(self._class_registry[parent])
            methods, attrs = [], []
            for fm in re.finditer(
                r"\b(?:function\s+([A-Za-z_]\w*)|(constructor))\s*\(([^)]*)\)", body
            ):
                mname = fm.group(1) or "constructor"
                arg_ids = [
                    self._add_arg(p.strip().split("=")[0].strip())
                    for p in fm.group(3).split(",")
                    if p.strip()
                ]
                methods.append(
                    self._add_function(
                        file_id,
                        mname,
                        arg_ids,
                        [],
                        class_id=self._class_registry.get(name),
                        description="squirrel method",
                    )
                )
            # attribute slots: `name = value` at the top level of the body
            depth = 0
            for line in body.splitlines():
                stripped = line.strip()
                am = re.match(r"^([A-Za-z_]\w*)\s*=", stripped)
                if (
                    depth == 0
                    and am
                    and not stripped.startswith("function")
                    and "==" not in stripped[: len(am.group(1)) + 3]
                ):
                    attrs.append(self._add_arg(am.group(1)))
                depth += line.count("{") + line.count("(")
                depth -= line.count("}") + line.count(")")
                depth = max(depth, 0)
            self._add_class(
                file_id,
                name,
                description="squirrel class",
                parent_ids=parents,
                method_ids=methods,
                attr_ids=attrs,
            )

        # enums -> class with members as attrs
        for m in self._ENUM.finditer(text):
            name = m.group(1)
            lb = text.find("{", m.start())
            rb = self._find_matching(text, lb, "{", "}")
            attrs = []
            for em in re.finditer(
                r"([A-Za-z_]\w*)\s*(?:=\s*[^,}]+)?", text[lb + 1 : rb - 1]
            ):
                if em.group(1):
                    attrs.append(self._add_arg(em.group(1), "enum-member"))
            self._add_class(file_id, name, description="squirrel enum", attr_ids=attrs)

        def in_class(pos):
            return any(a <= pos < b for a, b in class_ranges)

        for m in self._FUNC.finditer(text):
            if in_class(m.start()):
                continue
            name = m.group(1)
            arg_ids = [
                self._add_arg(p.strip().split("=")[0].strip())
                for p in m.group(2).split(",")
                if p.strip()
            ]
            self._add_function(
                file_id, name, arg_ids, [], description="squirrel function"
            )

        for m in self._LOCAL.finditer(text):
            if not in_class(m.start()):
                self._add_variable(file_id, m.group(1), None, scope="local")
        for m in self._CONST.finditer(text):
            self._add_variable(file_id, m.group(1), None)
        for m in self._SLOT.finditer(text):
            if not in_class(m.start()):
                self._add_variable(file_id, m.group(1), None)
