# Riot.js (.riot) analyzer -- custom-tag component format.
#
#     <todo-app>                                    -> class (component tag)
#       <h3>{ props.title }</h3>
#       <script>
#         import Item from './item.riot'            -> import
#         export default {                          -> component object
#           state: { count: 0 },
#           onMounted() { ... },                    -> function (method)
#           increment(e) { this.update(...) },      -> function (method)
#         }
#       </script>
#     </todo-app>
#
# Comments inside <script> are '//' and '/* */'; strings use '"', '\'', '`'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_$][A-Za-z0-9_$]*"


class RiotAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "riot"
    EXTENSIONS = (".riot",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'", "`")

    # root custom tag:  <my-tag ...>   (kebab or camel, first tag in the file)
    _ROOT_TAG = re.compile(r"<([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)\b")
    _SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)
    _IMPORT = re.compile(
        r"(?m)^\s*import\s+(?:(" + _ID + r")\s*,?\s*)?"
        r'(?:\{([^}]*)\})?\s*(?:from\s+)?["\']([^"\']+)["\']'
    )

    _HTML_TAGS = {
        "div",
        "span",
        "p",
        "a",
        "ul",
        "li",
        "ol",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "button",
        "input",
        "form",
        "label",
        "img",
        "table",
        "tr",
        "td",
        "th",
        "thead",
        "tbody",
        "select",
        "option",
        "textarea",
        "br",
        "hr",
        "nav",
        "header",
        "footer",
        "section",
        "article",
        "main",
        "aside",
        "style",
        "script",
        "template",
        "slot",
        "pre",
        "code",
        "strong",
        "em",
        "b",
        "i",
        "small",
        "svg",
        "path",
        "g",
        "figure",
        "figcaption",
        "video",
        "audio",
        "canvas",
        "iframe",
        "fieldset",
        "legend",
    }

    def _register_types(self, file_id, text, path):
        name = self._root_tag_name(text)
        if name:
            self._register_class(name)

    def _extract_entities(self, file_id, text, path):
        root = self._root_tag_name(text)
        cls_id = None
        if root:
            cls_id = self._register_class(root)
            self._add_class(file_id, root, description="riot component")

        for sm in self._SCRIPT.finditer(text):
            script = self._strip_comments(sm.group(1))
            for m in self._IMPORT.finditer(script):
                src = m.group(3)
                if m.group(1):
                    self._add_import(file_id, m.group(1), src)
                for nm in self._split_top_level(m.group(2) or ""):
                    nm = nm.strip().split(" as ")[-1].strip()
                    if nm:
                        self._add_import(file_id, nm, src)
                if not m.group(1) and not m.group(2):
                    leaf = re.split(r"[\\/]", src)[-1]
                    self._add_import(file_id, leaf, src)
            self._extract_methods(file_id, script, cls_id)

    def _root_tag_name(self, text):
        for m in self._ROOT_TAG.finditer(text):
            tag = m.group(1)
            if tag.lower() in self._HTML_TAGS:
                continue
            if "-" in tag or tag[0].isupper() or tag.islower():
                # a custom component tag (allow hyphenless lowercase roots too)
                if tag.lower() not in self._HTML_TAGS:
                    return tag
        return None

    def _extract_methods(self, file_id, script, cls_id):
        # object-literal method shorthand:  name(args) {   at low indent
        meth = re.compile(
            r"(?m)^\s{0,8}(?:async\s+|get\s+|set\s+|\*\s*)*("
            + _ID
            + r")\s*\(([^)]*)\)\s*\{"
        )
        seen = set()
        for m in meth.finditer(script):
            name = m.group(1)
            if (
                name in ("if", "for", "while", "switch", "catch", "return", "function")
                or name in seen
            ):
                continue
            seen.add(name)
            args = self._simple_args(m.group(2))
            self._add_function(
                file_id, name, args, [], class_id=cls_id, description="riot method"
            )

    def _simple_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip().split("=")[0].strip().lstrip(".")
            m = re.match(_ID, part)
            if m:
                arg_ids.append(self._add_arg(m.group(0)))
        return arg_ids
