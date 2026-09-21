# Marko (.marko) analyzer -- HTML-superset UI component language (eBay).
#
#     import Button from "./button.marko"          -> import
#     import { fmt } from "../util"                -> import (each name)
#     static const TAX = 0.2                        -> variable
#     $ const total = input.price * qty            -> variable (inline script)
#     class {                                       -> class (component)
#         onCreate() { this.state = { n: 0 } }      -> function (method)
#         increment() { this.state.n++ }            -> function (method)
#     }
#     static function helper(a, b) { ... }          -> function
#     <my-widget/>                                  -> import (custom-tag ref)
#
# Comments are '//' and '/* */' inside script; strings use '"', '\'', '`'.
import re
from pathlib import Path

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_$][A-Za-z0-9_$]*"


class MarkoAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "marko"
    EXTENSIONS = (".marko",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'", "`")

    _IMPORT_DEF = re.compile(
        r"(?m)^\s*(?:static\s+)?import\s+(?:("
        + _ID
        + r")\s*,?\s*)?(?:\{([^}]*)\})?\s*(?:from\s+)?"
        r'["\']([^"\']+)["\']'
    )
    # `<component-tag>` custom element references (kebab-case, has a hyphen)
    _CUSTOM_TAG = re.compile(r"<([a-z][a-z0-9]*(?:-[a-z0-9]+)+)\b")
    _CLASS = re.compile(r"(?m)^\s*class\s*\{")
    _STATIC_FUNC = re.compile(
        r"(?m)^\s*static\s+(?:async\s+)?function\s+(" + _ID + r")\s*\(([^)]*)\)"
    )
    # top-level `static <js>` variable declarations
    _STATIC_VAR = re.compile(r"(?m)^\s*static\s+(?:const|let|var)\s+(" + _ID + r")\b")
    # inline-script assignment:  `$ const x = ...`  / `$ let y = ...`
    _DOLLAR_VAR = re.compile(r"(?m)^\s*\$\s+(?:const|let|var)\s+(" + _ID + r")\b")
    # core tag-variables:  <let/count=0>  <const/x=y>  <id/uid>  <get/v=...>
    #                      <const/[a, b]=list>  <const/{ a, b }=obj>  (destructure)
    #                      <define/MyTag>  (reusable tag definition -> function)
    _TAG_VAR = re.compile(r"<(let|const|id|get|define)/")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        if self._CLASS.search(clean):
            stem = Path(path).stem
            self._register_class(stem)

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_imp = set()
        for m in self._IMPORT_DEF.finditer(clean):
            src = m.group(3)
            if m.group(1):
                self._add_import(file_id, m.group(1), src)
            if m.group(2):
                for nm in self._split_top_level(m.group(2)):
                    nm = nm.strip().split(" as ")[-1].strip()
                    if nm:
                        self._add_import(file_id, nm, src)
            if not m.group(1) and not m.group(2):
                leaf = re.split(r"[\\/]", src)[-1]
                self._add_import(file_id, leaf, src)
        for m in self._CUSTOM_TAG.finditer(clean):
            tag = m.group(1)
            if tag in seen_imp or tag in ("http-equiv",):
                continue
            seen_imp.add(tag)
            self._add_import(file_id, tag, tag)

        cls_id = None
        if self._CLASS.search(clean):
            cls_id = self._register_class(Path(path).stem)
            self._add_class(file_id, Path(path).stem, description="marko component")
            self._extract_methods(file_id, clean, cls_id)

        for m in self._STATIC_FUNC.finditer(clean):
            args = self._simple_args(m.group(2))
            self._add_function(
                file_id, m.group(1), args, [], description="marko static function"
            )

        seen_var = set()
        for rx, scope in ((self._STATIC_VAR, "static"), (self._DOLLAR_VAR, "script")):
            for m in rx.finditer(clean):
                if m.group(1) in seen_var:
                    continue
                seen_var.add(m.group(1))
                self._add_variable(file_id, m.group(1), scope=scope)

        self._tag_vars(file_id, clean, seen_var)

    def _tag_vars(self, file_id, clean, seen_var):
        for m in self._TAG_VAR.finditer(clean):
            kind = m.group(1)
            i = m.end()
            while i < len(clean) and clean[i] in " \t":
                i += 1
            if i >= len(clean):
                continue
            c = clean[i]
            if c in "[{":
                closer = "]" if c == "[" else "}"
                j = self._find_matching(clean, i, c, closer)
                names = self._destructure_names(clean[i:j])
            else:
                mm = re.match(_ID, clean[i:])
                if not mm:
                    continue
                names = [mm.group(0)]
            for nm in names:
                if kind == "define":
                    self._add_function(
                        file_id, nm, [], [], description="marko tag definition"
                    )
                elif nm not in seen_var:
                    seen_var.add(nm)
                    self._add_variable(file_id, nm, scope="tag")

    def _destructure_names(self, binding):
        inner = binding[1:-1] if binding and binding[0] in "[{" else binding
        names = []
        for part in self._split_top_level(inner):
            part = part.strip().lstrip(".")  # rest ...target
            part = part.split("=")[0].strip()  # drop default value
            if not part:
                continue
            if ":" in part and part[0] not in "[{":  # object rename key:target
                part = part.split(":", 1)[1].strip()
            if part and part[0] in "[{":  # nested destructure
                names.extend(self._destructure_names(part))
                continue
            mm = re.match(_ID, part)
            if mm:
                names.append(mm.group(0))
        return names

    def _extract_methods(self, file_id, clean, cls_id):
        cm = self._CLASS.search(clean)
        brace = clean.index("{", cm.start())
        end = self._find_matching(clean, brace, "{", "}")
        body = clean[brace + 1 : end - 1]
        # ES6 method shorthand:  name(args) {
        meth = re.compile(
            r"(?m)^\s*(?:async\s+|get\s+|set\s+|\*\s*)*("
            + _ID
            + r")\s*\(([^)]*)\)\s*\{"
        )
        for m in meth.finditer(body):
            name = m.group(1)
            if name in ("if", "for", "while", "switch", "catch", "return"):
                continue
            args = self._simple_args(m.group(2))
            self._add_function(
                file_id, name, args, [], class_id=cls_id, description="marko method"
            )

    def _simple_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip().split("=")[0].strip()
            part = part.lstrip(".")  # rest args
            m = re.match(_ID, part)
            if m:
                arg_ids.append(self._add_arg(m.group(0)))
        return arg_ids
