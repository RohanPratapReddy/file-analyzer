# React-Native / Metro JavaScript bundles (.jsbundle).
#
# A `.jsbundle` is the packaged ECMAScript output Metro emits for a native app:
# ordinary JavaScript (usually one big IIFE that registers modules via
# `__d(function(...) {...}, id, deps, name)` and boots with `__r(id)`), plus any
# hand-written `require`/`import`, function, class and const declarations that
# survive un-minified.  The grammar is JavaScript, so the faithful analyzer is
# the tree-sitter JS engine keyed to the `.jsbundle` extension; the inherited
# extraction captures every top-level import / function / class / variable.
from .javascript_analyzer import JavaScriptAnalyzer


class JSBundleAnalyzer(JavaScriptAnalyzer):
    def __init__(self, **kwargs):
        # grammar stays the JavaScript tree-sitter parser; only the recorded
        # language name and on-disk extension change.
        super().__init__(lang_key="javascript", extensions=[".jsbundle"], **kwargs)
        self.language_name = "jsbundle"
        self.introspection_source = (
            "React-Native/Metro JS bundle (__d module factories + __r runtime, "
            "require/import, function/class/const declarations)"
        )
