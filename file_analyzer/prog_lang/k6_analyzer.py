# k6 load-test scripts (.k6).
#
# A k6 script is plain ECMAScript (ES-module) source: it `import`s from the
# `k6`/`k6/http`/`k6/metrics` namespaces, `export`s a `default function` (the VU
# entry point) plus optional lifecycle functions (`setup`, `teardown`,
# `handleSummary`) and an `options` config object, and defines ordinary
# functions/classes/consts.  The syntax is JavaScript, so the honest analyzer is
# the tree-sitter JS engine with the k6 extension and a k6-specific attribution
# for the introspection source.  Every import / function / class / variable a
# real k6 test contains is captured by the inherited JS extraction unchanged.
from .javascript_analyzer import JavaScriptAnalyzer


class K6Analyzer(JavaScriptAnalyzer):
    def __init__(self, **kwargs):
        # grammar stays the JavaScript tree-sitter parser; only the recorded
        # language name and on-disk extension change.
        super().__init__(lang_key="javascript", extensions=[".k6"], **kwargs)
        self.language_name = "k6"
        self.introspection_source = (
            "k6 ES-module test script (import k6/*, export default VU fn + "
            "setup/teardown/handleSummary lifecycle + options)"
        )
