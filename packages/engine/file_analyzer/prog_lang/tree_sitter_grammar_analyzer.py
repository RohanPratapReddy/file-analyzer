# Tree-sitter grammar (.tree-sitter).
#
# A Tree-sitter grammar is authored as `grammar.js`, plain CommonJS JavaScript
# that exports a `grammar({...})` call:
#
#     const PREC = { call: 14, unary: 13 };            -> variable
#     module.exports = grammar({
#       name: "mylang",
#       rules: {
#         source_file: $ => repeat($._definition),     -> rule (arrow fn)
#         function_definition: $ => seq("fn", ...),
#       },
#     });
#     function commaSep(rule) { ... }                   -> function (helper)
#
# The syntax is JavaScript, so the honest analyzer is the tree-sitter JS engine
# with the `.tree-sitter` extension; every helper function, PREC/const variable
# and `require(...)` a grammar file contains is captured by the inherited JS
# extraction unchanged.
from .javascript_analyzer import JavaScriptAnalyzer


class TreeSitterGrammarAnalyzer(JavaScriptAnalyzer):
    def __init__(self, **kwargs):
        super().__init__(lang_key="javascript", extensions=[".tree-sitter"], **kwargs)
        self.language_name = "tree-sitter"
        self.introspection_source = (
            "Tree-sitter grammar.js (module.exports = grammar({name, rules}) + "
            "helper functions and precedence tables)"
        )
