# Apache Beam pipeline (.beam, text/Python form).
#
# NOTE ON THE EXTENSION: `.beam` is overloaded.  A compiled Erlang/BEAM module
# is *binary* bytecode and carries no analysable source (handled like any binary
# artefact: it decodes to noise and yields nothing).  In the language list this
# entry denotes an **Apache Beam pipeline**, which is ordinary importable Python
# using the `apache_beam` SDK, so the honest analyzer is the AST-based Python
# engine.  Domain shape of a Beam pipeline:
#
#     import apache_beam as beam                      -> import
#     class ParseFn(beam.DoFn):                       -> class (DoFn)
#         def process(self, element): yield ...
#     class CountWords(beam.PTransform):              -> class (composite transform)
#         def expand(self, pcoll): ...
#     @beam.ptransform_fn                             -> function (transform)
#     def MyTransform(pcoll): ...
#     with beam.Pipeline() as p:                      -> tagged pipeline construction
#         p | beam.Map(fn) | beam.ParDo(ParseFn())
#
# Full extraction is inherited from PythonEmbeddedAnalyzer; `_dsl_enrich` flags
# DoFn/PTransform/CombineFn subclasses, ptransform-decorated fns, and pipeline
# construction sites.
import ast

from .python_embedded_base import PythonEmbeddedAnalyzer


class ApacheBeamAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "apache-beam"
    EXTENSIONS = (".beam",)
    DSL_DECORATORS = (
        "ptransform_fn",
        "beam.ptransform_fn",
        "apache_beam.ptransform_fn",
    )
    DSL_BASECLASSES = (
        "DoFn",
        "PTransform",
        "CombineFn",
        "PartitionFn",
        "beam.DoFn",
        "beam.PTransform",
        "beam.CombineFn",
        "apache_beam.DoFn",
        "apache_beam.PTransform",
    )

    def _dsl_enrich(self, file_id, tree, code_text):
        super()._dsl_enrich(file_id, tree, code_text)
        # flag `with beam.Pipeline(...) as p:` construction sites
        for node in ast.walk(tree):
            if isinstance(node, ast.With):
                for item in node.items:
                    call = item.context_expr
                    if isinstance(call, ast.Call):
                        root = self._base_root(call.func)
                        if root.split(".")[-1] == "Pipeline":
                            name = "pipeline"
                            if isinstance(item.optional_vars, ast.Name):
                                name = item.optional_vars.id
                            self._dsl_tag(file_id, name, "pipeline-construction")
