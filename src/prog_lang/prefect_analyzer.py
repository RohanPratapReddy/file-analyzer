# Prefect (.prefect) analyzer.
#
# Prefect workflows are ordinary Python using the `prefect` framework; the file
# grammar is Python (AST-parsed by the shared base).  Domain constructs:
#
#     from prefect import flow, task                     -> import
#     @task(retries=3)                                   -> function (task)
#     def extract(url): ...
#     @task                                              -> function (task)
#     def transform(data): ...
#     @flow(name="etl")                                  -> function (flow = entry point)
#     def etl(url):
#         data = extract(url)
#         return transform(data)
#     class Settings(Block): ...                         -> class (block)
#
# @flow / @task decorated functions are the domain entry points; they are tagged
# in addition to the full Python pass.
from .python_embedded_base import PythonEmbeddedAnalyzer


class PrefectAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "prefect"
    EXTENSIONS = (".prefect",)
    DSL_DECORATORS = ("flow", "task", "prefect.flow", "prefect.task",
                      "materialize", "prefect.materialize")
    DSL_BASECLASSES = ("Block", "prefect.Block", "prefect.blocks.core.Block")
