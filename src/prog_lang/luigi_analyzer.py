# Luigi (.luigi) analyzer.
#
# Luigi pipelines are ordinary Python using Spotify's `luigi` framework; the
# file grammar is Python (AST-parsed by the shared base).  Domain constructs:
#
#     import luigi                                       -> import
#     class FetchData(luigi.Task):                       -> class (task)
#         date = luigi.DateParameter()                   -> class variable (parameter)
#         def requires(self): return []                  -> method
#         def output(self): return luigi.LocalTarget(...)-> method
#         def run(self): ...                             -> method
#     class Wrapper(luigi.WrapperTask): ...              -> class (wrapper task)
#     class External(luigi.ExternalTask): ...            -> class (external task)
#
# Classes subclassing a Luigi *Task type are the domain entry points; they are
# tagged in addition to the full Python pass (parameters, requires/output/run
# are captured as class variables/methods by the base).
from .python_embedded_base import PythonEmbeddedAnalyzer


class LuigiAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "luigi"
    EXTENSIONS = (".luigi",)
    DSL_BASECLASSES = (
        "Task", "luigi.Task", "WrapperTask", "luigi.WrapperTask",
        "ExternalTask", "luigi.ExternalTask", "Config", "luigi.Config",
        "luigi.contrib.spark.SparkSubmitTask", "SparkSubmitTask",
        "luigi.contrib.postgres.CopyToTable", "CopyToTable",
        "luigi.contrib.s3.S3Target",
    )
