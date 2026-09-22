# Dagster (.dagster) analyzer.
#
# Dagster pipelines are ordinary Python using the `dagster` framework; the file
# grammar is Python (AST-parsed by the shared base).  Domain constructs:
#
#     import dagster as dg
#     from dagster import asset, op, job, Definitions   -> import
#     @dg.asset                                          -> function (software-defined asset)
#     def raw_users(context): ...
#     @op                                                -> function (op)
#     def transform(context, data): ...
#     @job                                               -> function (job)
#     def etl(): transform(raw_users())
#     @sensor(job=etl) / @schedule(...)                  -> function (sensor/schedule)
#     class MyConfig(dg.Config): ...                     -> class (config)
#
# The @asset/@op/@job/@graph/@sensor/@schedule/@resource decorators mark Dagster
# entry points; they are tagged in addition to the full Python pass.
from .python_embedded_base import PythonEmbeddedAnalyzer


class DagsterAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "dagster"
    EXTENSIONS = (".dagster",)
    DSL_DECORATORS = (
        "asset",
        "op",
        "job",
        "graph",
        "graph_asset",
        "multi_asset",
        "sensor",
        "schedule",
        "resource",
        "config_mapping",
        "hook",
        "asset_check",
        "observable_source_asset",
        "static_partitioned_config",
        # dotted (aliased-module) forms
        "dg.asset",
        "dg.op",
        "dg.job",
        "dg.graph",
        "dg.sensor",
        "dg.schedule",
        "dagster.asset",
        "dagster.op",
        "dagster.job",
        "dagster.sensor",
    )
    DSL_BASECLASSES = (
        "Config",
        "dg.Config",
        "dagster.Config",
        "ConfigurableResource",
        "dg.ConfigurableResource",
        "IOManager",
        "dagster.ConfigurableResource",
    )
