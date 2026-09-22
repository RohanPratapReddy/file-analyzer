"""
file_analyzer.views -- analysis views + reads over the database AnalysisEngine produces.

This sub-package is the single source of truth for the convenience VIEWS that
denormalize the raw relational output into ready-to-read summaries. The catalog
([[catalog]]) defines them once; the builder installs them into the output ``.db``
and appends them to the ``.sql`` dump; the reader (and the moved Go/Java worker
programs under ``file_analyzer/views/go`` and ``file_analyzer/views/java``) then simply read the
installed views instead of embedding query SQL.

Typical use (also wired into ``AnalysisEngine.run``):

    from file_analyzer.views import install_views_sqlite, append_views_to_sql_dump
    install_views_sqlite("repository.db")
    append_views_to_sql_dump("repository_schema.sql")

    from file_analyzer.views import list_views, read_view, read_all_views
    read_all_views("repository.db")
"""

from .builder import (
    append_views_to_sql_dump,
    export_catalog_json,
    install_views_sqlite,
    sqlite_present_tables,
    views_ddl,
    write_sql_artifacts,
)
from .catalog import VIEW_CATALOG, VIEW_PREFIX, ViewDef, catalog_by_name
from .reader import list_views, read_all_views, read_view

__all__ = [
    "VIEW_CATALOG",
    "VIEW_PREFIX",
    "ViewDef",
    "catalog_by_name",
    "views_ddl",
    "install_views_sqlite",
    "append_views_to_sql_dump",
    "export_catalog_json",
    "write_sql_artifacts",
    "sqlite_present_tables",
    "list_views",
    "read_view",
    "read_all_views",
]
