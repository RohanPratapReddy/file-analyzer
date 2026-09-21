"""
src.views -- analysis views + reads over the database AnalysisEngine produces.

This sub-package is the single source of truth for the convenience VIEWS that
denormalize the raw relational output into ready-to-read summaries. The catalog
([[catalog]]) defines them once; the builder installs them into the output ``.db``
and appends them to the ``.sql`` dump; the reader (and the moved Go/Java worker
programs under ``src/views/go`` and ``src/views/java``) then simply read the
installed views instead of embedding query SQL.

Typical use (also wired into ``AnalysisEngine.run``):

    from src.views import install_views_sqlite, append_views_to_sql_dump
    install_views_sqlite("repository.db")
    append_views_to_sql_dump("repository_schema.sql")

    from src.views import list_views, read_view, read_all_views
    read_all_views("repository.db")
"""

from .catalog import VIEW_CATALOG, VIEW_PREFIX, ViewDef, catalog_by_name
from .builder import (
    views_ddl,
    install_views_sqlite,
    append_views_to_sql_dump,
    export_catalog_json,
    write_sql_artifacts,
    sqlite_present_tables,
)
from .reader import list_views, read_view, read_all_views

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
