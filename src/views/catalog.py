"""
Authoritative catalog of analysis VIEWS over the database AnalysisEngine emits.

This module is the *single source of truth* for the convenience views that were
previously hard-coded (identically) inside the Go and Java reader programs. The
Python builder ([[builder]]) turns this catalog into real ``CREATE VIEW`` objects
in the output database (and into the ``.sql`` dump); the Go/Java workers then
simply read those installed views (``SELECT * FROM v_<name>``) instead of each
re-embedding the query SQL.

Design rules for every ``select`` body below:

* Pure ``SELECT`` / ``WITH`` -- read-only, no DDL/DML, no side effects.
* Portable across SQLite and PostgreSQL (the two live targets):
    - ``CASE WHEN is_external THEN ...`` works in both -- SQLite stores the flag
      as INTEGER 0/1 (truthy) and Postgres as a native BOOLEAN.
    - The real columns ``count`` (tensor_members_table) and ``value``
      (data_relations_table) are double-quoted so Postgres does not treat them
      as the aggregate keyword / a reserved word; double quotes are also valid
      identifier quoting in SQLite.
    - ``GROUP BY <alias-or-input-column>`` is used only where both engines agree.
* ``tables`` lists the base tables the view needs. A view is materialized only
  when all of its tables are present, so on a database that lacks (say) the
  ``schema_*`` or ``data_*`` families those views are simply never created --
  and the readers therefore never see (or error on) them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

# Prefix applied to the created database object so the views are trivially
# distinguishable from base tables (and from any future generator views).
VIEW_PREFIX = "v_"


@dataclass(frozen=True)
class ViewDef:
    """One analysis view: a logical name, its required base tables, and its SELECT."""

    name: str
    tables: Tuple[str, ...]
    select: str

    @property
    def object_name(self) -> str:
        """The name of the created database VIEW object (prefixed)."""
        return f"{VIEW_PREFIX}{self.name}"


def _v(name: str, tables: Tuple[str, ...], select: str) -> ViewDef:
    # Collapse the readable multi-line SQL to a single normalized line.
    return ViewDef(name, tables, " ".join(select.split()))


# ---------------------------------------------------------------------------
# The catalog. Grouped by analyzer family; order is the report order.
# ---------------------------------------------------------------------------
VIEW_CATALOG: List[ViewDef] = [
    # ----- Core repository views (RepositoryAnalyzer + code analyzers) -----
    _v("file_inventory", ("file_details", "tables"), """
        SELECT f.file_id,
               f.file_name || '.' || e.extension_name AS file,
               f.size, f.units
        FROM file_details f
        JOIN "tables" e ON f.file_extension_id = e.extension_id
        ORDER BY f.size DESC
        LIMIT 20
    """),
    _v("extension_distribution", ("file_details", "tables"), """
        SELECT e.extension_name, COUNT(*) AS file_count
        FROM file_details f
        JOIN "tables" e ON f.file_extension_id = e.extension_id
        GROUP BY e.extension_name
        ORDER BY file_count DESC
    """),
    _v("folder_tree_depth", ("folder_details",), """
        WITH RECURSIVE tree(id, name, depth) AS (
            SELECT folder_id, folder_name, 0
            FROM folder_details WHERE parent_folder_id IS NULL
            UNION ALL
            SELECT f.folder_id, f.folder_name, t.depth + 1
            FROM folder_details f JOIN tree t ON f.parent_folder_id = t.id
        )
        SELECT depth, COUNT(*) AS folders
        FROM tree GROUP BY depth ORDER BY depth
    """),
    _v("import_internal_vs_external", ("import_linkage_table",), """
        SELECT CASE WHEN is_external THEN 'external' ELSE 'internal' END AS kind,
               COUNT(*) AS links
        FROM import_linkage_table
        GROUP BY kind ORDER BY links DESC
    """),
    _v("import_edges", ("import_linkage_table",), """
        SELECT linkage_id, import_name, import_source,
               imported_by_file_name AS by_file,
               imported_to_file_name AS to_file,
               CASE WHEN is_external THEN 'ext' ELSE 'local' END AS scope
        FROM import_linkage_table
        ORDER BY linkage_id
        LIMIT 25
    """),
    _v("top_classes_by_methods", ("classes_table", "junction_class_methods"), """
        SELECT c.class_name, COUNT(j.function_id) AS method_count
        FROM classes_table c
        LEFT JOIN junction_class_methods j ON c.class_id = j.class_id
        GROUP BY c.class_id, c.class_name
        ORDER BY method_count DESC, c.class_name
        LIMIT 15
    """),
    _v("functions_defined_vs_imported", ("functions_table",), """
        SELECT CASE WHEN is_imported THEN 'imported' ELSE 'defined' END AS origin,
               COUNT(*) AS n
        FROM functions_table GROUP BY origin ORDER BY n DESC
    """),
    _v("symbols_by_kind", ("symbol_index", "kind_reference"), """
        SELECT k.kind_name, COUNT(*) AS symbols
        FROM symbol_index s
        JOIN kind_reference k ON s.kind_id = k.kind_id
        GROUP BY k.kind_name ORDER BY symbols DESC
    """),
    _v("introspection_by_language", ("introspection_metadata_table",), """
        SELECT language, inspection_source, COUNT(*) AS records
        FROM introspection_metadata_table
        GROUP BY language, inspection_source
        ORDER BY records DESC
    """),
    _v("tensor_members_by_kind", ("tensor_members_table",), """
        SELECT kind, COUNT(*) AS members, SUM(COALESCE("count", 0)) AS total_count
        FROM tensor_members_table GROUP BY kind ORDER BY members DESC
    """),

    # ----- Database-schema views (SchemaAnalyzer output) -----
    _v("schema_databases_by_engine", ("schema_databases_table",), """
        SELECT db_engine, COUNT(*) AS databases
        FROM schema_databases_table
        GROUP BY db_engine ORDER BY databases DESC
    """),
    _v("schema_tables_by_engine", ("schema_tables_table",), """
        SELECT db_engine, COUNT(*) AS tables
        FROM schema_tables_table
        GROUP BY db_engine ORDER BY tables DESC
    """),
    _v("schema_tables_by_kind", ("schema_tables_table",), """
        SELECT table_kind, COUNT(*) AS n
        FROM schema_tables_table
        GROUP BY table_kind ORDER BY n DESC
    """),
    _v("schema_top_column_types", ("schema_columns_table",), """
        SELECT column_type, COUNT(*) AS columns
        FROM schema_columns_table
        GROUP BY column_type ORDER BY columns DESC
        LIMIT 20
    """),
    _v("schema_keys_by_type", ("schema_keys_table",), """
        SELECT key_type, COUNT(*) AS keys
        FROM schema_keys_table
        GROUP BY key_type ORDER BY keys DESC
    """),
    _v("schema_foreign_key_edges", ("schema_keys_table", "schema_tables_table"), """
        SELECT t.table_name AS from_table,
               k.referenced_table AS to_table,
               k.on_delete, k.on_update
        FROM schema_keys_table k
        JOIN schema_tables_table t ON k.table_id = t.table_id
        WHERE k.key_type = 'FOREIGN KEY'
        ORDER BY k.key_id
        LIMIT 25
    """),
    _v("schema_constraints_by_type", ("schema_constraints_table",), """
        SELECT constraint_type, COUNT(*) AS n
        FROM schema_constraints_table
        GROUP BY constraint_type ORDER BY n DESC
    """),
    _v("schema_triggers_by_timing", ("schema_triggers_table",), """
        SELECT COALESCE(timing, '(none)') AS timing, COUNT(*) AS triggers
        FROM schema_triggers_table
        GROUP BY timing ORDER BY triggers DESC
    """),
    _v("schema_methods_by_language", ("schema_methods_table",), """
        SELECT COALESCE(language, '(none)') AS language,
               COALESCE(method_kind, '(none)') AS method_kind,
               COUNT(*) AS methods
        FROM schema_methods_table
        GROUP BY language, method_kind ORDER BY methods DESC
    """),
    _v("schema_types_by_category", ("schema_types_table",), """
        SELECT COALESCE(type_category, '(none)') AS type_category, COUNT(*) AS n
        FROM schema_types_table
        GROUP BY type_category ORDER BY n DESC
    """),
    _v("schema_top_indexed_tables", ("schema_indexes_table", "schema_tables_table"), """
        SELECT t.table_name, COUNT(*) AS indexes
        FROM schema_indexes_table i
        JOIN schema_tables_table t ON i.table_id = t.table_id
        GROUP BY t.table_id, t.table_name
        ORDER BY indexes DESC, t.table_name
        LIMIT 15
    """),
    _v("schema_entities_per_file", ("schema_file_index", "file_details"), """
        SELECT f.file_name, sfi.entity_kind, COUNT(*) AS entities
        FROM schema_file_index sfi
        JOIN file_details f ON sfi.file_id = f.file_id
        GROUP BY f.file_id, f.file_name, sfi.entity_kind
        ORDER BY entities DESC
        LIMIT 25
    """),

    # ----- Data-artifact profile views (DataAnalyzer output) -----
    _v("data_datasets_by_modality", ("data_datasets_table",), """
        SELECT modality, COUNT(*) AS datasets
        FROM data_datasets_table
        GROUP BY modality ORDER BY datasets DESC
    """),
    _v("data_datasets_by_category", ("data_datasets_table",), """
        SELECT category, subcategory, COUNT(*) AS datasets
        FROM data_datasets_table
        GROUP BY category, subcategory ORDER BY datasets DESC LIMIT 25
    """),
    _v("data_datasets_by_format", ("data_datasets_table",), """
        SELECT file_format, COUNT(*) AS datasets, SUM(size_bytes) AS total_bytes
        FROM data_datasets_table
        GROUP BY file_format ORDER BY datasets DESC LIMIT 25
    """),
    _v("data_analysis_status", ("data_datasets_table",), """
        SELECT analysis_status, COUNT(*) AS datasets
        FROM data_datasets_table
        GROUP BY analysis_status ORDER BY datasets DESC
    """),
    _v("data_largest_tabular", ("data_datasets_table",), """
        SELECT dataset_name, row_count, column_count
        FROM data_datasets_table
        WHERE row_count IS NOT NULL
        ORDER BY row_count DESC LIMIT 25
    """),
    _v("data_columns_by_inferred_type", ("data_columns_table",), """
        SELECT inferred_type, COUNT(*) AS columns
        FROM data_columns_table
        GROUP BY inferred_type ORDER BY columns DESC
    """),
    _v("data_top_correlations", ("data_relations_table", "data_datasets_table"), """
        SELECT d.dataset_name, r.left_column, r.right_column, r."value"
        FROM data_relations_table r
        JOIN data_datasets_table d ON r.dataset_id = d.dataset_id
        WHERE r.relation_type = 'pearson_correlation'
        ORDER BY ABS(r."value") DESC LIMIT 25
    """),
    _v("data_tensors_by_dtype", ("data_tensors_table",), """
        SELECT dtype, COUNT(*) AS tensors, SUM(num_elements) AS total_elements
        FROM data_tensors_table
        GROUP BY dtype ORDER BY tensors DESC LIMIT 25
    """),
    _v("data_largest_tensors", ("data_tensors_table", "data_datasets_table"), """
        SELECT d.dataset_name, t.tensor_name, t.dtype, t.rank, t.num_elements
        FROM data_tensors_table t
        JOIN data_datasets_table d ON t.dataset_id = d.dataset_id
        ORDER BY t.num_elements DESC LIMIT 25
    """),
    _v("data_properties_by_group", ("data_properties_table",), """
        SELECT group_name, COUNT(*) AS properties
        FROM data_properties_table
        GROUP BY group_name ORDER BY properties DESC LIMIT 25
    """),
    _v("data_entities_per_file", ("data_file_index", "file_details"), """
        SELECT f.file_name, dfi.entity_kind, COUNT(*) AS entities
        FROM data_file_index dfi
        JOIN file_details f ON dfi.file_id = f.file_id
        GROUP BY f.file_id, f.file_name, dfi.entity_kind
        ORDER BY entities DESC
        LIMIT 25
    """),
]


def catalog_by_name() -> dict:
    """Return {view_name: ViewDef} for quick lookup."""
    return {v.name: v for v in VIEW_CATALOG}
