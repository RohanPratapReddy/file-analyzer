# Auto-extracted from code_analyzer.py (verbatim class body).
import concurrent.futures
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class RepositoryDatabaseGenerator:
    """
    Transforms in-memory metadata tables produced by RepositoryAnalyzer and
    PolyglotCodeAnalyzer into a fully normalized, relational SQL schema dump
    (including the introspection_metadata_table) and can materialize a SQLite database.
    """

    SUPPORTED_DIALECTS = ["mysql", "pgsql", "postgresql", "sqlite"]

    def __init__(
        self,
        folder_tables: Tuple[
            List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]
        ],
        code_analyzer_tables: Dict[str, List[Dict[str, Any]]],
        import_linkage_table: Optional[List[Dict[str, Any]]] = None,
        schema_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        database_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        data_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        config_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        text_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        markup_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        document_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        misc_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        archive_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        binary_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        conversion_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        sql_dialect: str = "sqlite",
        dump_sql_path: str = "repository_schema.sql",
        schema_name: str = "code_intelligence",
        drop_existing: bool = True,
    ):
        """
        Args:
            folder_tables: Tuple of (folder_details, tables, file_details)
                           from RepositoryAnalyzer.generate().
            code_analyzer_tables: Dict of tables from CodeAnalyzer.get_tables().
            import_linkage_table: Optional list of rows from
                           ImportLinkageAnalyzer.generate() (cross-file import resolution).
            schema_tables: Optional dict of tables from SchemaAnalyzer.get_tables()
                           (database-schema definitions parsed from SQL/Mongo/Redis/...
                           artifacts). When provided, the schema_* relational tables
                           are added to the DDL/inserts alongside the code tables.
            database_tables: Optional dict of tables from DatabaseAnalyzer.get_tables()
                           (``database_stores_table`` + tables/columns/indexes/
                           relations/properties + ``database_file_index``): one
                           on-disk database *store* per file, merging schema
                           structure with a data profile -- metadata & statistics
                           only, never the payload, never decryption. When
                           provided, the database_* relational tables are added to
                           the DDL/inserts alongside the rest.
            data_tables: Optional dict of tables from DataAnalyzer.get_tables()
                           (dataset/column/tensor/relation/property profiles of
                           real data artifacts -- csv/parquet/json/images/tensors/
                           documents/... -- metadata & statistics only, never the
                           payload). When provided, the data_* relational tables
                           are added to the DDL/inserts alongside the code tables.
            config_tables: Optional dict of tables from ConfigAnalyzer.get_tables()
                           (``config_files_table`` + ``config_sections_table`` +
                           ``config_value_keys_table`` + ``config_values_table`` +
                           ``config_properties_table`` + ``config_file_index``):
                           one configuration *file* decomposed into a normalized
                           key/value tree -- one key node per position (with its
                           name/path/parent), one typed value row per key
                           (config_value_type INT/FLOAT/STRING/BOOL/NULL/BYTES/
                           DICT/LIST + parent link), top-level containers grouped
                           into sections, and file-level metadata/forensic profile
                           as properties. Real per-extension parsing, metadata &
                           values only, never the raw payload; credential digests
                           redacted. When provided, the config_* relational tables
                           are added to the DDL/inserts alongside the rest.
            text_tables: Optional dict of tables from TextualAnalyzer.get_tables()
                           (``text_files_table`` + ``text_sections_table`` +
                           ``text_records_table`` + ``text_fields_table`` +
                           ``text_properties_table`` + ``text_file_index``): one
                           text-record *file* (data_text/text/log/documentation/
                           template/scientific_data/subtitle) decomposed into a
                           normalized document->sections->records->fields tree --
                           one section per top-level grouping, one record per entry
                           (caption cue / log event / checksum / G-code command /
                           JSON object / table row / ...), one typed field per
                           name/value pair, plus file-level metadata/forensic
                           profile as properties. Real per-extension parsing,
                           metadata & values only, never the raw payload; JWT
                           signatures redacted. When provided, the text_* relational
                           tables are added to the DDL/inserts alongside the rest.
            archive_tables: Optional dict of tables from ArchiveAnalyzer.process()
                           (``archive_index`` + ``archive_members``): a census of
                           zip/tar/compression containers and their members, with
                           ``archive_index.sub_database`` pointing at the nested
                           per-archive database produced by recursing into the
                           extracted tree. When provided, the archive_* relational
                           tables are added to the DDL/inserts alongside the rest.
            binary_tables: Optional dict of tables from MachineCodeAnalyzer.process()
                           (``binary_index`` + ``binary_sections`` + ``binary_symbols``
                           + ``binary_imports`` + ``binary_properties``): deep
                           executable/object/bytecode structure (ELF/PE/Mach-O/.class/
                           .pyc/WASM/DEX/ar/LLVM/UF2/OLE) with forensic metrics --
                           metadata only, never payload. When provided, the binary_*
                           relational tables are added to the DDL/inserts.
            conversion_tables: Optional dict of tables from
                           FormatConverter.convert_files() (``format_conversions``):
                           one row per opaque/legacy/proprietary file for which a
                           *renderable* transcode (PNG/WAV/MP4/PDF/TXT) was
                           attempted, recording the outcome (converted /
                           unsupported / tool_unavailable / skipped_exists / error)
                           and the path of any produced artifact. No payload is
                           stored -- only the outcome metadata; the rendered file
                           itself lives on disk under the conversions output dir.
                           When provided, the ``format_conversions`` table is added
                           to the DDL/inserts alongside the rest. May also carry a
                           ``conversion_analysis`` key (TextAnalyzer output) -- the
                           per-artifact structural deep-parse (PNG/WAV/MP4/PDF/TXT/
                           GIF/HTML metrics as JSON) -- which, when present, adds the
                           companion ``conversion_analysis`` table.
            sql_dialect: Target engine ('mysql', 'pgsql'/'postgresql', 'sqlite').
            dump_sql_path: Path where the resulting .sql file will be written.
            schema_name: Namespace/Database name for PostgreSQL/MySQL.
            drop_existing: Whether to append DROP TABLE IF EXISTS statements.
        """
        self.folders, self.extensions, self.files = folder_tables
        self.code_tables = code_analyzer_tables
        self.import_linkage = import_linkage_table or []
        self.schema = schema_tables or {}
        self.database = database_tables or {}
        self.data = data_tables or {}
        self.config = config_tables or {}
        self.text = text_tables or {}
        self.markup = markup_tables or {}
        self.document = document_tables or {}
        self.misc = misc_tables or {}
        self.archive = archive_tables or {}
        self.binary = binary_tables or {}
        self.conversions = conversion_tables or {}
        self.dialect = sql_dialect.lower()
        if self.dialect == "postgresql":
            self.dialect = "pgsql"

        if self.dialect not in self.SUPPORTED_DIALECTS:
            raise ValueError(
                f"Unsupported dialect '{sql_dialect}'. Must be one of: {self.SUPPORTED_DIALECTS}"
            )

        self.dump_sql_path = Path(dump_sql_path)
        self.schema_name = schema_name
        self.drop_existing = drop_existing

    def generate(self) -> Path:
        """Executes full generation pipeline and writes the .sql script to disk."""
        sql_statements: List[str] = []

        # 1. Header & Configuration Setup
        sql_statements.append(self._generate_header())

        # 2. Schema Drop & Create
        if self.drop_existing:
            sql_statements.append(self._generate_drop_tables())

        # 3. Normalized DDL Tables, Constraints & Indexes
        sql_statements.append(self._generate_ddl())

        # 4. Triggers & Constraints
        sql_statements.append(self._generate_triggers())

        # 5. Data Insert Statements (Normalized)
        sql_statements.append(self._generate_inserts())

        # 6. Commit / Footer
        sql_statements.append(self._generate_footer())

        output_content = "\n\n".join(stmt for stmt in sql_statements if stmt.strip())
        self.dump_sql_path.parent.mkdir(parents=True, exist_ok=True)
        self.dump_sql_path.write_text(output_content, encoding="utf-8")
        print(
            f"Successfully generated full {self.dialect.upper()} relational schema: {self.dump_sql_path}"
        )
        return self.dump_sql_path

    # ================= Dialect Primitives =================

    def _quote(self, identifier: str) -> str:
        if self.dialect == "mysql":
            return f"`{identifier}`"
        return f'"{identifier}"'

    def _type_pk(self) -> str:
        if self.dialect == "pgsql":
            return "BIGSERIAL PRIMARY KEY"
        if self.dialect == "mysql":
            return "BIGINT AUTO_INCREMENT PRIMARY KEY"
        return "INTEGER PRIMARY KEY AUTOINCREMENT"

    def _type_int(self) -> str:
        return "INTEGER" if self.dialect == "sqlite" else "BIGINT"

    def _type_text(self) -> str:
        return "TEXT"

    def _type_bool(self) -> str:
        if self.dialect == "sqlite":
            return "INTEGER DEFAULT 0"
        if self.dialect == "mysql":
            return "TINYINT(1) DEFAULT 0"
        return "BOOLEAN DEFAULT FALSE"

    def _type_json(self) -> str:
        if self.dialect == "pgsql":
            return "JSONB"
        if self.dialect == "mysql":
            return "JSON"
        return "TEXT"

    def _escape_sql_val(self, val: Any) -> str:
        if val is None:
            return "NULL"
        if isinstance(val, bool):
            if self.dialect in ["sqlite", "mysql"]:
                return "1" if val else "0"
            return "TRUE" if val else "FALSE"
        if isinstance(val, (int, float)):
            return str(val)
        if isinstance(val, (dict, list)):
            sanitized = json.dumps(val).replace("'", "''")
            return f"'{sanitized}'"

        s = str(val).replace("'", "''")
        return f"'{s}'"

    # ================= Header & DDL Sections =================

    def _generate_header(self) -> str:
        comment_bar = "-- " + "=" * 76
        lines = [
            comment_bar,
            f"-- Relational Database Schema Dump ({self.dialect.upper()})",
            f"-- Generated Target: {self.dump_sql_path.name}",
            comment_bar,
            "",
        ]
        if self.dialect == "sqlite":
            lines.append("PRAGMA foreign_keys = OFF;")
        elif self.dialect == "mysql":
            lines.extend(
                [
                    "SET FOREIGN_KEY_CHECKS = 0;",
                    "SET NAMES utf8mb4;",
                    f"CREATE DATABASE IF NOT EXISTS {self._quote(self.schema_name)};",
                    f"USE {self._quote(self.schema_name)};",
                ]
            )
        elif self.dialect == "pgsql":
            lines.extend(
                [
                    "SET client_encoding = 'UTF8';",
                    f"CREATE SCHEMA IF NOT EXISTS {self._quote(self.schema_name)};",
                    f"SET search_path TO {self._quote(self.schema_name)}, public;",
                ]
            )
        return "\n".join(lines)

    def _generate_drop_tables(self) -> str:
        # Tables ordered respecting reverse dependency hierarchy.
        # Schema-definition tables reference file_details, so they must be
        # dropped before it -> they lead the reverse-order list.
        schema_reverse_order = (
            [
                "schema_file_index",
                "schema_indexes_table",
                "schema_types_table",
                "schema_methods_table",
                "schema_triggers_table",
                "schema_constraints_table",
                "schema_keys_table",
                "schema_columns_table",
                "schema_tables_table",
                "schema_databases_table",
            ]
            if self.schema
            else []
        )
        # Data-profile tables also reference file_details (and their own parent
        # data_datasets_table), so children/index lead, datasets trail, and the
        # whole block precedes file_details.
        data_reverse_order = (
            [
                "data_file_index",
                "data_model_layers_table",
                "data_relations_table",
                "data_tensors_table",
                "data_properties_table",
                "data_columns_table",
                "data_datasets_table",
            ]
            if self.data
            else []
        )
        # Database-store tables: tables/columns/indexes/relations/properties and the
        # file index reference their database_stores_table parent (and file_details),
        # so children/index lead, stores trail, block precedes file_details.
        database_reverse_order = (
            [
                "database_file_index",
                "database_properties_table",
                "database_relations_table",
                "database_indexes_table",
                "database_columns_table",
                "database_tables_table",
                "database_stores_table",
            ]
            if self.database
            else []
        )
        # Config key/value tables: sections/keys/values/properties and the file
        # index reference their config_files_table parent (and file_details), so
        # children/index lead, files trail, block precedes file_details.
        config_reverse_order = (
            [
                "config_file_index",
                "config_values_table",
                "config_value_keys_table",
                "config_properties_table",
                "config_sections_table",
                "config_files_table",
            ]
            if self.config
            else []
        )
        # Text-record tables: sections/records/fields/properties and the file index
        # reference their text_files_table parent (and file_details), so children/
        # index lead, files trail, block precedes file_details.
        text_reverse_order = (
            [
                "text_file_index",
                "text_fields_table",
                "text_records_table",
                "text_sections_table",
                "text_properties_table",
                "text_files_table",
            ]
            if self.text
            else []
        )
        # Markup tables: elements/attributes/namespaces/sections/properties and
        # the file index reference their markup_files_table parent (and
        # file_details); attributes also reference their markup_elements_table
        # parent. Children/index lead, files trail, block precedes file_details.
        markup_reverse_order = (
            [
                "markup_file_index",
                "markup_attributes_table",
                "markup_namespaces_table",
                "markup_sections_table",
                "markup_properties_table",
                "markup_elements_table",
                "markup_files_table",
            ]
            if self.markup
            else []
        )
        # Document tables: sections/records/fields/properties and the file index
        # reference their document_files_table parent (and file_details); fields
        # also reference their record/section parents. Children/index lead, files
        # trail, block precedes file_details.
        document_reverse_order = (
            [
                "document_file_index",
                "document_fields_table",
                "document_records_table",
                "document_sections_table",
                "document_properties_table",
                "document_files_table",
            ]
            if self.document
            else []
        )
        # Misc census tables (terminal plane): mirror the document layer -- fields
        # lead, then records, sections, properties, index trails, files precede
        # file_details.
        misc_reverse_order = (
            [
                "misc_file_index",
                "misc_fields_table",
                "misc_records_table",
                "misc_sections_table",
                "misc_properties_table",
                "misc_files_table",
            ]
            if self.misc
            else []
        )
        # Archive census tables: members reference their archive_index parent (and
        # file_details), so members lead, index trails, block precedes file_details.
        archive_reverse_order = (
            [
                "archive_members",
                "archive_index",
            ]
            if self.archive
            else []
        )
        # Binary tables: sections/symbols/imports/properties reference their
        # binary_index parent (and file_details), so children lead, index trails,
        # block precedes file_details.
        binary_reverse_order = (
            [
                "binary_properties",
                "binary_imports",
                "binary_symbols",
                "binary_sections",
                "binary_index",
            ]
            if self.binary
            else []
        )
        # Format-conversion outcomes + per-artifact deep analysis: flat tables
        # referencing file_details (analysis also references format_conversions, so
        # it must be dropped before it in reverse order).
        conversion_reverse_order = (
            ["conversion_analysis"]
            if self.conversions.get("conversion_analysis")
            else []
        ) + (["format_conversions"] if self.conversions else [])
        tables_in_reverse_order = (
            schema_reverse_order
            + database_reverse_order
            + data_reverse_order
            + config_reverse_order
            + text_reverse_order
            + markup_reverse_order
            + document_reverse_order
            + misc_reverse_order
            + archive_reverse_order
            + binary_reverse_order
            + conversion_reverse_order
            + [
                "junction_class_methods",
                "junction_class_inheritance",
                "junction_class_args",
                "junction_class_attrs",
                "junction_class_tensor_members",
                "junction_function_args",
                "junction_function_outputs",
                "file_folder_lineage",
                "import_linkage_table",
                "temp_kind_details",
                "introspection_metadata_table",
                "symbol_index",
                "outputs_table",
                "tensor_members_table",
                "args_table",
                "functions_table",
                "classes_table",
                "variables_table",
                "imports_table",
                "kind_reference",
                "file_details",
                "tables",
                "folder_details",
            ]
        )
        drops = ["-- Drop Tables"]
        for tbl in tables_in_reverse_order:
            q_tbl = self._quote(tbl)
            if self.dialect == "pgsql":
                drops.append(f"DROP TABLE IF EXISTS {q_tbl} CASCADE;")
            else:
                drops.append(f"DROP TABLE IF EXISTS {q_tbl};")
        return "\n".join(drops)

    def _generate_ddl(self) -> str:
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        bl = self._type_bool()
        js = self._type_json()

        ddl = [
            "-- ========================================================",
            "-- 1. Filesystem & Repository Storage",
            "-- ========================================================",
            f"""CREATE TABLE {q('folder_details')} (
    {q('folder_id')} {pk},
    {q('folder_name')} {txt} NOT NULL,
    {q('parent_folder_id')} {bi} NULL,
    {q('created_at')} TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    {q('updated_at')} TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT {q('fk_folder_parent')} FOREIGN KEY ({q('parent_folder_id')})
        REFERENCES {q('folder_details')} ({q('folder_id')}) ON DELETE CASCADE
);""",
            f"""CREATE TABLE {q('tables')} (
    {q('extension_id')} {pk},
    {q('extension_name')} VARCHAR(64) NOT NULL UNIQUE
);""",
            f"""CREATE TABLE {q('file_details')} (
    {q('file_id')} {pk},
    {q('file_name')} {txt} NOT NULL,
    {q('file_extension_id')} {bi} NOT NULL,
    {q('size')} NUMERIC(14, 2) NOT NULL DEFAULT 0.0,
    {q('units')} VARCHAR(16) NOT NULL DEFAULT 'Bytes',
    {q('raw_location_json')} {js} NULL,
    {q('created_at_ts64')} {bi} NULL,
    {q('modified_at_ts64')} {bi} NULL,
    {q('created_at')} TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    {q('updated_at')} TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT {q('fk_file_extension')} FOREIGN KEY ({q('file_extension_id')})
        REFERENCES {q('tables')} ({q('extension_id')}) ON DELETE RESTRICT
);""",
            f"""CREATE TABLE {q('file_folder_lineage')} (
    {q('lineage_id')} {pk},
    {q('file_id')} {bi} NOT NULL,
    {q('folder_id')} {bi} NOT NULL,
    {q('depth_index')} INTEGER NOT NULL,
    CONSTRAINT {q('fk_lineage_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_lineage_folder')} FOREIGN KEY ({q('folder_id')})
        REFERENCES {q('folder_details')} ({q('folder_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('uq_file_folder_depth')} UNIQUE ({q('file_id')}, {q('depth_index')})
);""",
            "-- ========================================================",
            "-- 2. Relational Entity Stores",
            "-- ========================================================",
            f"""CREATE TABLE {q('kind_reference')} (
    {q('kind_id')} {pk},
    {q('kind_name')} VARCHAR(64) NOT NULL UNIQUE
);""",
            f"""CREATE TABLE {q('imports_table')} (
    {q('import_id')} {pk},
    {q('import_name')} {txt} NOT NULL,
    {q('import_source')} {txt} NOT NULL,
    {q('alias')} {txt} NULL
);""",
            f"""CREATE TABLE {q('variables_table')} (
    {q('variable_id')} {pk},
    {q('variable_name')} {txt} NOT NULL,
    {q('variable_value')} {txt} NULL,
    {q('scope')} VARCHAR(128) NOT NULL,
    {q('is_imported')} {bl},
    {q('source_import_id')} {bi} NULL,
    CONSTRAINT {q('fk_var_import')} FOREIGN KEY ({q('source_import_id')})
        REFERENCES {q('imports_table')} ({q('import_id')}) ON DELETE SET NULL
);""",
            f"""CREATE TABLE {q('classes_table')} (
    {q('class_id')} {pk},
    {q('class_name')} {txt} NOT NULL,
    {q('class_description')} {txt} NULL,
    {q('is_imported')} {bl},
    {q('source_import_id')} {bi} NULL,
    CONSTRAINT {q('fk_class_import')} FOREIGN KEY ({q('source_import_id')})
        REFERENCES {q('imports_table')} ({q('import_id')}) ON DELETE SET NULL
);""",
            f"""CREATE TABLE {q('functions_table')} (
    {q('function_id')} {pk},
    {q('function_name')} {txt} NOT NULL,
    {q('class_id')} {bi} NULL,
    {q('function_description')} {txt} NULL,
    {q('function_forward_pass')} {txt} NULL,
    {q('function_backward_pass')} {txt} NULL,
    {q('is_imported')} {bl},
    {q('source_import_id')} {bi} NULL,
    CONSTRAINT {q('fk_func_class')} FOREIGN KEY ({q('class_id')})
        REFERENCES {q('classes_table')} ({q('class_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_func_import')} FOREIGN KEY ({q('source_import_id')})
        REFERENCES {q('imports_table')} ({q('import_id')}) ON DELETE SET NULL
);""",
            f"""CREATE TABLE {q('args_table')} (
    {q('args_id')} {pk},
    {q('args_name')} {txt} NOT NULL,
    {q('args_type')} {txt} NULL,
    {q('default_value')} {txt} NULL,
    {q('permitted_values')} {js} NULL
);""",
            f"""CREATE TABLE {q('outputs_table')} (
    {q('output_id')} {pk},
    {q('output_type')} {txt} NOT NULL,
    {q('description')} {txt} NULL
);""",
            f"""CREATE TABLE {q('tensor_members_table')} (
    {q('member_id')} {pk},
    {q('kind')} VARCHAR(64) NOT NULL,
    {q('name')} {txt} NOT NULL,
    {q('count')} {bi} NULL,
    {q('shape')} VARCHAR(128) NULL
);""",
            f"""CREATE TABLE {q('introspection_metadata_table')} (
    {q('metadata_id')} {pk},
    {q('entity_id')} {bi} NOT NULL,
    {q('entity_type')} VARCHAR(64) NOT NULL,
    {q('language')} VARCHAR(64) NOT NULL,
    {q('inspection_source')} {txt} NOT NULL,
    {q('bytecode_or_ast_dump')} {txt} NULL,
    {q('runtime_decorators_or_attributes')} {js} NULL,
    {q('callstack_or_frame_trace')} {txt} NULL,
    {q('structural_properties')} {js} NULL
);""",
            f"""CREATE TABLE {q('import_linkage_table')} (
    {q('linkage_id')} {pk},
    {q('import_id')} {bi} NOT NULL,
    {q('import_name')} {txt} NULL,
    {q('import_source')} {txt} NULL,
    {q('alias')} {txt} NULL,
    {q('imported_by_file_id')} {bi} NULL,
    {q('imported_by_file_name')} {txt} NULL,
    {q('imported_by_file_type')} VARCHAR(64) NULL,
    {q('imported_by_file_location')} {js} NULL,
    {q('imported_to_file_id')} {bi} NULL,
    {q('imported_to_file_name')} {txt} NULL,
    {q('imported_to_file_type')} VARCHAR(64) NULL,
    {q('imported_to_file_location')} {js} NULL,
    {q('is_external')} {bl},
    {q('import_value_ids')} {js} NULL,
    {q('import_value_variable_ids')} {js} NULL,
    {q('import_value_function_ids')} {js} NULL,
    {q('import_value_class_ids')} {js} NULL,
    CONSTRAINT {q('fk_linkage_import')} FOREIGN KEY ({q('import_id')})
        REFERENCES {q('imports_table')} ({q('import_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_linkage_by_file')} FOREIGN KEY ({q('imported_by_file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL,
    CONSTRAINT {q('fk_linkage_to_file')} FOREIGN KEY ({q('imported_to_file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL
);""",
            "-- ========================================================",
            "-- 3. Normalized Relational Junction Tables (3NF)",
            "-- ========================================================",
            f"""CREATE TABLE {q('junction_function_args')} (
    {q('function_id')} {bi} NOT NULL,
    {q('args_id')} {bi} NOT NULL,
    {q('order_index')} INTEGER NOT NULL,
    PRIMARY KEY ({q('function_id')}, {q('args_id')}),
    CONSTRAINT {q('fk_jfa_function')} FOREIGN KEY ({q('function_id')})
        REFERENCES {q('functions_table')} ({q('function_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_jfa_arg')} FOREIGN KEY ({q('args_id')})
        REFERENCES {q('args_table')} ({q('args_id')}) ON DELETE CASCADE
);""",
            f"""CREATE TABLE {q('junction_function_outputs')} (
    {q('function_id')} {bi} NOT NULL,
    {q('output_id')} {bi} NOT NULL,
    PRIMARY KEY ({q('function_id')}, {q('output_id')}),
    CONSTRAINT {q('fk_jfo_function')} FOREIGN KEY ({q('function_id')})
        REFERENCES {q('functions_table')} ({q('function_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_jfo_output')} FOREIGN KEY ({q('output_id')})
        REFERENCES {q('outputs_table')} ({q('output_id')}) ON DELETE CASCADE
);""",
            f"""CREATE TABLE {q('junction_class_methods')} (
    {q('class_id')} {bi} NOT NULL,
    {q('function_id')} {bi} NOT NULL,
    PRIMARY KEY ({q('class_id')}, {q('function_id')}),
    CONSTRAINT {q('fk_jcm_class')} FOREIGN KEY ({q('class_id')})
        REFERENCES {q('classes_table')} ({q('class_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_jcm_function')} FOREIGN KEY ({q('function_id')})
        REFERENCES {q('functions_table')} ({q('function_id')}) ON DELETE CASCADE
);""",
            f"""CREATE TABLE {q('junction_class_inheritance')} (
    {q('class_id')} {bi} NOT NULL,
    {q('parent_class_id')} {bi} NOT NULL,
    PRIMARY KEY ({q('class_id')}, {q('parent_class_id')}),
    CONSTRAINT {q('fk_jci_class')} FOREIGN KEY ({q('class_id')})
        REFERENCES {q('classes_table')} ({q('class_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_jci_parent')} FOREIGN KEY ({q('parent_class_id')})
        REFERENCES {q('classes_table')} ({q('class_id')}) ON DELETE CASCADE
);""",
            f"""CREATE TABLE {q('junction_class_args')} (
    {q('class_id')} {bi} NOT NULL,
    {q('args_id')} {bi} NOT NULL,
    PRIMARY KEY ({q('class_id')}, {q('args_id')}),
    CONSTRAINT {q('fk_jca_class')} FOREIGN KEY ({q('class_id')})
        REFERENCES {q('classes_table')} ({q('class_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_jca_arg')} FOREIGN KEY ({q('args_id')})
        REFERENCES {q('args_table')} ({q('args_id')}) ON DELETE CASCADE
);""",
            f"""CREATE TABLE {q('junction_class_attrs')} (
    {q('class_id')} {bi} NOT NULL,
    {q('args_id')} {bi} NOT NULL,
    PRIMARY KEY ({q('class_id')}, {q('args_id')}),
    CONSTRAINT {q('fk_jcattr_class')} FOREIGN KEY ({q('class_id')})
        REFERENCES {q('classes_table')} ({q('class_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_jcattr_arg')} FOREIGN KEY ({q('args_id')})
        REFERENCES {q('args_table')} ({q('args_id')}) ON DELETE CASCADE
);""",
            f"""CREATE TABLE {q('junction_class_tensor_members')} (
    {q('class_id')} {bi} NOT NULL,
    {q('member_id')} {bi} NOT NULL,
    PRIMARY KEY ({q('class_id')}, {q('member_id')}),
    CONSTRAINT {q('fk_jctm_class')} FOREIGN KEY ({q('class_id')})
        REFERENCES {q('classes_table')} ({q('class_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_jctm_member')} FOREIGN KEY ({q('member_id')})
        REFERENCES {q('tensor_members_table')} ({q('member_id')}) ON DELETE CASCADE
);""",
            f"""CREATE TABLE {q('symbol_index')} (
    {q('symbol_id')} {pk},
    {q('file_id')} {bi} NOT NULL,
    {q('kind_id')} {bi} NOT NULL,
    {q('target_entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_sym_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE,
    CONSTRAINT {q('fk_sym_kind')} FOREIGN KEY ({q('kind_id')})
        REFERENCES {q('kind_reference')} ({q('kind_id')}) ON DELETE RESTRICT
);""",
            f"""CREATE TABLE {q('temp_kind_details')} (
    {q('temp_kind_id')} {pk},
    {q('kind_type')} VARCHAR(64) NOT NULL,
    {q('kind_name')} VARCHAR(128) NOT NULL,
    {q('kind_function_ids')} {js} NULL,
    {q('kind_args_ids')} {js} NULL,
    {q('kind_class_ids')} {js} NULL,
    {q('kind_variables_ids')} {js} NULL,
    {q('kind_tensor_member_ids')} {js} NULL,
    {q('pipeline_flowchart')} {txt} NOT NULL
);""",
        ]

        if self.schema:
            ddl.extend(self._schema_ddl())

        if self.database:
            ddl.extend(self._database_ddl())

        if self.data:
            ddl.extend(self._data_ddl())

        if self.config:
            ddl.extend(self._config_ddl())

        if self.text:
            ddl.extend(self._text_ddl())

        if self.markup:
            ddl.extend(self._markup_ddl())

        if self.document:
            ddl.extend(self._document_ddl())

        if self.misc:
            ddl.extend(self._misc_ddl())

        if self.archive:
            ddl.extend(self._archive_ddl())

        if self.binary:
            ddl.extend(self._binary_ddl())

        if self.conversions:
            ddl.extend(self._conversions_ddl())

        if self.conversions.get("conversion_analysis"):
            ddl.extend(self._analysis_ddl())

        ddl += [
            "-- ========================================================",
            "-- 4. Indexing Hierarchy",
            "-- ========================================================",
            f"CREATE INDEX {q('idx_folder_parent')} ON {q('folder_details')} ({q('parent_folder_id')});",
            f"CREATE INDEX {q('idx_file_ext')} ON {q('file_details')} ({q('file_extension_id')});",
            f"CREATE INDEX {q('idx_sym_file_kind')} ON {q('symbol_index')} ({q('file_id')}, {q('kind_id')});",
            f"CREATE INDEX {q('idx_func_class')} ON {q('functions_table')} ({q('class_id')});",
            f"CREATE INDEX {q('idx_var_scope')} ON {q('variables_table')} ({q('scope')});",
            f"CREATE INDEX {q('idx_meta_entity')} ON {q('introspection_metadata_table')} ({q('entity_id')}, {q('entity_type')});",
            f"CREATE INDEX {q('idx_linkage_import')} ON {q('import_linkage_table')} ({q('import_id')});",
            f"CREATE INDEX {q('idx_linkage_by_file')} ON {q('import_linkage_table')} ({q('imported_by_file_id')});",
            f"CREATE INDEX {q('idx_linkage_to_file')} ON {q('import_linkage_table')} ({q('imported_to_file_id')});",
        ]

        if self.schema:
            ddl += [
                f"CREATE INDEX {q('idx_schema_tbl_file')} ON {q('schema_tables_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_schema_col_file')} ON {q('schema_columns_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_schema_sfi_file')} ON {q('schema_file_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_schema_sfi_entity')} ON {q('schema_file_index')} ({q('entity_kind')}, {q('entity_id')});",
            ]

        if self.database:
            ddl += [
                f"CREATE INDEX {q('idx_db_store_file')} ON {q('database_stores_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_db_tbl_store')} ON {q('database_tables_table')} ({q('store_id')});",
                f"CREATE INDEX {q('idx_db_tbl_file')} ON {q('database_tables_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_db_col_tbl')} ON {q('database_columns_table')} ({q('table_id')});",
                f"CREATE INDEX {q('idx_db_col_store')} ON {q('database_columns_table')} ({q('store_id')});",
                f"CREATE INDEX {q('idx_db_col_file')} ON {q('database_columns_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_db_idx_store')} ON {q('database_indexes_table')} ({q('store_id')});",
                f"CREATE INDEX {q('idx_db_rel_store')} ON {q('database_relations_table')} ({q('store_id')});",
                f"CREATE INDEX {q('idx_db_prop_store')} ON {q('database_properties_table')} ({q('store_id')});",
                f"CREATE INDEX {q('idx_db_dbfi_file')} ON {q('database_file_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_db_dbfi_entity')} ON {q('database_file_index')} ({q('entity_kind')}, {q('entity_id')});",
            ]

        if self.data:
            ddl += [
                f"CREATE INDEX {q('idx_data_ds_file')} ON {q('data_datasets_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_data_col_ds')} ON {q('data_columns_table')} ({q('dataset_id')});",
                f"CREATE INDEX {q('idx_data_col_file')} ON {q('data_columns_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_data_tensor_ds')} ON {q('data_tensors_table')} ({q('dataset_id')});",
                f"CREATE INDEX {q('idx_data_rel_ds')} ON {q('data_relations_table')} ({q('dataset_id')});",
                f"CREATE INDEX {q('idx_data_prop_ds')} ON {q('data_properties_table')} ({q('dataset_id')});",
                f"CREATE INDEX {q('idx_data_mlayer_ds')} ON {q('data_model_layers_table')} ({q('dataset_id')});",
                f"CREATE INDEX {q('idx_data_mlayer_file')} ON {q('data_model_layers_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_data_dfi_file')} ON {q('data_file_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_data_dfi_entity')} ON {q('data_file_index')} ({q('entity_kind')}, {q('entity_id')});",
            ]

        if self.config:
            ddl += [
                f"CREATE INDEX {q('idx_config_file_file')} ON {q('config_files_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_config_sec_cfg')} ON {q('config_sections_table')} ({q('config_file_id')});",
                f"CREATE INDEX {q('idx_config_sec_file')} ON {q('config_sections_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_config_key_cfg')} ON {q('config_value_keys_table')} ({q('config_file_id')});",
                f"CREATE INDEX {q('idx_config_key_sec')} ON {q('config_value_keys_table')} ({q('section_id')});",
                f"CREATE INDEX {q('idx_config_key_parent')} ON {q('config_value_keys_table')} ({q('config_value_parent_key_id')});",
                f"CREATE INDEX {q('idx_config_key_file')} ON {q('config_value_keys_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_config_val_key')} ON {q('config_values_table')} ({q('config_value_key_id')});",
                f"CREATE INDEX {q('idx_config_val_cfg')} ON {q('config_values_table')} ({q('config_file_id')});",
                f"CREATE INDEX {q('idx_config_val_type')} ON {q('config_values_table')} ({q('config_value_type')});",
                f"CREATE INDEX {q('idx_config_val_file')} ON {q('config_values_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_config_prop_cfg')} ON {q('config_properties_table')} ({q('config_file_id')});",
                f"CREATE INDEX {q('idx_config_cfi_file')} ON {q('config_file_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_config_cfi_entity')} ON {q('config_file_index')} ({q('entity_kind')}, {q('entity_id')});",
            ]

        if self.text:
            ddl += [
                f"CREATE INDEX {q('idx_text_file_file')} ON {q('text_files_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_text_sec_txt')} ON {q('text_sections_table')} ({q('text_file_id')});",
                f"CREATE INDEX {q('idx_text_sec_file')} ON {q('text_sections_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_text_rec_txt')} ON {q('text_records_table')} ({q('text_file_id')});",
                f"CREATE INDEX {q('idx_text_rec_sec')} ON {q('text_records_table')} ({q('text_section_id')});",
                f"CREATE INDEX {q('idx_text_rec_file')} ON {q('text_records_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_text_fld_rec')} ON {q('text_fields_table')} ({q('text_record_id')});",
                f"CREATE INDEX {q('idx_text_fld_txt')} ON {q('text_fields_table')} ({q('text_file_id')});",
                f"CREATE INDEX {q('idx_text_fld_file')} ON {q('text_fields_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_text_prop_txt')} ON {q('text_properties_table')} ({q('text_file_id')});",
                f"CREATE INDEX {q('idx_text_tfi_file')} ON {q('text_file_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_text_tfi_entity')} ON {q('text_file_index')} ({q('entity_kind')}, {q('entity_id')});",
            ]

        if self.markup:
            ddl += [
                f"CREATE INDEX {q('idx_markup_file_file')} ON {q('markup_files_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_markup_el_mk')} ON {q('markup_elements_table')} ({q('markup_file_id')});",
                f"CREATE INDEX {q('idx_markup_el_tag')} ON {q('markup_elements_table')} ({q('tag_name')});",
                f"CREATE INDEX {q('idx_markup_el_file')} ON {q('markup_elements_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_markup_attr_mk')} ON {q('markup_attributes_table')} ({q('markup_file_id')});",
                f"CREATE INDEX {q('idx_markup_attr_el')} ON {q('markup_attributes_table')} ({q('markup_element_id')});",
                f"CREATE INDEX {q('idx_markup_attr_file')} ON {q('markup_attributes_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_markup_ns_mk')} ON {q('markup_namespaces_table')} ({q('markup_file_id')});",
                f"CREATE INDEX {q('idx_markup_ns_file')} ON {q('markup_namespaces_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_markup_sec_mk')} ON {q('markup_sections_table')} ({q('markup_file_id')});",
                f"CREATE INDEX {q('idx_markup_sec_file')} ON {q('markup_sections_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_markup_prop_mk')} ON {q('markup_properties_table')} ({q('markup_file_id')});",
                f"CREATE INDEX {q('idx_markup_mfi_file')} ON {q('markup_file_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_markup_mfi_entity')} ON {q('markup_file_index')} ({q('entity_kind')}, {q('entity_id')});",
            ]

        if self.document:
            ddl += [
                f"CREATE INDEX {q('idx_doc_file_file')} ON {q('document_files_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_doc_sec_doc')} ON {q('document_sections_table')} ({q('document_file_id')});",
                f"CREATE INDEX {q('idx_doc_sec_file')} ON {q('document_sections_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_doc_rec_doc')} ON {q('document_records_table')} ({q('document_file_id')});",
                f"CREATE INDEX {q('idx_doc_rec_sec')} ON {q('document_records_table')} ({q('document_section_id')});",
                f"CREATE INDEX {q('idx_doc_rec_file')} ON {q('document_records_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_doc_fld_rec')} ON {q('document_fields_table')} ({q('document_record_id')});",
                f"CREATE INDEX {q('idx_doc_fld_doc')} ON {q('document_fields_table')} ({q('document_file_id')});",
                f"CREATE INDEX {q('idx_doc_fld_file')} ON {q('document_fields_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_doc_prop_doc')} ON {q('document_properties_table')} ({q('document_file_id')});",
                f"CREATE INDEX {q('idx_doc_dfi_file')} ON {q('document_file_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_doc_dfi_entity')} ON {q('document_file_index')} ({q('entity_kind')}, {q('entity_id')});",
            ]

        if self.misc:
            ddl += [
                f"CREATE INDEX {q('idx_misc_file_file')} ON {q('misc_files_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_misc_sec_misc')} ON {q('misc_sections_table')} ({q('misc_file_id')});",
                f"CREATE INDEX {q('idx_misc_sec_file')} ON {q('misc_sections_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_misc_rec_misc')} ON {q('misc_records_table')} ({q('misc_file_id')});",
                f"CREATE INDEX {q('idx_misc_rec_sec')} ON {q('misc_records_table')} ({q('misc_section_id')});",
                f"CREATE INDEX {q('idx_misc_rec_file')} ON {q('misc_records_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_misc_fld_rec')} ON {q('misc_fields_table')} ({q('misc_record_id')});",
                f"CREATE INDEX {q('idx_misc_fld_misc')} ON {q('misc_fields_table')} ({q('misc_file_id')});",
                f"CREATE INDEX {q('idx_misc_fld_file')} ON {q('misc_fields_table')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_misc_prop_misc')} ON {q('misc_properties_table')} ({q('misc_file_id')});",
                f"CREATE INDEX {q('idx_misc_mfi_file')} ON {q('misc_file_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_misc_mfi_entity')} ON {q('misc_file_index')} ({q('entity_kind')}, {q('entity_id')});",
            ]

        if self.archive:
            ddl += [
                f"CREATE INDEX {q('idx_archive_idx_file')} ON {q('archive_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_archive_mem_arc')} ON {q('archive_members')} ({q('archive_id')});",
                f"CREATE INDEX {q('idx_archive_mem_file')} ON {q('archive_members')} ({q('file_id')});",
            ]

        if self.binary:
            ddl += [
                f"CREATE INDEX {q('idx_binary_idx_file')} ON {q('binary_index')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_binary_sec_bin')} ON {q('binary_sections')} ({q('binary_id')});",
                f"CREATE INDEX {q('idx_binary_sym_bin')} ON {q('binary_symbols')} ({q('binary_id')});",
                f"CREATE INDEX {q('idx_binary_imp_bin')} ON {q('binary_imports')} ({q('binary_id')});",
                f"CREATE INDEX {q('idx_binary_prop_bin')} ON {q('binary_properties')} ({q('binary_id')});",
            ]

        if self.conversions:
            ddl += [
                f"CREATE INDEX {q('idx_conv_file')} ON {q('format_conversions')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_conv_status')} ON {q('format_conversions')} ({q('status')});",
            ]

        if self.conversions.get("conversion_analysis"):
            ddl += [
                f"CREATE INDEX {q('idx_canalysis_conv')} ON {q('conversion_analysis')} ({q('conversion_id')});",
                f"CREATE INDEX {q('idx_canalysis_file')} ON {q('conversion_analysis')} ({q('file_id')});",
                f"CREATE INDEX {q('idx_canalysis_status')} ON {q('conversion_analysis')} ({q('status')});",
            ]

        return "\n\n".join(ddl)

    def _schema_ddl(self) -> List[str]:
        """DDL for the database-schema-definition tables (SchemaAnalyzer output)."""
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        bl = self._type_bool()
        js = self._type_json()
        # nullable FK back to the repository file inventory
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )

        return [
            "-- ========================================================",
            "-- 3b. Database Schema Definitions (SQL / Mongo / Redis / ...)",
            "-- ========================================================",
            f"""CREATE TABLE {q('schema_databases_table')} (
    {q('db_id')} {pk},
    {q('db_name')} {txt} NULL,
    {q('db_engine')} VARCHAR(32) NULL,
    {q('namespace')} {txt} NULL,
    {q('file_ids')} {js} NULL,
    {q('table_ids')} {js} NULL
);""",
            f"""CREATE TABLE {q('schema_tables_table')} (
    {q('table_id')} {pk},
    {q('table_name')} {txt} NULL,
    {q('qualified_name')} {txt} NULL,
    {q('db_engine')} VARCHAR(32) NULL,
    {q('namespace')} {txt} NULL,
    {q('table_kind')} VARCHAR(32) NULL,
    {q('columns_ids')} {js} NULL,
    {q('key_ids')} {js} NULL,
    {q('constraint_ids')} {js} NULL,
    {q('trigger_ids')} {js} NULL,
    {q('index_ids')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_schema_tbl_file'))}
);""",
            f"""CREATE TABLE {q('schema_columns_table')} (
    {q('column_id')} {pk},
    {q('column_name')} {txt} NULL,
    {q('column_type')} {txt} NULL,
    {q('column_value')} {txt} NULL,
    {q('keys')} VARCHAR(64) NULL,
    {q('is_nullable')} {bl},
    {q('default_value')} {txt} NULL,
    {q('references_table')} {txt} NULL,
    {q('references_column')} {txt} NULL,
    {q('ordinal')} {bi} NULL,
    {q('table_ids')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_schema_col_file'))}
);""",
            f"""CREATE TABLE {q('schema_keys_table')} (
    {q('key_id')} {pk},
    {q('key_name')} {txt} NULL,
    {q('key_type')} VARCHAR(32) NULL,
    {q('table_id')} {bi} NULL,
    {q('column_ids')} {js} NULL,
    {q('referenced_table')} {txt} NULL,
    {q('referenced_columns')} {js} NULL,
    {q('on_delete')} VARCHAR(32) NULL,
    {q('on_update')} VARCHAR(32) NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_schema_key_file'))}
);""",
            f"""CREATE TABLE {q('schema_constraints_table')} (
    {q('constraint_id')} {pk},
    {q('constraint_name')} {txt} NULL,
    {q('constraint_type')} VARCHAR(32) NULL,
    {q('table_id')} {bi} NULL,
    {q('column_ids')} {js} NULL,
    {q('expression')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_schema_con_file'))}
);""",
            f"""CREATE TABLE {q('schema_triggers_table')} (
    {q('trigger_id')} {pk},
    {q('trigger_name')} {txt} NULL,
    {q('table_id')} {bi} NULL,
    {q('timing')} VARCHAR(32) NULL,
    {q('events')} {js} NULL,
    {q('level')} VARCHAR(16) NULL,
    {q('action')} {txt} NULL,
    {q('method_id')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_schema_trg_file'))}
);""",
            f"""CREATE TABLE {q('schema_methods_table')} (
    {q('method_id')} {pk},
    {q('method_name')} {txt} NULL,
    {q('method_kind')} VARCHAR(32) NULL,
    {q('return_type')} {txt} NULL,
    {q('language')} VARCHAR(32) NULL,
    {q('arg_signature')} {txt} NULL,
    {q('table_id')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_schema_mth_file'))}
);""",
            f"""CREATE TABLE {q('schema_types_table')} (
    {q('type_id')} {pk},
    {q('type_name')} {txt} NULL,
    {q('type_category')} VARCHAR(32) NULL,
    {q('base_type')} {txt} NULL,
    {q('allowed_values')} {js} NULL,
    {q('table_id')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_schema_typ_file'))}
);""",
            f"""CREATE TABLE {q('schema_indexes_table')} (
    {q('index_id')} {pk},
    {q('index_name')} {txt} NULL,
    {q('table_id')} {bi} NULL,
    {q('is_unique')} {bl},
    {q('method')} VARCHAR(32) NULL,
    {q('column_ids')} {js} NULL,
    {q('column_expr')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_schema_idx_file'))}
);""",
            f"""CREATE TABLE {q('schema_file_index')} (
    {q('sfi_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('entity_kind')} VARCHAR(32) NOT NULL,
    {q('entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_schema_sfi_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE
);""",
        ]

    def _database_ddl(self) -> List[str]:
        """DDL for the database-store tables (DatabaseAnalyzer output).

        One ``database_stores_table`` row per on-disk store file (nullable FK to
        ``file_details``, ON DELETE SET NULL). Tables/columns/indexes/relations/
        properties carry a FK to their ``database_stores_table`` parent (ON DELETE
        CASCADE); columns also FK their ``database_tables_table`` parent, indexes
        optionally FK a table. ``database_file_index`` FK to file_details CASCADEs.
        Merges schema structure with a data profile -- metadata only, no payload.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        bl = self._type_bool()
        js = self._type_json()
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_store = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('store_id')})\n"
            f"        REFERENCES {q('database_stores_table')} ({q('store_id')}) ON DELETE CASCADE"
        )
        fk_tbl = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('table_id')})\n"
            f"        REFERENCES {q('database_tables_table')} ({q('table_id')}) ON DELETE CASCADE"
        )

        return [
            "-- ========================================================",
            "-- 3b2. Database Store Files (sqlite/dbase/berkeleydb/ese/jet/",
            "--      redis/leveldb/lmdb/pst/innodb/firebird/... one store/file)",
            "--      schema structure + data profile -- never the raw payload",
            "-- ========================================================",
            f"""CREATE TABLE {q('database_stores_table')} (
    {q('store_id')} {pk},
    {q('store_name')} {txt} NULL,
    {q('engine')} VARCHAR(48) NULL,
    {q('engine_family')} VARCHAR(32) NULL,
    {q('file_format')} VARCHAR(64) NULL,
    {q('format_class')} VARCHAR(16) NULL,
    {q('size_bytes')} {bi} NULL,
    {q('page_size')} {bi} NULL,
    {q('page_count')} {bi} NULL,
    {q('encoding')} VARCHAR(32) NULL,
    {q('schema_version')} {txt} NULL,
    {q('app_version')} {txt} NULL,
    {q('table_count')} {bi} NULL,
    {q('record_count_total')} {bi} NULL,
    {q('structural_parse')} {bl},
    {q('likely_encrypted')} {bl},
    {q('analysis_status')} VARCHAR(32) NULL,
    {q('notes')} {txt} NULL,
    {q('properties')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_db_store_file'))}
);""",
            f"""CREATE TABLE {q('database_tables_table')} (
    {q('table_id')} {pk},
    {q('store_id')} {bi} NULL,
    {q('table_name')} {txt} NULL,
    {q('table_kind')} VARCHAR(32) NULL,
    {q('qualified_name')} {txt} NULL,
    {q('column_count')} {bi} NULL,
    {q('row_count')} {bi} NULL,
    {q('estimated')} {bl},
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_store.format(name=q('fk_db_tbl_store'))},
{fk_file.format(name=q('fk_db_tbl_file'))}
);""",
            f"""CREATE TABLE {q('database_columns_table')} (
    {q('column_id')} {pk},
    {q('table_id')} {bi} NULL,
    {q('store_id')} {bi} NULL,
    {q('column_name')} {txt} NULL,
    {q('ordinal')} {bi} NULL,
    {q('declared_type')} {txt} NULL,
    {q('inferred_type')} VARCHAR(32) NULL,
    {q('is_nullable')} {bl},
    {q('is_primary_key')} {bl},
    {q('is_unique')} {bl},
    {q('default_value')} {txt} NULL,
    {q('references_table')} {txt} NULL,
    {q('references_column')} {txt} NULL,
    {q('null_count')} {bi} NULL,
    {q('non_null_count')} {bi} NULL,
    {q('distinct_count')} {bi} NULL,
    {q('min_value')} {txt} NULL,
    {q('max_value')} {txt} NULL,
    {q('sample_values')} {js} NULL,
    {q('extra')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_tbl.format(name=q('fk_db_col_tbl'))},
{fk_store.format(name=q('fk_db_col_store'))},
{fk_file.format(name=q('fk_db_col_file'))}
);""",
            f"""CREATE TABLE {q('database_indexes_table')} (
    {q('index_id')} {pk},
    {q('store_id')} {bi} NULL,
    {q('table_id')} {bi} NULL,
    {q('table_name')} {txt} NULL,
    {q('index_name')} {txt} NULL,
    {q('is_unique')} {bl},
    {q('method')} VARCHAR(32) NULL,
    {q('column_names')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_store.format(name=q('fk_db_idx_store'))},
{fk_tbl.format(name=q('fk_db_idx_tbl'))},
{fk_file.format(name=q('fk_db_idx_file'))}
);""",
            f"""CREATE TABLE {q('database_relations_table')} (
    {q('relation_id')} {pk},
    {q('store_id')} {bi} NULL,
    {q('relation_type')} VARCHAR(48) NULL,
    {q('from_table')} {txt} NULL,
    {q('from_column')} {txt} NULL,
    {q('to_table')} {txt} NULL,
    {q('to_column')} {txt} NULL,
    {q('value')} {txt} NULL,
    {q('method')} VARCHAR(32) NULL,
    {q('extra')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_store.format(name=q('fk_db_rel_store'))},
{fk_file.format(name=q('fk_db_rel_file'))}
);""",
            f"""CREATE TABLE {q('database_properties_table')} (
    {q('property_id')} {pk},
    {q('store_id')} {bi} NULL,
    {q('property_name')} {txt} NULL,
    {q('property_value')} {txt} NULL,
    {q('value_type')} VARCHAR(32) NULL,
    {q('group_name')} VARCHAR(64) NULL,
    {q('file_id')} {bi} NULL,
{fk_store.format(name=q('fk_db_prop_store'))},
{fk_file.format(name=q('fk_db_prop_file'))}
);""",
            f"""CREATE TABLE {q('database_file_index')} (
    {q('dbfi_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('entity_kind')} VARCHAR(32) NOT NULL,
    {q('entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_db_dbfi_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE
);""",
        ]

    def _data_ddl(self) -> List[str]:
        """DDL for the data-profile tables (DataAnalyzer output).

        Entity rows carry a nullable FK to ``file_details`` (ON DELETE SET NULL);
        child rows also carry a nullable FK to the parent ``data_datasets_table``
        (ON DELETE CASCADE); ``data_file_index`` FK to file_details CASCADEs.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        bl = self._type_bool()
        js = self._type_json()
        if self.dialect == "pgsql":
            rl = "DOUBLE PRECISION"
        elif self.dialect == "mysql":
            rl = "DOUBLE"
        else:
            rl = "REAL"
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_ds = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('dataset_id')})\n"
            f"        REFERENCES {q('data_datasets_table')} ({q('dataset_id')}) ON DELETE CASCADE"
        )

        return [
            "-- ========================================================",
            "-- 3c. Data Artifact Profiles (csv/parquet/json/tensors/media/docs)",
            "--     metadata & statistics only -- never the raw payload",
            "-- ========================================================",
            f"""CREATE TABLE {q('data_datasets_table')} (
    {q('dataset_id')} {pk},
    {q('dataset_name')} {txt} NULL,
    {q('category')} VARCHAR(48) NULL,
    {q('subcategory')} VARCHAR(64) NULL,
    {q('modality')} VARCHAR(32) NULL,
    {q('file_format')} VARCHAR(64) NULL,
    {q('format_family')} VARCHAR(64) NULL,
    {q('size_bytes')} {bi} NULL,
    {q('row_count')} {bi} NULL,
    {q('column_count')} {bi} NULL,
    {q('record_count')} {bi} NULL,
    {q('tensor_count')} {bi} NULL,
    {q('analysis_status')} VARCHAR(32) NULL,
    {q('notes')} {txt} NULL,
    {q('properties')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_data_ds_file'))}
);""",
            f"""CREATE TABLE {q('data_columns_table')} (
    {q('column_id')} {pk},
    {q('dataset_id')} {bi} NULL,
    {q('column_name')} {txt} NULL,
    {q('ordinal')} {bi} NULL,
    {q('data_type')} {txt} NULL,
    {q('inferred_type')} VARCHAR(32) NULL,
    {q('null_count')} {bi} NULL,
    {q('non_null_count')} {bi} NULL,
    {q('unique_count')} {bi} NULL,
    {q('min_value')} {txt} NULL,
    {q('max_value')} {txt} NULL,
    {q('mean_value')} {rl} NULL,
    {q('std_value')} {rl} NULL,
    {q('sample_values')} {js} NULL,
    {q('extra')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_ds.format(name=q('fk_data_col_ds'))},
{fk_file.format(name=q('fk_data_col_file'))}
);""",
            f"""CREATE TABLE {q('data_tensors_table')} (
    {q('tensor_id')} {pk},
    {q('dataset_id')} {bi} NULL,
    {q('tensor_name')} {txt} NULL,
    {q('dtype')} VARCHAR(48) NULL,
    {q('shape')} {js} NULL,
    {q('rank')} {bi} NULL,
    {q('num_elements')} {bi} NULL,
    {q('num_bytes')} {bi} NULL,
    {q('role')} VARCHAR(24) NULL,
    {q('layer_name')} {txt} NULL,
    {q('extra')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_ds.format(name=q('fk_data_tensor_ds'))},
{fk_file.format(name=q('fk_data_tensor_file'))}
);""",
            f"""CREATE TABLE {q('data_relations_table')} (
    {q('relation_id')} {pk},
    {q('dataset_id')} {bi} NULL,
    {q('relation_type')} VARCHAR(48) NULL,
    {q('left_column')} {txt} NULL,
    {q('right_column')} {txt} NULL,
    {q('value')} {rl} NULL,
    {q('method')} VARCHAR(32) NULL,
    {q('extra')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_ds.format(name=q('fk_data_rel_ds'))},
{fk_file.format(name=q('fk_data_rel_file'))}
);""",
            f"""CREATE TABLE {q('data_properties_table')} (
    {q('property_id')} {pk},
    {q('dataset_id')} {bi} NULL,
    {q('property_name')} {txt} NULL,
    {q('property_value')} {txt} NULL,
    {q('value_type')} VARCHAR(32) NULL,
    {q('group_name')} VARCHAR(64) NULL,
    {q('file_id')} {bi} NULL,
{fk_ds.format(name=q('fk_data_prop_ds'))},
{fk_file.format(name=q('fk_data_prop_file'))}
);""",
            f"""CREATE TABLE {q('data_model_layers_table')} (
    {q('model_layer_id')} {pk},
    {q('dataset_id')} {bi} NULL,
    {q('layer_name')} {txt} NULL,
    {q('layer_type')} VARCHAR(48) NULL,
    {q('ordinal')} {bi} NULL,
    {q('depth')} {bi} NULL,
    {q('tensor_count')} {bi} NULL,
    {q('param_tensor_count')} {bi} NULL,
    {q('buffer_tensor_count')} {bi} NULL,
    {q('total_parameters')} {bi} NULL,
    {q('total_buffer_elements')} {bi} NULL,
    {q('total_bytes')} {bi} NULL,
    {q('dtypes')} {js} NULL,
    {q('param_shapes')} {js} NULL,
    {q('roles')} {js} NULL,
    {q('file_id')} {bi} NULL,
{fk_ds.format(name=q('fk_data_mlayer_ds'))},
{fk_file.format(name=q('fk_data_mlayer_file'))}
);""",
            f"""CREATE TABLE {q('data_file_index')} (
    {q('dfi_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('entity_kind')} VARCHAR(32) NOT NULL,
    {q('entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_data_dfi_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE
);""",
        ]

    def _config_ddl(self) -> List[str]:
        """DDL for the configuration-file key/value tables (ConfigAnalyzer output).

        ``config_files_table`` has one row per parsed configuration file (nullable
        FK to ``file_details``, ON DELETE SET NULL). ``config_sections_table`` (top-
        level container groupings), ``config_value_keys_table`` (one node per tree
        position, self-referential ``config_value_parent_key_id``),
        ``config_values_table`` (one typed value per key, ``config_value_type`` =
        INT/FLOAT/STRING/BOOL/NULL/BYTES/DICT/LIST) and ``config_properties_table``
        (file-level metadata / forensic profile) each carry a FK to their
        ``config_files_table`` parent (ON DELETE CASCADE) plus nullable FKs back to
        their section / parent-key / file. ``config_file_index`` FK to file_details
        CASCADEs. Real per-extension parsing -- values & metadata only, no payload.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        bl = self._type_bool()
        js = self._type_json()
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_cfg = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('config_file_id')})\n"
            f"        REFERENCES {q('config_files_table')} ({q('config_file_id')}) ON DELETE CASCADE"
        )
        fk_sec = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('section_id')})\n"
            f"        REFERENCES {q('config_sections_table')} ({q('section_id')}) ON DELETE SET NULL"
        )
        fk_key = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('config_value_key_id')})\n"
            f"        REFERENCES {q('config_value_keys_table')} ({q('config_value_key_id')}) ON DELETE CASCADE"
        )
        fk_parent_key = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('config_value_parent_key_id')})\n"
            f"        REFERENCES {q('config_value_keys_table')} ({q('config_value_key_id')}) ON DELETE SET NULL"
        )

        return [
            "-- ========================================================",
            "-- 3c2. Configuration Files (ini/yaml/json/xml/plist/directive/...)",
            "--      normalized key/value tree -- one typed value per key,",
            "--      sections group top-level containers; values & metadata only",
            "-- ========================================================",
            f"""CREATE TABLE {q('config_files_table')} (
    {q('config_file_id')} {pk},
    {q('file_name')} {txt} NULL,
    {q('extension')} VARCHAR(64) NULL,
    {q('syntax_family')} VARCHAR(48) NULL,
    {q('parse_engine')} VARCHAR(48) NULL,
    {q('format_label')} {txt} NULL,
    {q('detected_via')} VARCHAR(24) NULL,
    {q('format_class')} VARCHAR(16) NULL,
    {q('size_bytes')} {bi} NULL,
    {q('encoding')} VARCHAR(32) NULL,
    {q('root_type')} VARCHAR(16) NULL,
    {q('section_count')} {bi} NULL,
    {q('key_count')} {bi} NULL,
    {q('value_count')} {bi} NULL,
    {q('property_count')} {bi} NULL,
    {q('max_depth')} {bi} NULL,
    {q('analysis_status')} VARCHAR(32) NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_config_file_file'))}
);""",
            f"""CREATE TABLE {q('config_sections_table')} (
    {q('section_id')} {pk},
    {q('config_file_id')} {bi} NULL,
    {q('section_name')} {txt} NULL,
    {q('section_path')} {txt} NULL,
    {q('section_type')} VARCHAR(16) NULL,
    {q('parent_section_id')} {bi} NULL,
    {q('key_count')} {bi} NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_cfg.format(name=q('fk_config_sec_cfg'))},
{fk_file.format(name=q('fk_config_sec_file'))}
);""",
            f"""CREATE TABLE {q('config_value_keys_table')} (
    {q('config_value_key_id')} {pk},
    {q('config_file_id')} {bi} NULL,
    {q('section_id')} {bi} NULL,
    {q('config_value_key_name')} {txt} NULL,
    {q('key_path')} {txt} NULL,
    {q('config_value_parent_key_id')} {bi} NULL,
    {q('depth')} {bi} NULL,
    {q('node_type')} VARCHAR(16) NULL,
    {q('child_count')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_cfg.format(name=q('fk_config_key_cfg'))},
{fk_sec.format(name=q('fk_config_key_sec'))},
{fk_parent_key.format(name=q('fk_config_key_parent'))},
{fk_file.format(name=q('fk_config_key_file'))}
);""",
            f"""CREATE TABLE {q('config_values_table')} (
    {q('config_value_id')} {pk},
    {q('config_value_key_id')} {bi} NULL,
    {q('config_file_id')} {bi} NULL,
    {q('section_id')} {bi} NULL,
    {q('config_value_parent_key_id')} {bi} NULL,
    {q('config_value_type')} VARCHAR(16) NULL,
    {q('scalar_value')} {txt} NULL,
    {q('list_index')} {bi} NULL,
    {q('is_leaf')} {bl},
    {q('file_id')} {bi} NULL,
{fk_key.format(name=q('fk_config_val_key'))},
{fk_cfg.format(name=q('fk_config_val_cfg'))},
{fk_sec.format(name=q('fk_config_val_sec'))},
{fk_parent_key.format(name=q('fk_config_val_parent'))},
{fk_file.format(name=q('fk_config_val_file'))}
);""",
            f"""CREATE TABLE {q('config_properties_table')} (
    {q('property_id')} {pk},
    {q('config_file_id')} {bi} NULL,
    {q('property_name')} {txt} NULL,
    {q('property_value')} {txt} NULL,
    {q('value_type')} VARCHAR(32) NULL,
    {q('group_name')} VARCHAR(128) NULL,
    {q('file_id')} {bi} NULL,
{fk_cfg.format(name=q('fk_config_prop_cfg'))},
{fk_file.format(name=q('fk_config_prop_file'))}
);""",
            f"""CREATE TABLE {q('config_file_index')} (
    {q('cfi_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('entity_kind')} VARCHAR(32) NOT NULL,
    {q('entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_config_cfi_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE
);""",
        ]

    def _text_ddl(self) -> List[str]:
        """DDL for the text-record tables (TextualAnalyzer output).

        ``text_files_table`` has one row per parsed text-record file (nullable FK
        to ``file_details``, ON DELETE SET NULL). ``text_sections_table`` (top-
        level groupings -- caption tracks, log streams, man-page blocks, ...),
        ``text_records_table`` (one entry inside a section -- a cue, a log line, a
        checksum, a G-code command, a JSON object, ...) and ``text_fields_table``
        (one typed name/value pair per record) form the ``document -> sections ->
        records -> fields`` tree; ``text_properties_table`` carries file-level
        metadata / forensic profile. Each child FKs to its ``text_files_table``
        parent (ON DELETE CASCADE) plus nullable FKs back to its section / record
        / file. ``text_file_index`` FK to file_details CASCADEs. Real per-
        extension parsing -- values & metadata only, no payload.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_txt = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('text_file_id')})\n"
            f"        REFERENCES {q('text_files_table')} ({q('text_file_id')}) ON DELETE CASCADE"
        )
        fk_sec = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('text_section_id')})\n"
            f"        REFERENCES {q('text_sections_table')} ({q('text_section_id')}) ON DELETE SET NULL"
        )
        fk_rec = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('text_record_id')})\n"
            f"        REFERENCES {q('text_records_table')} ({q('text_record_id')}) ON DELETE CASCADE"
        )

        return [
            "-- ========================================================",
            "-- 3c3. Text-record Files (data_text/text/log/documentation/",
            "--      template/scientific_data/subtitle) -- normalized",
            "--      document->sections->records->fields; values & metadata only",
            "-- ========================================================",
            f"""CREATE TABLE {q('text_files_table')} (
    {q('text_file_id')} {pk},
    {q('file_name')} {txt} NULL,
    {q('extension')} VARCHAR(64) NULL,
    {q('content_kind')} VARCHAR(32) NULL,
    {q('syntax_family')} VARCHAR(48) NULL,
    {q('parse_engine')} VARCHAR(48) NULL,
    {q('format_label')} {txt} NULL,
    {q('detected_via')} VARCHAR(24) NULL,
    {q('format_class')} VARCHAR(16) NULL,
    {q('size_bytes')} {bi} NULL,
    {q('encoding')} VARCHAR(32) NULL,
    {q('line_count')} {bi} NULL,
    {q('section_count')} {bi} NULL,
    {q('record_count')} {bi} NULL,
    {q('field_count')} {bi} NULL,
    {q('property_count')} {bi} NULL,
    {q('analysis_status')} VARCHAR(32) NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_text_file_file'))}
);""",
            f"""CREATE TABLE {q('text_sections_table')} (
    {q('text_section_id')} {pk},
    {q('text_file_id')} {bi} NULL,
    {q('section_name')} {txt} NULL,
    {q('section_path')} {txt} NULL,
    {q('section_type')} VARCHAR(32) NULL,
    {q('ordinal')} {bi} NULL,
    {q('record_count')} {bi} NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_txt.format(name=q('fk_text_sec_txt'))},
{fk_file.format(name=q('fk_text_sec_file'))}
);""",
            f"""CREATE TABLE {q('text_records_table')} (
    {q('text_record_id')} {pk},
    {q('text_file_id')} {bi} NULL,
    {q('text_section_id')} {bi} NULL,
    {q('record_index')} {bi} NULL,
    {q('record_type')} VARCHAR(48) NULL,
    {q('record_label')} {txt} NULL,
    {q('start_line')} {bi} NULL,
    {q('end_line')} {bi} NULL,
    {q('field_count')} {bi} NULL,
    {q('text_preview')} {txt} NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_txt.format(name=q('fk_text_rec_txt'))},
{fk_sec.format(name=q('fk_text_rec_sec'))},
{fk_file.format(name=q('fk_text_rec_file'))}
);""",
            f"""CREATE TABLE {q('text_fields_table')} (
    {q('text_field_id')} {pk},
    {q('text_record_id')} {bi} NULL,
    {q('text_file_id')} {bi} NULL,
    {q('text_section_id')} {bi} NULL,
    {q('field_name')} {txt} NULL,
    {q('field_key')} {txt} NULL,
    {q('field_type')} VARCHAR(16) NULL,
    {q('field_value')} {txt} NULL,
    {q('ordinal')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_rec.format(name=q('fk_text_fld_rec'))},
{fk_txt.format(name=q('fk_text_fld_txt'))},
{fk_sec.format(name=q('fk_text_fld_sec'))},
{fk_file.format(name=q('fk_text_fld_file'))}
);""",
            f"""CREATE TABLE {q('text_properties_table')} (
    {q('property_id')} {pk},
    {q('text_file_id')} {bi} NULL,
    {q('property_name')} {txt} NULL,
    {q('property_value')} {txt} NULL,
    {q('value_type')} VARCHAR(32) NULL,
    {q('group_name')} VARCHAR(128) NULL,
    {q('file_id')} {bi} NULL,
{fk_txt.format(name=q('fk_text_prop_txt'))},
{fk_file.format(name=q('fk_text_prop_file'))}
);""",
            f"""CREATE TABLE {q('text_file_index')} (
    {q('tfi_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('entity_kind')} VARCHAR(32) NOT NULL,
    {q('entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_text_tfi_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE
);""",
        ]

    def _document_ddl(self) -> List[str]:
        """DDL for the document tables (DocumentAnalyzer output).

        ``document_files_table`` has one row per parsed document file (nullable FK
        to ``file_details``, ON DELETE SET NULL). ``document_sections_table`` (top-
        level groupings -- an AppCache block, a SQL statement list, a Makefile's
        variables/rules/directives, a PEM block set, a notebook's cells, a diff's
        per-file hunks, ...), ``document_records_table`` (one entry inside a
        section -- a manifest entry, a query statement, a make rule, an SSH key, a
        notebook cell, a diff hunk, a copyright line, ...) and
        ``document_fields_table`` (one typed name/value pair per record) form the
        ``document -> sections -> records -> fields`` tree;
        ``document_properties_table`` carries file-level metadata / forensic
        profile. Each child FKs to its ``document_files_table`` parent (ON DELETE
        CASCADE) plus nullable FKs back to its section / record / file.
        ``document_file_index`` FK to file_details CASCADEs. Real per-extension
        parsing -- values & metadata only, no payload; credential material never
        decoded into its secret content.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_doc = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('document_file_id')})\n"
            f"        REFERENCES {q('document_files_table')} ({q('document_file_id')}) ON DELETE CASCADE"
        )
        fk_sec = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('document_section_id')})\n"
            f"        REFERENCES {q('document_sections_table')} ({q('document_section_id')}) ON DELETE SET NULL"
        )
        fk_rec = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('document_record_id')})\n"
            f"        REFERENCES {q('document_records_table')} ({q('document_record_id')}) ON DELETE CASCADE"
        )

        return [
            "-- ========================================================",
            "-- 3c4. Document Files (manifest/query/makefile/certificate_text/",
            "--      notebook/document/license/diff) -- normalized",
            "--      document->sections->records->fields; values & metadata only",
            "-- ========================================================",
            f"""CREATE TABLE {q('document_files_table')} (
    {q('document_file_id')} {pk},
    {q('file_name')} {txt} NULL,
    {q('extension')} VARCHAR(64) NULL,
    {q('content_kind')} VARCHAR(32) NULL,
    {q('syntax_family')} VARCHAR(48) NULL,
    {q('parse_engine')} VARCHAR(48) NULL,
    {q('format_label')} {txt} NULL,
    {q('detected_via')} VARCHAR(24) NULL,
    {q('format_class')} VARCHAR(16) NULL,
    {q('size_bytes')} {bi} NULL,
    {q('encoding')} VARCHAR(32) NULL,
    {q('line_count')} {bi} NULL,
    {q('section_count')} {bi} NULL,
    {q('record_count')} {bi} NULL,
    {q('field_count')} {bi} NULL,
    {q('property_count')} {bi} NULL,
    {q('analysis_status')} VARCHAR(32) NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_doc_file_file'))}
);""",
            f"""CREATE TABLE {q('document_sections_table')} (
    {q('document_section_id')} {pk},
    {q('document_file_id')} {bi} NULL,
    {q('section_name')} {txt} NULL,
    {q('section_path')} {txt} NULL,
    {q('section_type')} VARCHAR(32) NULL,
    {q('ordinal')} {bi} NULL,
    {q('record_count')} {bi} NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_doc.format(name=q('fk_doc_sec_doc'))},
{fk_file.format(name=q('fk_doc_sec_file'))}
);""",
            f"""CREATE TABLE {q('document_records_table')} (
    {q('document_record_id')} {pk},
    {q('document_file_id')} {bi} NULL,
    {q('document_section_id')} {bi} NULL,
    {q('record_index')} {bi} NULL,
    {q('record_type')} VARCHAR(48) NULL,
    {q('record_label')} {txt} NULL,
    {q('start_line')} {bi} NULL,
    {q('end_line')} {bi} NULL,
    {q('field_count')} {bi} NULL,
    {q('text_preview')} {txt} NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_doc.format(name=q('fk_doc_rec_doc'))},
{fk_sec.format(name=q('fk_doc_rec_sec'))},
{fk_file.format(name=q('fk_doc_rec_file'))}
);""",
            f"""CREATE TABLE {q('document_fields_table')} (
    {q('document_field_id')} {pk},
    {q('document_record_id')} {bi} NULL,
    {q('document_file_id')} {bi} NULL,
    {q('document_section_id')} {bi} NULL,
    {q('field_name')} {txt} NULL,
    {q('field_key')} {txt} NULL,
    {q('field_type')} VARCHAR(16) NULL,
    {q('field_value')} {txt} NULL,
    {q('ordinal')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_rec.format(name=q('fk_doc_fld_rec'))},
{fk_doc.format(name=q('fk_doc_fld_doc'))},
{fk_sec.format(name=q('fk_doc_fld_sec'))},
{fk_file.format(name=q('fk_doc_fld_file'))}
);""",
            f"""CREATE TABLE {q('document_properties_table')} (
    {q('property_id')} {pk},
    {q('document_file_id')} {bi} NULL,
    {q('property_name')} {txt} NULL,
    {q('property_value')} {txt} NULL,
    {q('value_type')} VARCHAR(32) NULL,
    {q('group_name')} VARCHAR(128) NULL,
    {q('file_id')} {bi} NULL,
{fk_doc.format(name=q('fk_doc_prop_doc'))},
{fk_file.format(name=q('fk_doc_prop_file'))}
);""",
            f"""CREATE TABLE {q('document_file_index')} (
    {q('dfi_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('entity_kind')} VARCHAR(32) NOT NULL,
    {q('entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_doc_dfi_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE
);""",
        ]

    def _misc_ddl(self) -> List[str]:
        """DDL for the misc tables (MiscAnalyzer output -- terminal plane).

        Structurally identical to the document layer with a ``misc_`` prefix:
        ``misc_files_table`` has one row per parsed misc file (nullable FK to
        ``file_details``, ON DELETE SET NULL); ``misc_sections_table`` /
        ``misc_records_table`` / ``misc_fields_table`` form the
        ``document -> sections -> records -> fields`` tree (a QSS rule list, an
        OpenShot clip/file/effect list, a Camtasia source/track list, a pg_dump
        table/COPY/statement list); ``misc_properties_table`` carries file-level
        metadata / forensic profile. Each child FKs to its ``misc_files_table``
        parent (ON DELETE CASCADE) plus nullable FKs back to its section / record
        / file. ``misc_file_index`` FK to file_details CASCADEs. Real
        per-extension parsing -- values & metadata only, no payload.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_misc = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('misc_file_id')})\n"
            f"        REFERENCES {q('misc_files_table')} ({q('misc_file_id')}) ON DELETE CASCADE"
        )
        fk_sec = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('misc_section_id')})\n"
            f"        REFERENCES {q('misc_sections_table')} ({q('misc_section_id')}) ON DELETE SET NULL"
        )
        fk_rec = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('misc_record_id')})\n"
            f"        REFERENCES {q('misc_records_table')} ({q('misc_record_id')}) ON DELETE CASCADE"
        )

        return [
            "-- ========================================================",
            "-- 3c5. Misc Files (qss/osp/tscproj/pgdump) -- terminal plane;",
            "--      normalized document->sections->records->fields;",
            "--      values & metadata only",
            "-- ========================================================",
            f"""CREATE TABLE {q('misc_files_table')} (
    {q('misc_file_id')} {pk},
    {q('file_name')} {txt} NULL,
    {q('extension')} VARCHAR(64) NULL,
    {q('content_kind')} VARCHAR(32) NULL,
    {q('syntax_family')} VARCHAR(48) NULL,
    {q('parse_engine')} VARCHAR(48) NULL,
    {q('format_label')} {txt} NULL,
    {q('detected_via')} VARCHAR(24) NULL,
    {q('format_class')} VARCHAR(16) NULL,
    {q('size_bytes')} {bi} NULL,
    {q('encoding')} VARCHAR(32) NULL,
    {q('line_count')} {bi} NULL,
    {q('section_count')} {bi} NULL,
    {q('record_count')} {bi} NULL,
    {q('field_count')} {bi} NULL,
    {q('property_count')} {bi} NULL,
    {q('analysis_status')} VARCHAR(32) NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_misc_file_file'))}
);""",
            f"""CREATE TABLE {q('misc_sections_table')} (
    {q('misc_section_id')} {pk},
    {q('misc_file_id')} {bi} NULL,
    {q('section_name')} {txt} NULL,
    {q('section_path')} {txt} NULL,
    {q('section_type')} VARCHAR(32) NULL,
    {q('ordinal')} {bi} NULL,
    {q('record_count')} {bi} NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_misc.format(name=q('fk_misc_sec_misc'))},
{fk_file.format(name=q('fk_misc_sec_file'))}
);""",
            f"""CREATE TABLE {q('misc_records_table')} (
    {q('misc_record_id')} {pk},
    {q('misc_file_id')} {bi} NULL,
    {q('misc_section_id')} {bi} NULL,
    {q('record_index')} {bi} NULL,
    {q('record_type')} VARCHAR(48) NULL,
    {q('record_label')} {txt} NULL,
    {q('start_line')} {bi} NULL,
    {q('end_line')} {bi} NULL,
    {q('field_count')} {bi} NULL,
    {q('text_preview')} {txt} NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_misc.format(name=q('fk_misc_rec_misc'))},
{fk_sec.format(name=q('fk_misc_rec_sec'))},
{fk_file.format(name=q('fk_misc_rec_file'))}
);""",
            f"""CREATE TABLE {q('misc_fields_table')} (
    {q('misc_field_id')} {pk},
    {q('misc_record_id')} {bi} NULL,
    {q('misc_file_id')} {bi} NULL,
    {q('misc_section_id')} {bi} NULL,
    {q('field_name')} {txt} NULL,
    {q('field_key')} {txt} NULL,
    {q('field_type')} VARCHAR(16) NULL,
    {q('field_value')} {txt} NULL,
    {q('ordinal')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_rec.format(name=q('fk_misc_fld_rec'))},
{fk_misc.format(name=q('fk_misc_fld_misc'))},
{fk_sec.format(name=q('fk_misc_fld_sec'))},
{fk_file.format(name=q('fk_misc_fld_file'))}
);""",
            f"""CREATE TABLE {q('misc_properties_table')} (
    {q('property_id')} {pk},
    {q('misc_file_id')} {bi} NULL,
    {q('property_name')} {txt} NULL,
    {q('property_value')} {txt} NULL,
    {q('value_type')} VARCHAR(32) NULL,
    {q('group_name')} VARCHAR(128) NULL,
    {q('file_id')} {bi} NULL,
{fk_misc.format(name=q('fk_misc_prop_misc'))},
{fk_file.format(name=q('fk_misc_prop_file'))}
);""",
            f"""CREATE TABLE {q('misc_file_index')} (
    {q('mfi_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('entity_kind')} VARCHAR(32) NOT NULL,
    {q('entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_misc_mfi_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE
);""",
        ]

    def _markup_ddl(self) -> List[str]:
        """DDL for the markup tables (MarkupAnalyzer output).

        ``markup_files_table`` has one row per parsed markup document (nullable
        FK to ``file_details``, ON DELETE SET NULL). ``markup_elements_table``
        (one row per distinct tag/element with its within-tag metrics),
        ``markup_attributes_table`` (one row per distinct element/attribute pair;
        FK to its element parent), ``markup_namespaces_table`` (XML namespace
        declarations), ``markup_sections_table`` (structural outline -- the XML
        root's children or a non-XML markup's headings) and
        ``markup_properties_table`` (document-level facts / forensic profile) each
        FK to their ``markup_files_table`` parent (ON DELETE CASCADE) plus a
        nullable FK back to ``file_details``. ``markup_file_index`` FK to
        file_details CASCADEs. Real per-extension parsing -- names, counts,
        metrics & short samples only, no payload.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_mk = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('markup_file_id')})\n"
            f"        REFERENCES {q('markup_files_table')} ({q('markup_file_id')}) ON DELETE CASCADE"
        )
        fk_el = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('markup_element_id')})\n"
            f"        REFERENCES {q('markup_elements_table')} ({q('markup_element_id')}) ON DELETE SET NULL"
        )

        return [
            "-- ========================================================",
            "-- 3c4. Markup Files (HTML/XHTML, ~200 XML vocabularies, OFX SGML,",
            "--      wiki/gemtext/roff/typst/MIF/markdown/lightweight) -- normalized",
            "--      document->elements(+attributes+namespaces)->sections+properties;",
            "--      which tags/sections are present + within-tag metrics, no payload",
            "-- ========================================================",
            f"""CREATE TABLE {q('markup_files_table')} (
    {q('markup_file_id')} {pk},
    {q('file_name')} {txt} NULL,
    {q('extension')} VARCHAR(64) NULL,
    {q('content_kind')} VARCHAR(32) NULL,
    {q('syntax_family')} VARCHAR(64) NULL,
    {q('markup_language')} VARCHAR(32) NULL,
    {q('dialect_profile')} VARCHAR(64) NULL,
    {q('parse_engine')} VARCHAR(32) NULL,
    {q('format_label')} {txt} NULL,
    {q('detected_via')} VARCHAR(24) NULL,
    {q('format_class')} VARCHAR(16) NULL,
    {q('size_bytes')} {bi} NULL,
    {q('encoding')} VARCHAR(32) NULL,
    {q('line_count')} {bi} NULL,
    {q('well_formed')} {bi} NULL,
    {q('root_element')} {txt} NULL,
    {q('namespace_count')} {bi} NULL,
    {q('element_count')} {bi} NULL,
    {q('distinct_element_count')} {bi} NULL,
    {q('attribute_count')} {bi} NULL,
    {q('distinct_attribute_count')} {bi} NULL,
    {q('max_depth')} {bi} NULL,
    {q('comment_count')} {bi} NULL,
    {q('pi_count')} {bi} NULL,
    {q('cdata_count')} {bi} NULL,
    {q('text_length')} {bi} NULL,
    {q('section_count')} {bi} NULL,
    {q('property_count')} {bi} NULL,
    {q('analysis_status')} VARCHAR(32) NULL,
    {q('notes')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_file.format(name=q('fk_markup_file_file'))}
);""",
            f"""CREATE TABLE {q('markup_elements_table')} (
    {q('markup_element_id')} {pk},
    {q('markup_file_id')} {bi} NULL,
    {q('tag_name')} {txt} NULL,
    {q('qualified_name')} {txt} NULL,
    {q('namespace_prefix')} VARCHAR(64) NULL,
    {q('namespace_uri')} {txt} NULL,
    {q('occurrence_count')} {bi} NULL,
    {q('min_depth')} {bi} NULL,
    {q('max_depth')} {bi} NULL,
    {q('total_child_count')} {bi} NULL,
    {q('max_children')} {bi} NULL,
    {q('leaf_count')} {bi} NULL,
    {q('text_bearing_count')} {bi} NULL,
    {q('total_text_length')} {bi} NULL,
    {q('distinct_attribute_count')} {bi} NULL,
    {q('attribute_names')} {txt} NULL,
    {q('sample_text')} {txt} NULL,
    {q('is_root')} {bi} NULL,
    {q('ordinal')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_mk.format(name=q('fk_markup_el_mk'))},
{fk_file.format(name=q('fk_markup_el_file'))}
);""",
            f"""CREATE TABLE {q('markup_attributes_table')} (
    {q('markup_attribute_id')} {pk},
    {q('markup_file_id')} {bi} NULL,
    {q('markup_element_id')} {bi} NULL,
    {q('element_tag')} {txt} NULL,
    {q('attribute_name')} {txt} NULL,
    {q('namespace_prefix')} VARCHAR(64) NULL,
    {q('occurrence_count')} {bi} NULL,
    {q('distinct_value_count')} {bi} NULL,
    {q('value_type')} VARCHAR(16) NULL,
    {q('sample_value')} {txt} NULL,
    {q('min_length')} {bi} NULL,
    {q('max_length')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_mk.format(name=q('fk_markup_attr_mk'))},
{fk_el.format(name=q('fk_markup_attr_el'))},
{fk_file.format(name=q('fk_markup_attr_file'))}
);""",
            f"""CREATE TABLE {q('markup_namespaces_table')} (
    {q('markup_namespace_id')} {pk},
    {q('markup_file_id')} {bi} NULL,
    {q('prefix')} VARCHAR(64) NULL,
    {q('uri')} {txt} NULL,
    {q('is_default')} {bi} NULL,
    {q('element_usage_count')} {bi} NULL,
    {q('file_id')} {bi} NULL,
{fk_mk.format(name=q('fk_markup_ns_mk'))},
{fk_file.format(name=q('fk_markup_ns_file'))}
);""",
            f"""CREATE TABLE {q('markup_sections_table')} (
    {q('markup_section_id')} {pk},
    {q('markup_file_id')} {bi} NULL,
    {q('section_name')} {txt} NULL,
    {q('section_type')} VARCHAR(32) NULL,
    {q('section_path')} {txt} NULL,
    {q('depth')} {bi} NULL,
    {q('ordinal')} {bi} NULL,
    {q('element_tag')} {txt} NULL,
    {q('child_count')} {bi} NULL,
    {q('text_length')} {bi} NULL,
    {q('title')} {txt} NULL,
    {q('file_id')} {bi} NULL,
{fk_mk.format(name=q('fk_markup_sec_mk'))},
{fk_file.format(name=q('fk_markup_sec_file'))}
);""",
            f"""CREATE TABLE {q('markup_properties_table')} (
    {q('property_id')} {pk},
    {q('markup_file_id')} {bi} NULL,
    {q('property_name')} {txt} NULL,
    {q('property_value')} {txt} NULL,
    {q('value_type')} VARCHAR(32) NULL,
    {q('group_name')} VARCHAR(128) NULL,
    {q('file_id')} {bi} NULL,
{fk_mk.format(name=q('fk_markup_prop_mk'))},
{fk_file.format(name=q('fk_markup_prop_file'))}
);""",
            f"""CREATE TABLE {q('markup_file_index')} (
    {q('mfi_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('entity_kind')} VARCHAR(32) NOT NULL,
    {q('entity_id')} {bi} NOT NULL,
    CONSTRAINT {q('fk_markup_mfi_file')} FOREIGN KEY ({q('file_id')})
        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE CASCADE
);""",
        ]

    def _archive_ddl(self) -> List[str]:
        """DDL for the archive-container census tables (ArchiveAnalyzer output).

        ``archive_index`` has one row per container file (nullable FK to
        ``file_details``, ON DELETE SET NULL; ``sub_database`` points at the nested
        per-archive database). ``archive_members`` has one row per member, FK to its
        ``archive_index`` parent (ON DELETE CASCADE) and a nullable FK to the
        container's ``file_details`` row (ON DELETE SET NULL).
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        bl = self._type_bool()
        js = self._type_json()
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )

        return [
            "-- ========================================================",
            "-- 3d. Archive / Container Census (zip/tar/compression)",
            "--     member listing + link to the nested per-archive database",
            "-- ========================================================",
            f"""CREATE TABLE {q('archive_index')} (
    {q('archive_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('archive_name')} {txt} NULL,
    {q('archive_format')} VARCHAR(32) NULL,
    {q('member_count')} {bi} NULL,
    {q('compressed_size')} {bi} NULL,
    {q('extracted_size')} {bi} NULL,
    {q('extractable')} {bl},
    {q('extraction_status')} VARCHAR(32) NULL,
    {q('sub_database')} {txt} NULL,
    {q('sub_file_count')} {bi} NULL,
    {q('sub_shard_summary')} {js} NULL,
    {q('depth')} {bi} NULL,
    {q('notes')} {txt} NULL,
{fk_file.format(name=q('fk_archive_idx_file'))}
);""",
            f"""CREATE TABLE {q('archive_members')} (
    {q('member_id')} {pk},
    {q('archive_id')} {bi} NULL,
    {q('member_path')} {txt} NULL,
    {q('member_kind')} VARCHAR(16) NULL,
    {q('member_size')} {bi} NULL,
    {q('compressed_size')} {bi} NULL,
    {q('modified')} VARCHAR(32) NULL,
    {q('analyzer_class')} VARCHAR(16) NULL,
    {q('file_id')} {bi} NULL,
    CONSTRAINT {q('fk_archive_mem_arc')} FOREIGN KEY ({q('archive_id')})
        REFERENCES {q('archive_index')} ({q('archive_id')}) ON DELETE CASCADE,
{fk_file.format(name=q('fk_archive_mem_file'))}
);""",
        ]

    def _binary_ddl(self) -> List[str]:
        """DDL for the machine-code / executable analysis tables (MachineCodeAnalyzer).

        ``binary_index`` has one row per binary (nullable FK to ``file_details``,
        ON DELETE SET NULL). ``binary_sections`` / ``binary_symbols`` /
        ``binary_imports`` / ``binary_properties`` each hang off their
        ``binary_index`` parent (ON DELETE CASCADE). All values are structural
        metadata & forensic statistics; no section/segment payload is ever stored.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        bl = self._type_bool()
        if self.dialect == "pgsql":
            rl = "DOUBLE PRECISION"
        elif self.dialect == "mysql":
            rl = "DOUBLE"
        else:
            rl = "REAL"
        fk_file = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_bin = (
            f"    CONSTRAINT {{name}} FOREIGN KEY ({q('binary_id')})\n"
            f"        REFERENCES {q('binary_index')} ({q('binary_id')}) ON DELETE CASCADE"
        )

        return [
            "-- ========================================================",
            "-- 3e. Machine-code / Executable Analysis",
            "--     ELF/PE/Mach-O/.class/.pyc/WASM/DEX/ar/LLVM/UF2/OLE structure",
            "--     + format-agnostic forensic metrics (metadata only)",
            "-- ========================================================",
            f"""CREATE TABLE {q('binary_index')} (
    {q('binary_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('file_name')} {txt} NULL,
    {q('binary_format')} VARCHAR(64) NULL,
    {q('format_family')} VARCHAR(32) NULL,
    {q('category')} VARCHAR(48) NULL,
    {q('subcategory')} VARCHAR(64) NULL,
    {q('architecture')} VARCHAR(32) NULL,
    {q('bitness')} {bi} NULL,
    {q('endianness')} VARCHAR(8) NULL,
    {q('entry_point')} {bi} NULL,
    {q('is_stripped')} {bl},
    {q('is_dynamic')} {bl},
    {q('is_pic')} {bl},
    {q('section_count')} {bi} NULL,
    {q('symbol_count')} {bi} NULL,
    {q('import_count')} {bi} NULL,
    {q('export_count')} {bi} NULL,
    {q('sha256')} VARCHAR(64) NULL,
    {q('size')} {bi} NULL,
    {q('entropy')} {rl} NULL,
    {q('detected_via')} VARCHAR(16) NULL,
    {q('notes')} {txt} NULL,
    {q('error')} {txt} NULL,
{fk_file.format(name=q('fk_binary_idx_file'))}
);""",
            f"""CREATE TABLE {q('binary_sections')} (
    {q('section_id')} {pk},
    {q('binary_id')} {bi} NULL,
    {q('ordinal')} {bi} NULL,
    {q('name')} {txt} NULL,
    {q('sec_type')} VARCHAR(32) NULL,
    {q('virtual_address')} {bi} NULL,
    {q('file_offset')} {bi} NULL,
    {q('size')} {bi} NULL,
    {q('flags')} VARCHAR(64) NULL,
    {q('entropy')} {rl} NULL,
{fk_bin.format(name=q('fk_binary_sec_bin'))}
);""",
            f"""CREATE TABLE {q('binary_symbols')} (
    {q('symbol_id')} {pk},
    {q('binary_id')} {bi} NULL,
    {q('name')} {txt} NULL,
    {q('sym_kind')} VARCHAR(32) NULL,
    {q('binding')} VARCHAR(16) NULL,
    {q('address')} {bi} NULL,
    {q('size')} {bi} NULL,
    {q('section')} VARCHAR(32) NULL,
    {q('is_import')} {bl},
    {q('is_export')} {bl},
    {q('library')} {txt} NULL,
{fk_bin.format(name=q('fk_binary_sym_bin'))}
);""",
            f"""CREATE TABLE {q('binary_imports')} (
    {q('import_id')} {pk},
    {q('binary_id')} {bi} NULL,
    {q('library')} {txt} NULL,
    {q('symbol')} {txt} NULL,
    {q('kind')} VARCHAR(32) NULL,
{fk_bin.format(name=q('fk_binary_imp_bin'))}
);""",
            f"""CREATE TABLE {q('binary_properties')} (
    {q('property_id')} {pk},
    {q('binary_id')} {bi} NULL,
    {q('prop_group')} VARCHAR(32) NULL,
    {q('prop_name')} VARCHAR(64) NULL,
    {q('prop_value')} {txt} NULL,
{fk_bin.format(name=q('fk_binary_prop_bin'))}
);""",
        ]

    def _conversions_ddl(self) -> List[str]:
        """DDL for the format-conversion outcome table (FormatConverter output).

        ``format_conversions`` has one row per opaque/legacy/proprietary file for
        which a *renderable* transcode was attempted, with a nullable FK to
        ``file_details`` (ON DELETE SET NULL). Only the outcome metadata is stored
        (status / target / method / tool / output path & size); the rendered
        artifact itself lives on disk, and the source payload is never persisted.
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        fk_file = (
            f"    CONSTRAINT {q('fk_conv_file')} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        return [
            "-- ========================================================",
            "-- 3f. Format Conversions (opaque/legacy -> renderable)",
            "--     PNG/WAV/MP4/PDF/TXT transcode outcomes (metadata only)",
            "-- ========================================================",
            f"""CREATE TABLE {q('format_conversions')} (
    {q('conversion_id')} {pk},
    {q('file_id')} {bi} NULL,
    {q('source_file')} {txt} NULL,
    {q('source_path')} {txt} NULL,
    {q('source_ext')} VARCHAR(32) NULL,
    {q('target_format')} VARCHAR(16) NULL,
    {q('status')} VARCHAR(24) NULL,
    {q('method')} VARCHAR(64) NULL,
    {q('tool')} VARCHAR(32) NULL,
    {q('output_file')} {txt} NULL,
    {q('output_size')} {bi} NULL,
    {q('detail')} {txt} NULL,
{fk_file}
);""",
        ]

    def _analysis_ddl(self) -> List[str]:
        """DDL for the per-artifact deep-analysis table (TextAnalyzer output).

        ``conversion_analysis`` has one row per FormatConverter outcome: for a
        ``converted`` artifact it carries the structural analysis of the rendered
        file (PNG/WAV/MP4/PDF/TXT/GIF/HTML), and for a non-converted outcome it
        records ``status='not_analyzed'``, so the table is a faithful 1:1 companion
        to ``format_conversions``. The variable-shape per-format metrics are stored
        as a JSON string in ``metrics_json``; the flat provenance/summary columns
        are always populated. Nullable FKs: ``file_id`` -> ``file_details`` and
        ``conversion_id`` -> ``format_conversions`` (both ON DELETE SET NULL).
        """
        q = self._quote
        pk = self._type_pk()
        bi = self._type_int()
        txt = self._type_text()
        fk_file = (
            f"    CONSTRAINT {q('fk_canalysis_file')} FOREIGN KEY ({q('file_id')})\n"
            f"        REFERENCES {q('file_details')} ({q('file_id')}) ON DELETE SET NULL"
        )
        fk_conv = (
            f"    CONSTRAINT {q('fk_canalysis_conv')} FOREIGN KEY ({q('conversion_id')})\n"
            f"        REFERENCES {q('format_conversions')} ({q('conversion_id')}) ON DELETE SET NULL"
        )
        return [
            "-- ========================================================",
            "-- 3g. Conversion Analysis (deep parse of rendered artifacts)",
            "--     PNG/WAV/MP4/PDF/TXT/GIF/HTML structural metrics (JSON)",
            "-- ========================================================",
            f"""CREATE TABLE {q('conversion_analysis')} (
    {q('analysis_id')} {pk},
    {q('conversion_id')} {bi} NULL,
    {q('file_id')} {bi} NULL,
    {q('source_file')} {txt} NULL,
    {q('source_ext')} VARCHAR(32) NULL,
    {q('artifact_file')} {txt} NULL,
    {q('kind')} VARCHAR(16) NULL,
    {q('status')} VARCHAR(24) NULL,
    {q('summary')} {txt} NULL,
    {q('detail')} {txt} NULL,
    {q('metrics_json')} {txt} NULL,
{fk_file},
{fk_conv}
);""",
        ]

    def _generate_triggers(self) -> str:
        q = self._quote
        lines = [
            "-- ========================================================",
            "-- 5. Database Actions & Audit Triggers",
            "-- ========================================================",
        ]

        if self.dialect == "sqlite":
            lines.append(f"""CREATE TRIGGER {q('trg_update_folder_timestamp')}
AFTER UPDATE ON {q('folder_details')}
FOR EACH ROW
BEGIN
    UPDATE {q('folder_details')} SET {q('updated_at')} = CURRENT_TIMESTAMP WHERE {q('folder_id')} = OLD.{q('folder_id')};
END;""")
            lines.append(f"""CREATE TRIGGER {q('trg_update_file_timestamp')}
AFTER UPDATE ON {q('file_details')}
FOR EACH ROW
BEGIN
    UPDATE {q('file_details')} SET {q('updated_at')} = CURRENT_TIMESTAMP WHERE {q('file_id')} = OLD.{q('file_id')};
END;""")

        elif self.dialect == "mysql":
            lines.append("DELIMITER $$")
            lines.append(f"""CREATE TRIGGER {q('trg_before_folder_update')}
BEFORE UPDATE ON {q('folder_details')}
FOR EACH ROW
BEGIN
    SET NEW.{q('updated_at')} = CURRENT_TIMESTAMP();
END$$""")
            lines.append(f"""CREATE TRIGGER {q('trg_before_file_update')}
BEFORE UPDATE ON {q('file_details')}
FOR EACH ROW
BEGIN
    SET NEW.{q('updated_at')} = CURRENT_TIMESTAMP();
END$$""")
            lines.append("DELIMITER ;")

        elif self.dialect == "pgsql":
            lines.append(
                f"""CREATE OR REPLACE FUNCTION {self.schema_name}.update_timestamp_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.{q('updated_at')} = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;"""
            )
            lines.append(f"""CREATE TRIGGER {q('trg_folder_updated_at')}
BEFORE UPDATE ON {q('folder_details')}
FOR EACH ROW
EXECUTE FUNCTION {self.schema_name}.update_timestamp_column();""")
            lines.append(f"""CREATE TRIGGER {q('trg_file_updated_at')}
BEFORE UPDATE ON {q('file_details')}
FOR EACH ROW
EXECUTE FUNCTION {self.schema_name}.update_timestamp_column();""")

        return "\n\n".join(lines)

    # ================= Insert Synthesis =================

    def _generate_inserts(self) -> str:
        lines = [
            "-- ========================================================",
            "-- 6. Data Ingestion & Populating Normalized Tables",
            "-- ========================================================",
        ]
        q = self._quote

        # 1. Folders
        if self.folders:
            folder_cols = [q("folder_id"), q("folder_name"), q("parent_folder_id")]
            lines.append(f"-- Ingesting {q('folder_details')}")
            for row in self.folders:
                vals = [
                    self._escape_sql_val(row.get("folder_id")),
                    self._escape_sql_val(row.get("folder_name")),
                    self._escape_sql_val(row.get("parent_folder_id")),
                ]
                lines.append(
                    f"INSERT INTO {q('folder_details')} ({', '.join(folder_cols)}) VALUES ({', '.join(vals)});"
                )

        # 2. Extensions
        if self.extensions:
            ext_cols = [q("extension_id"), q("extension_name")]
            lines.append(f"\n-- Ingesting {q('tables')}")
            for row in self.extensions:
                vals = [
                    self._escape_sql_val(row.get("extension_id")),
                    self._escape_sql_val(row.get("extension_name")),
                ]
                lines.append(
                    f"INSERT INTO {q('tables')} ({', '.join(ext_cols)}) VALUES ({', '.join(vals)});"
                )

        # 3. Files & Lineage
        if self.files:
            file_cols = [
                q("file_id"),
                q("file_name"),
                q("file_extension_id"),
                q("size"),
                q("units"),
                q("raw_location_json"),
                q("created_at_ts64"),
                q("modified_at_ts64"),
            ]
            lineage_cols = [q("file_id"), q("folder_id"), q("depth_index")]
            lines.append(f"\n-- Ingesting {q('file_details')} and Normalized Lineage")

            for row in self.files:
                fid = row.get("file_id")
                loc_list = row.get("location", [])
                vals = [
                    self._escape_sql_val(fid),
                    self._escape_sql_val(row.get("file_name")),
                    self._escape_sql_val(row.get("file_extension_id")),
                    self._escape_sql_val(row.get("size", 0.0)),
                    self._escape_sql_val(row.get("units", "Bytes")),
                    self._escape_sql_val(loc_list),
                    self._escape_sql_val(row.get("created_at_ts64")),
                    self._escape_sql_val(row.get("modified_at_ts64")),
                ]
                lines.append(
                    f"INSERT INTO {q('file_details')} ({', '.join(file_cols)}) VALUES ({', '.join(vals)});"
                )

                # Deconstruct array into 3NF Lineage Table
                for idx, folder_id in enumerate(loc_list):
                    l_vals = [
                        self._escape_sql_val(fid),
                        self._escape_sql_val(folder_id),
                        self._escape_sql_val(idx),
                    ]
                    lines.append(
                        f"INSERT INTO {q('file_folder_lineage')} ({', '.join(lineage_cols)}) VALUES ({', '.join(l_vals)});"
                    )

        # 4. Reference Kinds
        kinds = self.code_tables.get("kind_reference", [])
        if kinds:
            lines.append(f"\n-- Ingesting {q('kind_reference')}")
            for row in kinds:
                vals = [
                    self._escape_sql_val(row.get("kind_id")),
                    self._escape_sql_val(row.get("kind_name")),
                ]
                lines.append(
                    f"INSERT INTO {q('kind_reference')} ({q('kind_id')}, {q('kind_name')}) VALUES ({', '.join(vals)});"
                )

        # 5. Imports
        imports = self.code_tables.get("imports_table", [])
        if imports:
            lines.append(f"\n-- Ingesting {q('imports_table')}")
            imp_cols = [
                q("import_id"),
                q("import_name"),
                q("import_source"),
                q("alias"),
            ]
            for row in imports:
                vals = [
                    self._escape_sql_val(row.get("import_id")),
                    self._escape_sql_val(row.get("import_name")),
                    self._escape_sql_val(row.get("import_source")),
                    self._escape_sql_val(row.get("alias")),
                ]
                lines.append(
                    f"INSERT INTO {q('imports_table')} ({', '.join(imp_cols)}) VALUES ({', '.join(vals)});"
                )

        # 6. Variables
        variables = self.code_tables.get("variables_table", [])
        if variables:
            lines.append(f"\n-- Ingesting {q('variables_table')}")
            var_cols = [
                q("variable_id"),
                q("variable_name"),
                q("variable_value"),
                q("scope"),
                q("is_imported"),
                q("source_import_id"),
            ]
            for row in variables:
                vals = [
                    self._escape_sql_val(row.get("variable_id")),
                    self._escape_sql_val(row.get("variable_name")),
                    self._escape_sql_val(row.get("variable_value")),
                    self._escape_sql_val(row.get("scope")),
                    self._escape_sql_val(row.get("is_imported", False)),
                    self._escape_sql_val(row.get("source_import_id")),
                ]
                lines.append(
                    f"INSERT INTO {q('variables_table')} ({', '.join(var_cols)}) VALUES ({', '.join(vals)});"
                )

        # 7. Classes & Junctions
        classes = self.code_tables.get("classes_table", [])
        if classes:
            lines.append(f"\n-- Ingesting {q('classes_table')} and Member Junctions")
            cls_cols = [
                q("class_id"),
                q("class_name"),
                q("class_description"),
                q("is_imported"),
                q("source_import_id"),
            ]

            for row in classes:
                cid = row.get("class_id")
                vals = [
                    self._escape_sql_val(cid),
                    self._escape_sql_val(row.get("class_name")),
                    self._escape_sql_val(row.get("class_description")),
                    self._escape_sql_val(row.get("is_imported", False)),
                    self._escape_sql_val(row.get("source_import_id")),
                ]
                lines.append(
                    f"INSERT INTO {q('classes_table')} ({', '.join(cls_cols)}) VALUES ({', '.join(vals)});"
                )

                # Junctions for Class
                for pid in row.get("parent_class_ids", []):
                    lines.append(
                        f"INSERT INTO {q('junction_class_inheritance')} ({q('class_id')}, {q('parent_class_id')}) VALUES ({cid}, {pid});"
                    )
                for mid in row.get("method_ids", []):
                    lines.append(
                        f"INSERT INTO {q('junction_class_methods')} ({q('class_id')}, {q('function_id')}) VALUES ({cid}, {mid});"
                    )
                for aid in row.get("args_ids", []):
                    lines.append(
                        f"INSERT INTO {q('junction_class_args')} ({q('class_id')}, {q('args_id')}) VALUES ({cid}, {aid});"
                    )
                for attr_id in row.get("attr_ids", []):
                    lines.append(
                        f"INSERT INTO {q('junction_class_attrs')} ({q('class_id')}, {q('args_id')}) VALUES ({cid}, {attr_id});"
                    )
                for tid in row.get("tensor_member_ids", []):
                    lines.append(
                        f"INSERT INTO {q('junction_class_tensor_members')} ({q('class_id')}, {q('member_id')}) VALUES ({cid}, {tid});"
                    )

        # 8. Args & Outputs
        args = self.code_tables.get("args_table", [])
        if args:
            lines.append(f"\n-- Ingesting {q('args_table')}")
            arg_cols = [
                q("args_id"),
                q("args_name"),
                q("args_type"),
                q("default_value"),
                q("permitted_values"),
            ]
            for row in args:
                vals = [
                    self._escape_sql_val(row.get("args_id")),
                    self._escape_sql_val(row.get("args_name")),
                    self._escape_sql_val(row.get("args_type")),
                    self._escape_sql_val(row.get("default_value")),
                    self._escape_sql_val(row.get("permitted_values")),
                ]
                lines.append(
                    f"INSERT INTO {q('args_table')} ({', '.join(arg_cols)}) VALUES ({', '.join(vals)});"
                )

        outputs = self.code_tables.get("outputs_table", [])
        if outputs:
            lines.append(f"\n-- Ingesting {q('outputs_table')}")
            for row in outputs:
                vals = [
                    self._escape_sql_val(row.get("output_id")),
                    self._escape_sql_val(row.get("output_type")),
                    self._escape_sql_val(row.get("description")),
                ]
                lines.append(
                    f"INSERT INTO {q('outputs_table')} ({q('output_id')}, {q('output_type')}, {q('description')}) VALUES ({', '.join(vals)});"
                )

        # 9. Tensor Members
        tensors = self.code_tables.get("tensor_members_table", [])
        if tensors:
            lines.append(f"\n-- Ingesting {q('tensor_members_table')}")
            t_cols = [q("member_id"), q("kind"), q("name"), q("count"), q("shape")]
            for row in tensors:
                vals = [
                    self._escape_sql_val(row.get("member_id")),
                    self._escape_sql_val(row.get("kind")),
                    self._escape_sql_val(row.get("name")),
                    self._escape_sql_val(row.get("count")),
                    self._escape_sql_val(row.get("shape")),
                ]
                lines.append(
                    f"INSERT INTO {q('tensor_members_table')} ({', '.join(t_cols)}) VALUES ({', '.join(vals)});"
                )

        # 10. Functions & Junctions
        functions = self.code_tables.get("functions_table", [])
        if functions:
            lines.append(f"\n-- Ingesting {q('functions_table')}")
            f_cols = [
                q("function_id"),
                q("function_name"),
                q("class_id"),
                q("function_description"),
                q("function_forward_pass"),
                q("function_backward_pass"),
                q("is_imported"),
                q("source_import_id"),
            ]
            for row in functions:
                fn_id = row.get("function_id")
                vals = [
                    self._escape_sql_val(fn_id),
                    self._escape_sql_val(row.get("function_name")),
                    self._escape_sql_val(row.get("class_id")),
                    self._escape_sql_val(row.get("function_description")),
                    self._escape_sql_val(row.get("function_forward_pass")),
                    self._escape_sql_val(row.get("function_backward_pass")),
                    self._escape_sql_val(row.get("is_imported", False)),
                    self._escape_sql_val(row.get("source_import_id")),
                ]
                lines.append(
                    f"INSERT INTO {q('functions_table')} ({', '.join(f_cols)}) VALUES ({', '.join(vals)});"
                )

                for idx, aid in enumerate(row.get("args_ids", [])):
                    lines.append(
                        f"INSERT INTO {q('junction_function_args')} ({q('function_id')}, {q('args_id')}, {q('order_index')}) VALUES ({fn_id}, {aid}, {idx});"
                    )
                for oid in row.get("function_outputs_ids", []):
                    lines.append(
                        f"INSERT INTO {q('junction_function_outputs')} ({q('function_id')}, {q('output_id')}) VALUES ({fn_id}, {oid});"
                    )

        # 11. Symbol Index
        symbols = self.code_tables.get("symbol_index", [])
        if symbols:
            lines.append(f"\n-- Ingesting {q('symbol_index')}")
            sym_cols = [
                q("symbol_id"),
                q("file_id"),
                q("kind_id"),
                q("target_entity_id"),
            ]
            for row in symbols:
                vals = [
                    self._escape_sql_val(row.get("symbol_id")),
                    self._escape_sql_val(row.get("file_id")),
                    self._escape_sql_val(row.get("kind_id")),
                    self._escape_sql_val(row.get("target_entity_id")),
                ]
                lines.append(
                    f"INSERT INTO {q('symbol_index')} ({', '.join(sym_cols)}) VALUES ({', '.join(vals)});"
                )

        # 12. Introspection Metadata
        meta_rows = self.code_tables.get("introspection_metadata_table", [])
        if meta_rows:
            lines.append(f"\n-- Ingesting {q('introspection_metadata_table')}")
            meta_cols = [
                q("metadata_id"),
                q("entity_id"),
                q("entity_type"),
                q("language"),
                q("inspection_source"),
                q("bytecode_or_ast_dump"),
                q("runtime_decorators_or_attributes"),
                q("callstack_or_frame_trace"),
                q("structural_properties"),
            ]
            for row in meta_rows:
                vals = [
                    self._escape_sql_val(row.get("metadata_id")),
                    self._escape_sql_val(row.get("entity_id")),
                    self._escape_sql_val(row.get("entity_type")),
                    self._escape_sql_val(row.get("language")),
                    self._escape_sql_val(row.get("inspection_source")),
                    self._escape_sql_val(row.get("bytecode_or_ast_dump")),
                    self._escape_sql_val(row.get("runtime_decorators_or_attributes")),
                    self._escape_sql_val(row.get("callstack_or_frame_trace")),
                    self._escape_sql_val(row.get("structural_properties")),
                ]
                lines.append(
                    f"INSERT INTO {q('introspection_metadata_table')} ({', '.join(meta_cols)}) VALUES ({', '.join(vals)});"
                )

        # 13. Import Linkage (Cross-File Import Resolution)
        linkage_rows = self.import_linkage
        if linkage_rows:
            lines.append(f"\n-- Ingesting {q('import_linkage_table')}")
            link_cols = [
                q("linkage_id"),
                q("import_id"),
                q("import_name"),
                q("import_source"),
                q("alias"),
                q("imported_by_file_id"),
                q("imported_by_file_name"),
                q("imported_by_file_type"),
                q("imported_by_file_location"),
                q("imported_to_file_id"),
                q("imported_to_file_name"),
                q("imported_to_file_type"),
                q("imported_to_file_location"),
                q("is_external"),
                q("import_value_ids"),
                q("import_value_variable_ids"),
                q("import_value_function_ids"),
                q("import_value_class_ids"),
            ]
            for row in linkage_rows:
                vals = [
                    self._escape_sql_val(row.get("linkage_id")),
                    self._escape_sql_val(row.get("import_id")),
                    self._escape_sql_val(row.get("import_name")),
                    self._escape_sql_val(row.get("import_source")),
                    self._escape_sql_val(row.get("alias")),
                    self._escape_sql_val(row.get("imported_by_file_id")),
                    self._escape_sql_val(row.get("imported_by_file_name")),
                    self._escape_sql_val(row.get("imported_by_file_type")),
                    self._escape_sql_val(row.get("imported_by_file_location", [])),
                    self._escape_sql_val(row.get("imported_to_file_id")),
                    self._escape_sql_val(row.get("imported_to_file_name")),
                    self._escape_sql_val(row.get("imported_to_file_type")),
                    self._escape_sql_val(row.get("imported_to_file_location", [])),
                    self._escape_sql_val(row.get("is_external", False)),
                    self._escape_sql_val(row.get("import_value_ids", [])),
                    self._escape_sql_val(row.get("import_value_variable_ids", [])),
                    self._escape_sql_val(row.get("import_value_function_ids", [])),
                    self._escape_sql_val(row.get("import_value_class_ids", [])),
                ]
                lines.append(
                    f"INSERT INTO {q('import_linkage_table')} ({', '.join(link_cols)}) VALUES ({', '.join(vals)});"
                )

        # 14. Temp Kind Details (Mermaid Graphs)
        temp_kinds = self.code_tables.get("temp_kind_details", [])
        if temp_kinds:
            lines.append(f"\n-- Ingesting {q('temp_kind_details')}")
            tk_cols = [
                q("temp_kind_id"),
                q("kind_type"),
                q("kind_name"),
                q("kind_function_ids"),
                q("kind_args_ids"),
                q("kind_class_ids"),
                q("kind_variables_ids"),
                q("kind_tensor_member_ids"),
                q("pipeline_flowchart"),
            ]
            for row in temp_kinds:
                vals = [
                    self._escape_sql_val(row.get("temp_kind_id")),
                    self._escape_sql_val(row.get("kind_type")),
                    self._escape_sql_val(row.get("kind_name")),
                    self._escape_sql_val(row.get("kind_function_ids", [])),
                    self._escape_sql_val(row.get("kind_args_ids", [])),
                    self._escape_sql_val(row.get("kind_class_ids", [])),
                    self._escape_sql_val(row.get("kind_variables_ids", [])),
                    self._escape_sql_val(row.get("kind_tensor_member_ids", [])),
                    self._escape_sql_val(row.get("pipeline_flowchart")),
                ]
                lines.append(
                    f"INSERT INTO {q('temp_kind_details')} ({', '.join(tk_cols)}) VALUES ({', '.join(vals)});"
                )

        # 15. Schema definitions (SchemaAnalyzer output)
        if self.schema:
            lines.extend(self._generate_schema_inserts())

        # 15b. Database store files (DatabaseAnalyzer output)
        if self.database:
            lines.extend(self._generate_database_inserts())

        # 16. Data-artifact profiles (DataAnalyzer output)
        if self.data:
            lines.extend(self._generate_data_inserts())

        # 16b. Configuration-file key/value tables (ConfigAnalyzer output)
        if self.config:
            lines.extend(self._generate_config_inserts())

        # 16c. Text-record files (TextualAnalyzer output)
        if self.text:
            lines.extend(self._generate_text_inserts())

        # 16d. Markup files (MarkupAnalyzer output)
        if self.markup:
            lines.extend(self._generate_markup_inserts())

        # 16e. Document files (DocumentAnalyzer output)
        if self.document:
            lines.extend(self._generate_document_inserts())

        # 16f. Misc files (MiscAnalyzer output -- terminal plane)
        if self.misc:
            lines.extend(self._generate_misc_inserts())

        # 17. Archive-container census (ArchiveAnalyzer output)
        if self.archive:
            lines.extend(self._generate_archive_inserts())

        # 18. Machine-code / executable analysis (MachineCodeAnalyzer output)
        if self.binary:
            lines.extend(self._generate_binary_inserts())

        # 19. Format-conversion outcomes (FormatConverter output)
        if self.conversions:
            lines.extend(self._generate_conversion_inserts())

        # 19b. Per-artifact deep analysis (TextAnalyzer output)
        if self.conversions.get("conversion_analysis"):
            lines.extend(self._generate_analysis_inserts())

        return "\n".join(lines)

    def _generate_schema_inserts(self) -> List[str]:
        """INSERT statements for the database-schema-definition tables."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6b. Ingesting Database Schema Definitions",
            "-- ========================================================",
        ]

        # (table_name, [column keys in order]) for each schema table.
        specs = [
            (
                "schema_databases_table",
                ["db_id", "db_name", "db_engine", "namespace", "file_ids", "table_ids"],
            ),
            (
                "schema_tables_table",
                [
                    "table_id",
                    "table_name",
                    "qualified_name",
                    "db_engine",
                    "namespace",
                    "table_kind",
                    "columns_ids",
                    "key_ids",
                    "constraint_ids",
                    "trigger_ids",
                    "index_ids",
                    "file_id",
                ],
            ),
            (
                "schema_columns_table",
                [
                    "column_id",
                    "column_name",
                    "column_type",
                    "column_value",
                    "keys",
                    "is_nullable",
                    "default_value",
                    "references_table",
                    "references_column",
                    "ordinal",
                    "table_ids",
                    "file_id",
                ],
            ),
            (
                "schema_keys_table",
                [
                    "key_id",
                    "key_name",
                    "key_type",
                    "table_id",
                    "column_ids",
                    "referenced_table",
                    "referenced_columns",
                    "on_delete",
                    "on_update",
                    "file_id",
                ],
            ),
            (
                "schema_constraints_table",
                [
                    "constraint_id",
                    "constraint_name",
                    "constraint_type",
                    "table_id",
                    "column_ids",
                    "expression",
                    "file_id",
                ],
            ),
            (
                "schema_triggers_table",
                [
                    "trigger_id",
                    "trigger_name",
                    "table_id",
                    "timing",
                    "events",
                    "level",
                    "action",
                    "method_id",
                    "file_id",
                ],
            ),
            (
                "schema_methods_table",
                [
                    "method_id",
                    "method_name",
                    "method_kind",
                    "return_type",
                    "language",
                    "arg_signature",
                    "table_id",
                    "file_id",
                ],
            ),
            (
                "schema_types_table",
                [
                    "type_id",
                    "type_name",
                    "type_category",
                    "base_type",
                    "allowed_values",
                    "table_id",
                    "file_id",
                ],
            ),
            (
                "schema_indexes_table",
                [
                    "index_id",
                    "index_name",
                    "table_id",
                    "is_unique",
                    "method",
                    "column_ids",
                    "column_expr",
                    "file_id",
                ],
            ),
            ("schema_file_index", ["sfi_id", "file_id", "entity_kind", "entity_id"]),
        ]

        for table_name, cols in specs:
            rows = self.schema.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_database_inserts(self) -> List[str]:
        """INSERT statements for the database-store tables (DatabaseAnalyzer output)."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6b2. Ingesting Database Store Files",
            "-- ========================================================",
        ]

        # (table_name, [column keys in order]) for each database table.
        specs = [
            (
                "database_stores_table",
                [
                    "store_id",
                    "store_name",
                    "engine",
                    "engine_family",
                    "file_format",
                    "format_class",
                    "size_bytes",
                    "page_size",
                    "page_count",
                    "encoding",
                    "schema_version",
                    "app_version",
                    "table_count",
                    "record_count_total",
                    "structural_parse",
                    "likely_encrypted",
                    "analysis_status",
                    "notes",
                    "properties",
                    "file_id",
                ],
            ),
            (
                "database_tables_table",
                [
                    "table_id",
                    "store_id",
                    "table_name",
                    "table_kind",
                    "qualified_name",
                    "column_count",
                    "row_count",
                    "estimated",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "database_columns_table",
                [
                    "column_id",
                    "table_id",
                    "store_id",
                    "column_name",
                    "ordinal",
                    "declared_type",
                    "inferred_type",
                    "is_nullable",
                    "is_primary_key",
                    "is_unique",
                    "default_value",
                    "references_table",
                    "references_column",
                    "null_count",
                    "non_null_count",
                    "distinct_count",
                    "min_value",
                    "max_value",
                    "sample_values",
                    "extra",
                    "file_id",
                ],
            ),
            (
                "database_indexes_table",
                [
                    "index_id",
                    "store_id",
                    "table_id",
                    "table_name",
                    "index_name",
                    "is_unique",
                    "method",
                    "column_names",
                    "file_id",
                ],
            ),
            (
                "database_relations_table",
                [
                    "relation_id",
                    "store_id",
                    "relation_type",
                    "from_table",
                    "from_column",
                    "to_table",
                    "to_column",
                    "value",
                    "method",
                    "extra",
                    "file_id",
                ],
            ),
            (
                "database_properties_table",
                [
                    "property_id",
                    "store_id",
                    "property_name",
                    "property_value",
                    "value_type",
                    "group_name",
                    "file_id",
                ],
            ),
            ("database_file_index", ["dbfi_id", "file_id", "entity_kind", "entity_id"]),
        ]

        for table_name, cols in specs:
            rows = self.database.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_data_inserts(self) -> List[str]:
        """INSERT statements for the data-artifact-profile tables."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6c. Ingesting Data Artifact Profiles",
            "-- ========================================================",
        ]

        # (table_name, [column keys in order]) for each data table.
        specs = [
            (
                "data_datasets_table",
                [
                    "dataset_id",
                    "dataset_name",
                    "category",
                    "subcategory",
                    "modality",
                    "file_format",
                    "format_family",
                    "size_bytes",
                    "row_count",
                    "column_count",
                    "record_count",
                    "tensor_count",
                    "analysis_status",
                    "notes",
                    "properties",
                    "file_id",
                ],
            ),
            (
                "data_columns_table",
                [
                    "column_id",
                    "dataset_id",
                    "column_name",
                    "ordinal",
                    "data_type",
                    "inferred_type",
                    "null_count",
                    "non_null_count",
                    "unique_count",
                    "min_value",
                    "max_value",
                    "mean_value",
                    "std_value",
                    "sample_values",
                    "extra",
                    "file_id",
                ],
            ),
            (
                "data_tensors_table",
                [
                    "tensor_id",
                    "dataset_id",
                    "tensor_name",
                    "dtype",
                    "shape",
                    "rank",
                    "num_elements",
                    "num_bytes",
                    "role",
                    "layer_name",
                    "extra",
                    "file_id",
                ],
            ),
            (
                "data_relations_table",
                [
                    "relation_id",
                    "dataset_id",
                    "relation_type",
                    "left_column",
                    "right_column",
                    "value",
                    "method",
                    "extra",
                    "file_id",
                ],
            ),
            (
                "data_properties_table",
                [
                    "property_id",
                    "dataset_id",
                    "property_name",
                    "property_value",
                    "value_type",
                    "group_name",
                    "file_id",
                ],
            ),
            (
                "data_model_layers_table",
                [
                    "model_layer_id",
                    "dataset_id",
                    "layer_name",
                    "layer_type",
                    "ordinal",
                    "depth",
                    "tensor_count",
                    "param_tensor_count",
                    "buffer_tensor_count",
                    "total_parameters",
                    "total_buffer_elements",
                    "total_bytes",
                    "dtypes",
                    "param_shapes",
                    "roles",
                    "file_id",
                ],
            ),
            ("data_file_index", ["dfi_id", "file_id", "entity_kind", "entity_id"]),
        ]

        for table_name, cols in specs:
            rows = self.data.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_config_inserts(self) -> List[str]:
        """INSERT statements for the configuration-file key/value tables."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6c2. Ingesting Configuration Files (key/value tree)",
            "-- ========================================================",
        ]

        # (table_name, [column keys in order]) for each config table.
        specs = [
            (
                "config_files_table",
                [
                    "config_file_id",
                    "file_name",
                    "extension",
                    "syntax_family",
                    "parse_engine",
                    "format_label",
                    "detected_via",
                    "format_class",
                    "size_bytes",
                    "encoding",
                    "root_type",
                    "section_count",
                    "key_count",
                    "value_count",
                    "property_count",
                    "max_depth",
                    "analysis_status",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "config_sections_table",
                [
                    "section_id",
                    "config_file_id",
                    "section_name",
                    "section_path",
                    "section_type",
                    "parent_section_id",
                    "key_count",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "config_value_keys_table",
                [
                    "config_value_key_id",
                    "config_file_id",
                    "section_id",
                    "config_value_key_name",
                    "key_path",
                    "config_value_parent_key_id",
                    "depth",
                    "node_type",
                    "child_count",
                    "file_id",
                ],
            ),
            (
                "config_values_table",
                [
                    "config_value_id",
                    "config_value_key_id",
                    "config_file_id",
                    "section_id",
                    "config_value_parent_key_id",
                    "config_value_type",
                    "scalar_value",
                    "list_index",
                    "is_leaf",
                    "file_id",
                ],
            ),
            (
                "config_properties_table",
                [
                    "property_id",
                    "config_file_id",
                    "property_name",
                    "property_value",
                    "value_type",
                    "group_name",
                    "file_id",
                ],
            ),
            ("config_file_index", ["cfi_id", "file_id", "entity_kind", "entity_id"]),
        ]

        for table_name, cols in specs:
            rows = self.config.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_text_inserts(self) -> List[str]:
        """INSERT statements for the text-record tables (TextualAnalyzer output)."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6c3. Ingesting Text-record Files (document/section/record/field)",
            "-- ========================================================",
        ]

        # (table_name, [column keys in order]) for each text table.
        specs = [
            (
                "text_files_table",
                [
                    "text_file_id",
                    "file_name",
                    "extension",
                    "content_kind",
                    "syntax_family",
                    "parse_engine",
                    "format_label",
                    "detected_via",
                    "format_class",
                    "size_bytes",
                    "encoding",
                    "line_count",
                    "section_count",
                    "record_count",
                    "field_count",
                    "property_count",
                    "analysis_status",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "text_sections_table",
                [
                    "text_section_id",
                    "text_file_id",
                    "section_name",
                    "section_path",
                    "section_type",
                    "ordinal",
                    "record_count",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "text_records_table",
                [
                    "text_record_id",
                    "text_file_id",
                    "text_section_id",
                    "record_index",
                    "record_type",
                    "record_label",
                    "start_line",
                    "end_line",
                    "field_count",
                    "text_preview",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "text_fields_table",
                [
                    "text_field_id",
                    "text_record_id",
                    "text_file_id",
                    "text_section_id",
                    "field_name",
                    "field_key",
                    "field_type",
                    "field_value",
                    "ordinal",
                    "file_id",
                ],
            ),
            (
                "text_properties_table",
                [
                    "property_id",
                    "text_file_id",
                    "property_name",
                    "property_value",
                    "value_type",
                    "group_name",
                    "file_id",
                ],
            ),
            ("text_file_index", ["tfi_id", "file_id", "entity_kind", "entity_id"]),
        ]

        for table_name, cols in specs:
            rows = self.text.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_document_inserts(self) -> List[str]:
        """INSERT statements for the document tables (DocumentAnalyzer output)."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6c4. Ingesting Document Files (document/section/record/field)",
            "--      manifest/query/makefile/certificate_text/notebook/",
            "--      document/license/diff",
            "-- ========================================================",
        ]

        # (table_name, [column keys in order]) for each document table.
        specs = [
            (
                "document_files_table",
                [
                    "document_file_id",
                    "file_name",
                    "extension",
                    "content_kind",
                    "syntax_family",
                    "parse_engine",
                    "format_label",
                    "detected_via",
                    "format_class",
                    "size_bytes",
                    "encoding",
                    "line_count",
                    "section_count",
                    "record_count",
                    "field_count",
                    "property_count",
                    "analysis_status",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "document_sections_table",
                [
                    "document_section_id",
                    "document_file_id",
                    "section_name",
                    "section_path",
                    "section_type",
                    "ordinal",
                    "record_count",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "document_records_table",
                [
                    "document_record_id",
                    "document_file_id",
                    "document_section_id",
                    "record_index",
                    "record_type",
                    "record_label",
                    "start_line",
                    "end_line",
                    "field_count",
                    "text_preview",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "document_fields_table",
                [
                    "document_field_id",
                    "document_record_id",
                    "document_file_id",
                    "document_section_id",
                    "field_name",
                    "field_key",
                    "field_type",
                    "field_value",
                    "ordinal",
                    "file_id",
                ],
            ),
            (
                "document_properties_table",
                [
                    "property_id",
                    "document_file_id",
                    "property_name",
                    "property_value",
                    "value_type",
                    "group_name",
                    "file_id",
                ],
            ),
            ("document_file_index", ["dfi_id", "file_id", "entity_kind", "entity_id"]),
        ]

        for table_name, cols in specs:
            rows = self.document.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_misc_inserts(self) -> List[str]:
        """INSERT statements for the misc tables (MiscAnalyzer output)."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6c6. Ingesting Misc Files (document/section/record/field)",
            "--      qss/osp/tscproj/pgdump -- terminal plane",
            "-- ========================================================",
        ]

        # (table_name, [column keys in order]) for each misc table.
        specs = [
            (
                "misc_files_table",
                [
                    "misc_file_id",
                    "file_name",
                    "extension",
                    "content_kind",
                    "syntax_family",
                    "parse_engine",
                    "format_label",
                    "detected_via",
                    "format_class",
                    "size_bytes",
                    "encoding",
                    "line_count",
                    "section_count",
                    "record_count",
                    "field_count",
                    "property_count",
                    "analysis_status",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "misc_sections_table",
                [
                    "misc_section_id",
                    "misc_file_id",
                    "section_name",
                    "section_path",
                    "section_type",
                    "ordinal",
                    "record_count",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "misc_records_table",
                [
                    "misc_record_id",
                    "misc_file_id",
                    "misc_section_id",
                    "record_index",
                    "record_type",
                    "record_label",
                    "start_line",
                    "end_line",
                    "field_count",
                    "text_preview",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "misc_fields_table",
                [
                    "misc_field_id",
                    "misc_record_id",
                    "misc_file_id",
                    "misc_section_id",
                    "field_name",
                    "field_key",
                    "field_type",
                    "field_value",
                    "ordinal",
                    "file_id",
                ],
            ),
            (
                "misc_properties_table",
                [
                    "property_id",
                    "misc_file_id",
                    "property_name",
                    "property_value",
                    "value_type",
                    "group_name",
                    "file_id",
                ],
            ),
            ("misc_file_index", ["mfi_id", "file_id", "entity_kind", "entity_id"]),
        ]

        for table_name, cols in specs:
            rows = self.misc.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_markup_inserts(self) -> List[str]:
        """INSERT statements for the markup tables (MarkupAnalyzer output)."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6c4. Ingesting Markup Files (document/element/attribute/",
            "--      namespace/section/property)",
            "-- ========================================================",
        ]

        # (table_name, [column keys in order]) for each markup table.
        specs = [
            (
                "markup_files_table",
                [
                    "markup_file_id",
                    "file_name",
                    "extension",
                    "content_kind",
                    "syntax_family",
                    "markup_language",
                    "dialect_profile",
                    "parse_engine",
                    "format_label",
                    "detected_via",
                    "format_class",
                    "size_bytes",
                    "encoding",
                    "line_count",
                    "well_formed",
                    "root_element",
                    "namespace_count",
                    "element_count",
                    "distinct_element_count",
                    "attribute_count",
                    "distinct_attribute_count",
                    "max_depth",
                    "comment_count",
                    "pi_count",
                    "cdata_count",
                    "text_length",
                    "section_count",
                    "property_count",
                    "analysis_status",
                    "notes",
                    "file_id",
                ],
            ),
            (
                "markup_elements_table",
                [
                    "markup_element_id",
                    "markup_file_id",
                    "tag_name",
                    "qualified_name",
                    "namespace_prefix",
                    "namespace_uri",
                    "occurrence_count",
                    "min_depth",
                    "max_depth",
                    "total_child_count",
                    "max_children",
                    "leaf_count",
                    "text_bearing_count",
                    "total_text_length",
                    "distinct_attribute_count",
                    "attribute_names",
                    "sample_text",
                    "is_root",
                    "ordinal",
                    "file_id",
                ],
            ),
            (
                "markup_attributes_table",
                [
                    "markup_attribute_id",
                    "markup_file_id",
                    "markup_element_id",
                    "element_tag",
                    "attribute_name",
                    "namespace_prefix",
                    "occurrence_count",
                    "distinct_value_count",
                    "value_type",
                    "sample_value",
                    "min_length",
                    "max_length",
                    "file_id",
                ],
            ),
            (
                "markup_namespaces_table",
                [
                    "markup_namespace_id",
                    "markup_file_id",
                    "prefix",
                    "uri",
                    "is_default",
                    "element_usage_count",
                    "file_id",
                ],
            ),
            (
                "markup_sections_table",
                [
                    "markup_section_id",
                    "markup_file_id",
                    "section_name",
                    "section_type",
                    "section_path",
                    "depth",
                    "ordinal",
                    "element_tag",
                    "child_count",
                    "text_length",
                    "title",
                    "file_id",
                ],
            ),
            (
                "markup_properties_table",
                [
                    "property_id",
                    "markup_file_id",
                    "property_name",
                    "property_value",
                    "value_type",
                    "group_name",
                    "file_id",
                ],
            ),
            ("markup_file_index", ["mfi_id", "file_id", "entity_kind", "entity_id"]),
        ]

        for table_name, cols in specs:
            rows = self.markup.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_archive_inserts(self) -> List[str]:
        """INSERT statements for the archive-container census tables."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6d. Ingesting Archive / Container Census",
            "-- ========================================================",
        ]

        specs = [
            (
                "archive_index",
                [
                    "archive_id",
                    "file_id",
                    "archive_name",
                    "archive_format",
                    "member_count",
                    "compressed_size",
                    "extracted_size",
                    "extractable",
                    "extraction_status",
                    "sub_database",
                    "sub_file_count",
                    "sub_shard_summary",
                    "depth",
                    "notes",
                ],
            ),
            (
                "archive_members",
                [
                    "member_id",
                    "archive_id",
                    "member_path",
                    "member_kind",
                    "member_size",
                    "compressed_size",
                    "modified",
                    "analyzer_class",
                    "file_id",
                ],
            ),
        ]

        for table_name, cols in specs:
            rows = self.archive.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_binary_inserts(self) -> List[str]:
        """INSERT statements for the machine-code / executable analysis tables."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6e. Ingesting Machine-code / Executable Analysis",
            "-- ========================================================",
        ]

        specs = [
            (
                "binary_index",
                [
                    "binary_id",
                    "file_id",
                    "file_name",
                    "binary_format",
                    "format_family",
                    "category",
                    "subcategory",
                    "architecture",
                    "bitness",
                    "endianness",
                    "entry_point",
                    "is_stripped",
                    "is_dynamic",
                    "is_pic",
                    "section_count",
                    "symbol_count",
                    "import_count",
                    "export_count",
                    "sha256",
                    "size",
                    "entropy",
                    "detected_via",
                    "notes",
                    "error",
                ],
            ),
            (
                "binary_sections",
                [
                    "section_id",
                    "binary_id",
                    "ordinal",
                    "name",
                    "sec_type",
                    "virtual_address",
                    "file_offset",
                    "size",
                    "flags",
                    "entropy",
                ],
            ),
            (
                "binary_symbols",
                [
                    "symbol_id",
                    "binary_id",
                    "name",
                    "sym_kind",
                    "binding",
                    "address",
                    "size",
                    "section",
                    "is_import",
                    "is_export",
                    "library",
                ],
            ),
            ("binary_imports", ["import_id", "binary_id", "library", "symbol", "kind"]),
            (
                "binary_properties",
                ["property_id", "binary_id", "prop_group", "prop_name", "prop_value"],
            ),
        ]

        for table_name, cols in specs:
            rows = self.binary.get(table_name, [])
            if not rows:
                continue
            col_sql = ", ".join(q(c) for c in cols)
            lines.append(f"\n-- Ingesting {q(table_name)}")
            for row in rows:
                vals = ", ".join(esc(row.get(c)) for c in cols)
                lines.append(
                    f"INSERT INTO {q(table_name)} ({col_sql}) VALUES ({vals});"
                )

        return lines

    def _generate_conversion_inserts(self) -> List[str]:
        """INSERT statements for the format-conversion outcome table."""
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6f. Ingesting Format Conversions (opaque/legacy -> renderable)",
            "-- ========================================================",
        ]
        cols = [
            "conversion_id",
            "file_id",
            "source_file",
            "source_path",
            "source_ext",
            "target_format",
            "status",
            "method",
            "tool",
            "output_file",
            "output_size",
            "detail",
        ]
        rows = self.conversions.get("format_conversions", [])
        if not rows:
            return lines
        col_sql = ", ".join(q(c) for c in cols)
        lines.append(f"\n-- Ingesting {q('format_conversions')}")
        for row in rows:
            vals = ", ".join(esc(row.get(c)) for c in cols)
            lines.append(
                f"INSERT INTO {q('format_conversions')} ({col_sql}) VALUES ({vals});"
            )
        return lines

    def _generate_analysis_inserts(self) -> List[str]:
        """INSERT statements for the conversion-analysis table (TextAnalyzer output).

        The variable per-format ``metrics`` dict is serialized to a JSON string in
        the ``metrics_json`` column; every other column is a flat scalar.
        """
        q = self._quote
        esc = self._escape_sql_val
        lines: List[str] = [
            "\n-- ========================================================",
            "-- 6g. Ingesting Conversion Analysis (rendered-artifact metrics)",
            "-- ========================================================",
        ]
        rows = self.conversions.get("conversion_analysis", [])
        if not rows:
            return lines
        cols = [
            "analysis_id",
            "conversion_id",
            "file_id",
            "source_file",
            "source_ext",
            "artifact_file",
            "kind",
            "status",
            "summary",
            "detail",
            "metrics_json",
        ]
        col_sql = ", ".join(q(c) for c in cols)
        lines.append(f"\n-- Ingesting {q('conversion_analysis')}")
        for row in rows:
            metrics = row.get("metrics")
            record = {
                "analysis_id": row.get("analysis_id"),
                "conversion_id": row.get("conversion_id"),
                "file_id": row.get("file_id"),
                "source_file": row.get("source_file"),
                "source_ext": row.get("source_ext"),
                "artifact_file": row.get("artifact_file"),
                "kind": row.get("kind"),
                "status": row.get("status"),
                "summary": row.get("summary"),
                "detail": row.get("detail"),
                "metrics_json": (
                    json.dumps(metrics, default=str, ensure_ascii=False)
                    if metrics is not None
                    else None
                ),
            }
            vals = ", ".join(esc(record.get(c)) for c in cols)
            lines.append(
                f"INSERT INTO {q('conversion_analysis')} ({col_sql}) VALUES ({vals});"
            )
        return lines

    def _generate_footer(self) -> str:
        lines = [
            "-- ========================================================",
            "-- 7. Finalize & Commit",
            "-- ========================================================",
        ]
        if self.dialect == "sqlite":
            # SQLite scripts run in autocommit (no explicit BEGIN), so a bare COMMIT
            # would fail with "no transaction is active" under executescript / the CLI.
            lines.append("PRAGMA foreign_keys = ON;")
        elif self.dialect == "mysql":
            lines.extend(["SET FOREIGN_KEY_CHECKS = 1;", "COMMIT;"])
        elif self.dialect == "pgsql":
            lines.append("COMMIT;")
        return "\n".join(lines)

    def export_to_sqlite_db(self, db_path: str = "repository.db"):
        # 1. Generate SQL script in SQLite dialect
        self.dialect = "sqlite"
        sql_path = self.generate()

        # 2. Execute against a SQLite connection to create the .db file.
        #    Disable per-statement fsync/journalling for the bulk load: this
        #    build materialises tens/hundreds of thousands of INSERTs and the
        #    default durable-commit-per-statement makes that pathologically slow
        #    on Windows. The .db is a regenerable artifact, so durability during
        #    the load is unnecessary; a final PRAGMA optimize + close flushes it.
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA synchronous = OFF")
        conn.execute("PRAGMA temp_store = MEMORY")
        with open(sql_path, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.execute("PRAGMA optimize")
        conn.close()
        print(f"Direct SQLite binary database created: {db_path}")

    # ================= Concurrent injection =================
    def _split_inserts_into_blocks(self) -> List[Tuple[str, str]]:
        """
        Partition the generated INSERT section into independent per-table blocks
        so they can be injected concurrently. Each block is the contiguous run of
        ``INSERT`` statements under one ``-- Ingesting "<table>"`` marker (the
        ``file_details`` block also carries its ``file_folder_lineage`` rows, which
        is fine — a block is self-contained and disjoint from every other block).

        Returns a list of ``(block_label, sql_text)`` tuples in emission order.
        """
        inserts_sql = self._generate_inserts()
        blocks: List[Tuple[str, List[str]]] = []
        current_label: Optional[str] = None
        current_lines: List[str] = []

        def _flush():
            if current_label is not None and current_lines:
                blocks.append((current_label, list(current_lines)))

        def _at_statement_boundary() -> bool:
            # True when the block is empty or its last non-blank content line
            # ends a statement (";"). Value literals may contain embedded
            # newlines (they are not escaped), so a continuation line could
            # look like a marker; only treat "-- Ingesting" as a real block
            # delimiter at a genuine statement boundary.
            for prev in reversed(current_lines):
                if prev.strip():
                    return prev.rstrip().endswith(";")
            return True

        for line in inserts_sql.splitlines():
            stripped = line.strip()
            if stripped.startswith("-- Ingesting") and _at_statement_boundary():
                _flush()
                current_label = stripped
                current_lines = []
            elif current_label is not None:
                # Accumulate every line verbatim (INSERTs plus any continuation
                # lines from values containing newlines); banner/preamble lines
                # before the first marker are skipped (current_label is None).
                current_lines.append(line)
        _flush()

        # Keep only blocks that actually contain an INSERT statement.
        result: List[Tuple[str, str]] = []
        for label, lines in blocks:
            if any(l.lstrip().startswith("INSERT") for l in lines):
                result.append((label, "\n".join(lines)))
        return result

    def export_to_sqlite_db_concurrent(
        self, db_path: str = "repository.db", workers: Optional[int] = None
    ):
        """
        Materialize the SQLite database with the table structure created once,
        then the per-table INSERT blocks injected by a pool of concurrent worker
        threads (each with its own connection). This mirrors the router's ethos:
        the schema + data file is populated by parallel/concurrent injectors.

        Correctness: the structure (DROP/CREATE/triggers) is applied on a single
        connection before any injector starts; foreign-key enforcement is OFF
        during the load (as in the .sql dump), and every INSERT block targets a
        distinct table, so concurrent writers never conflict on rows. SQLite
        serializes the physical writes (WAL + busy_timeout), so the threads
        overlap their Python-side value building and queue their commits safely.
        """
        self.dialect = "sqlite"
        if workers is None:
            workers = max(1, (os.cpu_count() or 2))

        # 1. Build structure once (drops + DDL + triggers), single-threaded.
        structure = "\n\n".join(
            s
            for s in (
                self._generate_header(),
                self._generate_drop_tables() if self.drop_existing else "",
                self._generate_ddl(),
                self._generate_triggers(),
            )
            if s.strip()
        )

        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = OFF")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.executescript(structure)
        conn.commit()
        conn.close()

        # 2. Inject per-table INSERT blocks concurrently. The Go injector
        #    (file_analyzer/core/go/injector.go) is the fast path; a pure-Python
        #    thread pool is the toolchain-free fallback. Both apply one block per
        #    connection in its own transaction, and every block targets a distinct
        #    table, so concurrent writers never conflict.
        from .inject_pool import inject_blocks

        blocks = self._split_inserts_into_blocks()
        report = inject_blocks(db_path, blocks, workers=workers)
        for line in report.get("log") or []:
            if line:
                print(line)

        failures = report.get("failures") or []
        if failures:
            detail = "\n".join(f"  {lbl}: {err}" for lbl, err in failures)
            raise RuntimeError(
                f"concurrent injection failed for {len(failures)} block(s):\n{detail}"
            )

        # 3. Finalize.
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA optimize")
        conn.close()
        print(
            f"Direct SQLite binary database created (concurrent, "
            f"{report.get('engine', 'python')} injector, {report.get('workers', workers)} "
            f"workers, {len(blocks)} table blocks): {db_path}"
        )
