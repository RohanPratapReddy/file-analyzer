-- Analysis views (sqlite) -- generated from src.views.catalog
-- 33 view(s).

-- v_file_inventory  (needs: file_details, tables)
CREATE VIEW IF NOT EXISTS "v_file_inventory" AS SELECT f.file_id, f.file_name || '.' || e.extension_name AS file, f.size, f.units FROM file_details f JOIN "tables" e ON f.file_extension_id = e.extension_id ORDER BY f.size DESC LIMIT 20;

-- v_extension_distribution  (needs: file_details, tables)
CREATE VIEW IF NOT EXISTS "v_extension_distribution" AS SELECT e.extension_name, COUNT(*) AS file_count FROM file_details f JOIN "tables" e ON f.file_extension_id = e.extension_id GROUP BY e.extension_name ORDER BY file_count DESC;

-- v_folder_tree_depth  (needs: folder_details)
CREATE VIEW IF NOT EXISTS "v_folder_tree_depth" AS WITH RECURSIVE tree(id, name, depth) AS ( SELECT folder_id, folder_name, 0 FROM folder_details WHERE parent_folder_id IS NULL UNION ALL SELECT f.folder_id, f.folder_name, t.depth + 1 FROM folder_details f JOIN tree t ON f.parent_folder_id = t.id ) SELECT depth, COUNT(*) AS folders FROM tree GROUP BY depth ORDER BY depth;

-- v_import_internal_vs_external  (needs: import_linkage_table)
CREATE VIEW IF NOT EXISTS "v_import_internal_vs_external" AS SELECT CASE WHEN is_external THEN 'external' ELSE 'internal' END AS kind, COUNT(*) AS links FROM import_linkage_table GROUP BY kind ORDER BY links DESC;

-- v_import_edges  (needs: import_linkage_table)
CREATE VIEW IF NOT EXISTS "v_import_edges" AS SELECT linkage_id, import_name, import_source, imported_by_file_name AS by_file, imported_to_file_name AS to_file, CASE WHEN is_external THEN 'ext' ELSE 'local' END AS scope FROM import_linkage_table ORDER BY linkage_id LIMIT 25;

-- v_top_classes_by_methods  (needs: classes_table, junction_class_methods)
CREATE VIEW IF NOT EXISTS "v_top_classes_by_methods" AS SELECT c.class_name, COUNT(j.function_id) AS method_count FROM classes_table c LEFT JOIN junction_class_methods j ON c.class_id = j.class_id GROUP BY c.class_id, c.class_name ORDER BY method_count DESC, c.class_name LIMIT 15;

-- v_functions_defined_vs_imported  (needs: functions_table)
CREATE VIEW IF NOT EXISTS "v_functions_defined_vs_imported" AS SELECT CASE WHEN is_imported THEN 'imported' ELSE 'defined' END AS origin, COUNT(*) AS n FROM functions_table GROUP BY origin ORDER BY n DESC;

-- v_symbols_by_kind  (needs: symbol_index, kind_reference)
CREATE VIEW IF NOT EXISTS "v_symbols_by_kind" AS SELECT k.kind_name, COUNT(*) AS symbols FROM symbol_index s JOIN kind_reference k ON s.kind_id = k.kind_id GROUP BY k.kind_name ORDER BY symbols DESC;

-- v_introspection_by_language  (needs: introspection_metadata_table)
CREATE VIEW IF NOT EXISTS "v_introspection_by_language" AS SELECT language, inspection_source, COUNT(*) AS records FROM introspection_metadata_table GROUP BY language, inspection_source ORDER BY records DESC;

-- v_tensor_members_by_kind  (needs: tensor_members_table)
CREATE VIEW IF NOT EXISTS "v_tensor_members_by_kind" AS SELECT kind, COUNT(*) AS members, SUM(COALESCE("count", 0)) AS total_count FROM tensor_members_table GROUP BY kind ORDER BY members DESC;

-- v_schema_databases_by_engine  (needs: schema_databases_table)
CREATE VIEW IF NOT EXISTS "v_schema_databases_by_engine" AS SELECT db_engine, COUNT(*) AS databases FROM schema_databases_table GROUP BY db_engine ORDER BY databases DESC;

-- v_schema_tables_by_engine  (needs: schema_tables_table)
CREATE VIEW IF NOT EXISTS "v_schema_tables_by_engine" AS SELECT db_engine, COUNT(*) AS tables FROM schema_tables_table GROUP BY db_engine ORDER BY tables DESC;

-- v_schema_tables_by_kind  (needs: schema_tables_table)
CREATE VIEW IF NOT EXISTS "v_schema_tables_by_kind" AS SELECT table_kind, COUNT(*) AS n FROM schema_tables_table GROUP BY table_kind ORDER BY n DESC;

-- v_schema_top_column_types  (needs: schema_columns_table)
CREATE VIEW IF NOT EXISTS "v_schema_top_column_types" AS SELECT column_type, COUNT(*) AS columns FROM schema_columns_table GROUP BY column_type ORDER BY columns DESC LIMIT 20;

-- v_schema_keys_by_type  (needs: schema_keys_table)
CREATE VIEW IF NOT EXISTS "v_schema_keys_by_type" AS SELECT key_type, COUNT(*) AS keys FROM schema_keys_table GROUP BY key_type ORDER BY keys DESC;

-- v_schema_foreign_key_edges  (needs: schema_keys_table, schema_tables_table)
CREATE VIEW IF NOT EXISTS "v_schema_foreign_key_edges" AS SELECT t.table_name AS from_table, k.referenced_table AS to_table, k.on_delete, k.on_update FROM schema_keys_table k JOIN schema_tables_table t ON k.table_id = t.table_id WHERE k.key_type = 'FOREIGN KEY' ORDER BY k.key_id LIMIT 25;

-- v_schema_constraints_by_type  (needs: schema_constraints_table)
CREATE VIEW IF NOT EXISTS "v_schema_constraints_by_type" AS SELECT constraint_type, COUNT(*) AS n FROM schema_constraints_table GROUP BY constraint_type ORDER BY n DESC;

-- v_schema_triggers_by_timing  (needs: schema_triggers_table)
CREATE VIEW IF NOT EXISTS "v_schema_triggers_by_timing" AS SELECT COALESCE(timing, '(none)') AS timing, COUNT(*) AS triggers FROM schema_triggers_table GROUP BY timing ORDER BY triggers DESC;

-- v_schema_methods_by_language  (needs: schema_methods_table)
CREATE VIEW IF NOT EXISTS "v_schema_methods_by_language" AS SELECT COALESCE(language, '(none)') AS language, COALESCE(method_kind, '(none)') AS method_kind, COUNT(*) AS methods FROM schema_methods_table GROUP BY language, method_kind ORDER BY methods DESC;

-- v_schema_types_by_category  (needs: schema_types_table)
CREATE VIEW IF NOT EXISTS "v_schema_types_by_category" AS SELECT COALESCE(type_category, '(none)') AS type_category, COUNT(*) AS n FROM schema_types_table GROUP BY type_category ORDER BY n DESC;

-- v_schema_top_indexed_tables  (needs: schema_indexes_table, schema_tables_table)
CREATE VIEW IF NOT EXISTS "v_schema_top_indexed_tables" AS SELECT t.table_name, COUNT(*) AS indexes FROM schema_indexes_table i JOIN schema_tables_table t ON i.table_id = t.table_id GROUP BY t.table_id, t.table_name ORDER BY indexes DESC, t.table_name LIMIT 15;

-- v_schema_entities_per_file  (needs: schema_file_index, file_details)
CREATE VIEW IF NOT EXISTS "v_schema_entities_per_file" AS SELECT f.file_name, sfi.entity_kind, COUNT(*) AS entities FROM schema_file_index sfi JOIN file_details f ON sfi.file_id = f.file_id GROUP BY f.file_id, f.file_name, sfi.entity_kind ORDER BY entities DESC LIMIT 25;

-- v_data_datasets_by_modality  (needs: data_datasets_table)
CREATE VIEW IF NOT EXISTS "v_data_datasets_by_modality" AS SELECT modality, COUNT(*) AS datasets FROM data_datasets_table GROUP BY modality ORDER BY datasets DESC;

-- v_data_datasets_by_category  (needs: data_datasets_table)
CREATE VIEW IF NOT EXISTS "v_data_datasets_by_category" AS SELECT category, subcategory, COUNT(*) AS datasets FROM data_datasets_table GROUP BY category, subcategory ORDER BY datasets DESC LIMIT 25;

-- v_data_datasets_by_format  (needs: data_datasets_table)
CREATE VIEW IF NOT EXISTS "v_data_datasets_by_format" AS SELECT file_format, COUNT(*) AS datasets, SUM(size_bytes) AS total_bytes FROM data_datasets_table GROUP BY file_format ORDER BY datasets DESC LIMIT 25;

-- v_data_analysis_status  (needs: data_datasets_table)
CREATE VIEW IF NOT EXISTS "v_data_analysis_status" AS SELECT analysis_status, COUNT(*) AS datasets FROM data_datasets_table GROUP BY analysis_status ORDER BY datasets DESC;

-- v_data_largest_tabular  (needs: data_datasets_table)
CREATE VIEW IF NOT EXISTS "v_data_largest_tabular" AS SELECT dataset_name, row_count, column_count FROM data_datasets_table WHERE row_count IS NOT NULL ORDER BY row_count DESC LIMIT 25;

-- v_data_columns_by_inferred_type  (needs: data_columns_table)
CREATE VIEW IF NOT EXISTS "v_data_columns_by_inferred_type" AS SELECT inferred_type, COUNT(*) AS columns FROM data_columns_table GROUP BY inferred_type ORDER BY columns DESC;

-- v_data_top_correlations  (needs: data_relations_table, data_datasets_table)
CREATE VIEW IF NOT EXISTS "v_data_top_correlations" AS SELECT d.dataset_name, r.left_column, r.right_column, r."value" FROM data_relations_table r JOIN data_datasets_table d ON r.dataset_id = d.dataset_id WHERE r.relation_type = 'pearson_correlation' ORDER BY ABS(r."value") DESC LIMIT 25;

-- v_data_tensors_by_dtype  (needs: data_tensors_table)
CREATE VIEW IF NOT EXISTS "v_data_tensors_by_dtype" AS SELECT dtype, COUNT(*) AS tensors, SUM(num_elements) AS total_elements FROM data_tensors_table GROUP BY dtype ORDER BY tensors DESC LIMIT 25;

-- v_data_largest_tensors  (needs: data_tensors_table, data_datasets_table)
CREATE VIEW IF NOT EXISTS "v_data_largest_tensors" AS SELECT d.dataset_name, t.tensor_name, t.dtype, t.rank, t.num_elements FROM data_tensors_table t JOIN data_datasets_table d ON t.dataset_id = d.dataset_id ORDER BY t.num_elements DESC LIMIT 25;

-- v_data_properties_by_group  (needs: data_properties_table)
CREATE VIEW IF NOT EXISTS "v_data_properties_by_group" AS SELECT group_name, COUNT(*) AS properties FROM data_properties_table GROUP BY group_name ORDER BY properties DESC LIMIT 25;

-- v_data_entities_per_file  (needs: data_file_index, file_details)
CREATE VIEW IF NOT EXISTS "v_data_entities_per_file" AS SELECT f.file_name, dfi.entity_kind, COUNT(*) AS entities FROM data_file_index dfi JOIN file_details f ON dfi.file_id = f.file_id GROUP BY f.file_id, f.file_name, dfi.entity_kind ORDER BY entities DESC LIMIT 25;
