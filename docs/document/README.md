# DocumentAnalyzer — the document plane

**Package:** `src/document` · **Import:** `from src import DocumentAnalyzer` · **Component:** `document`

## What it does
`DocumentAnalyzer` is the parent/super-class of the `document` analysis plane.
Every extension of the eight residual *document* content kinds (`manifest`,
`query`, `makefile`, `certificate_text`, `notebook`, `document`, `license`,
`diff`) is dispatched to its own child parser class (in `src/document/parsers.py`,
each a `DocumentTypeParser` subclass), and the resulting real, structure-aware
profile is flattened into normalized `document_*` tables in the shape
`document → sections → records → fields (+ file-level properties)`:

- one **section** row per top-level grouping (an AppCache CACHE/NETWORK block, a
  SQL statement list, a Makefile's variables/rules/directives, a PEM block set, a
  notebook's cells, a diff's per-file hunks, a DEP-5 paragraph set, …),
- one **record** row per entry inside a section (a manifest entry, a query
  statement, a make rule, an SSH key, a notebook cell, a diff hunk, a copyright
  line, …),
- one **field** row per typed name/value pair on a record.

Honesty contract (shared with text/config/database): content is sniffed first, an
inherently-binary payload degrades to an honest forensic byte profile with no
fabricated records, key/credential material is never decoded into its secret
content (only public structural facts), the raw payload is never stored, and a
partial parse is reported `partial` — never stubbed.

## Formats / extensions handled   (from source; qualitative unless verified)
The extension universe is defined by `document_formats.known_exts()` /
`routing_suffixes()`, which is built from the child-parser registry
(`parsers.build_registry()`). The eight content kinds correspond to child parsers:
`ManifestParser`, `QueryParser`, `MakefileParser`, `CertificateTextParser`,
`NotebookParser`, `DocumentFileParser`, `LicenseParser`, `DiffParser`. Exact
suffix membership comes from `document_formats` / `parsers`; do not hard-code a
list. (Example: `.tsql` routes to the query parser — see gotchas.)

## Run it standalone
### CLI (component mode)
```bash
python -m src.main . --component document --emit document.json
```

### Docker (component mode in a container)

The `engine` service runs `python -m src.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component document --emit /artifacts/document.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component document --emit /artifacts/document.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`.

### Python
```python
from src import DocumentAnalyzer
eng = DocumentAnalyzer(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code plane: also rewrite local ids -> repository ids and build the index
# eng.link_repository((folders, extensions, files), paths); tables = eng.get_tables()
```

Constructor: `DocumentAnalyzer(file_paths,
dump_file_path="document_analysis.json", dump_file_type="memory")`. Public methods
verified in source: `analyze()`, `get_tables()`,
`link_repository(repository_tables, analyzed_file_paths=None)`, plus classmethods
`routing_suffixes()` / `_known_exts()`.

## Output tables (real names)
From `get_tables()`:

- `document_files_table` — `document_file_id`, `file_name`, `extension`,
  `content_kind`, `syntax_family`, `parse_engine`, `format_label`,
  `detected_via`, `format_class`, `size_bytes`, `encoding`, `line_count`,
  `section_count`, `record_count`, `field_count`, `property_count`,
  `analysis_status`, `notes`, `file_id`
- `document_sections_table` — `document_section_id`, `document_file_id`,
  `section_name`, `section_path`, `section_type`, `ordinal`, `record_count`,
  `notes`, `file_id`
- `document_records_table` — `document_record_id`, `document_file_id`,
  `document_section_id`, `record_index`, `record_type`, `record_label`,
  `start_line`, `end_line`, `field_count`, `text_preview`, `notes`, `file_id`
- `document_fields_table` — `document_field_id`, `document_record_id`,
  `document_file_id`, `document_section_id`, `field_name`, `field_key`,
  `field_type`, `field_value`, `ordinal`, `file_id`
- `document_properties_table` — `property_id`, `document_file_id`,
  `property_name`, `property_value`, `value_type`, `group_name`, `file_id`
- `document_file_index` — `dfi_id`, `file_id`, `entity_kind`, `entity_id`
  (populated by `link_repository`)

Together these are the `document_tables` family consumed by
`RepositoryDatabaseGenerator` (`document_tables=` argument).

## How it fits the pipeline (routing id; link_repository step)
Routing id is `document`. In `src/router/routing.py`, `resolve_analyzer` checks
`document` after config / text / markup (and every higher-priority plane); the
document suffix set already subtracts those planes, so only previously-residual
document extensions route here. As a non-code plane it runs
`link_repository((folders, extensions, files), paths)` after `analyze()` to
rewrite each row's local `file_id` to the repository `file_details.file_id` and
build `document_file_index`; the final tables come from `get_tables()`.

## Notes & gotchas (only verified ones)
- **`.sql` → schema, not document.** `.sql` is in `_SCHEMA_EXTS`, and
  `resolve_analyzer` checks `schema` long before `document`, so a `.sql` file goes
  to `SchemaAnalyzer`. To exercise the document plane's SQL/query parser use
  `.tsql` (verified in `parsers.py`: `.tsql → ("tsql", "T-SQL (SQL Server)
  script")`), or another query suffix the query parser owns.
- **A bare `LICENSE` (no extension) does not route.** `resolve_analyzer` returns
  `None` when the filename has no suffix, so an extensionless `LICENSE` file is
  never assigned to this (or any) plane; the `LicenseParser` fires for the license
  extensions it registers, not for the bare basename.
- One bad file never aborts the batch — parse/emit failures are caught, warned,
  and skipped; a parser exception degrades to an honest forensic profile.
- No `v_*` analysis views are defined for this plane; `src/views/catalog.py`
  covers only the core/schema/data view families (no `v_document_*` view).

## See also — [../USAGE.md](../USAGE.md)
