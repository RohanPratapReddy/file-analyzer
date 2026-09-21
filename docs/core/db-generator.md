# RepositoryDatabaseGenerator — the normalized SQL dump + SQLite builder

**Package:** `src/core` · **Import:** `from src import RepositoryDatabaseGenerator` · **Component:** `dbgen` / `db`

## What it does

`RepositoryDatabaseGenerator` takes the in-memory table families produced by
every upstream stage (census, code, and each per-plane / post-plane analyzer)
and emits one fully-normalized relational schema: a `.sql` text dump in the
chosen dialect, and — on request — a materialized SQLite `.db` built by
concurrent per-table injectors. It generates DDL, constraints, triggers, and
`INSERT`s; it does not read source files.

## Constructor

`RepositoryDatabaseGenerator(folder_tables, code_analyzer_tables, import_linkage_table=None, schema_tables=None, database_tables=None, data_tables=None, config_tables=None, text_tables=None, markup_tables=None, document_tables=None, misc_tables=None, archive_tables=None, binary_tables=None, conversion_tables=None, sql_dialect="sqlite", dump_sql_path="repository_schema.sql", schema_name="code_intelligence", drop_existing=True)`

| param | default | meaning |
|-------|---------|---------|
| `folder_tables` | *(required)* | The `(folders, extensions, files)` tuple from `RepositoryAnalyzer.generate()`. |
| `code_analyzer_tables` | *(required)* | Code analyzer tables dict (classes/functions/symbols/imports/…). |
| `import_linkage_table` | `None` → `[]` | Rows from `ImportLinkageAnalyzer.generate()`. |
| `schema_tables` | `None` → `{}` | `SchemaAnalyzer` output (schema_* tables). |
| `database_tables` | `None` → `{}` | `DatabaseAnalyzer` output (database_* tables). |
| `data_tables` | `None` → `{}` | `DataAnalyzer` output (data_* tables). |
| `config_tables` | `None` → `{}` | `ConfigAnalyzer` output (config_* tables). |
| `text_tables` | `None` → `{}` | `TextualAnalyzer` output (text_* tables). |
| `markup_tables` | `None` → `{}` | `MarkupAnalyzer` output (markup_* tables). |
| `document_tables` | `None` → `{}` | `DocumentAnalyzer` output (document_* tables). |
| `misc_tables` | `None` → `{}` | `MiscAnalyzer` output (misc_* tables). |
| `archive_tables` | `None` → `{}` | `ArchiveAnalyzer.process()` output (archive_index/archive_members). |
| `binary_tables` | `None` → `{}` | `MachineCodeAnalyzer.process()` output (binary_index/sections/symbols/imports/properties). |
| `conversion_tables` | `None` → `{}` | `FormatConverter.convert_files()` output (`format_conversions`, optionally `conversion_analysis`). |
| `sql_dialect` | `"sqlite"` | `mysql` / `pgsql` / `postgresql` (aliased to `pgsql`) / `sqlite`. Invalid → `ValueError`. |
| `dump_sql_path` | `"repository_schema.sql"` | Where the `.sql` dump is written. |
| `schema_name` | `"code_intelligence"` | Namespace/database name for PostgreSQL/MySQL. |
| `drop_existing` | `True` | Prepend `DROP TABLE IF EXISTS` statements. |

## Key methods

| method | returns | notes |
|--------|---------|-------|
| `generate()` | `Path` | Builds header → (drops) → DDL → triggers → inserts → footer and writes the `.sql` in `self.dialect`. Returns the dump path. |
| `export_to_sqlite_db(db_path="repository.db")` | `None` | Single-threaded: forces sqlite dialect, `generate()`s, then `executescript`s the whole dump into a new `.db`. |
| `export_to_sqlite_db_concurrent(db_path="repository.db", workers=None)` | `None` | Forces sqlite dialect; applies structure once, then injects per-table `INSERT` blocks across a thread pool (each thread its own connection). `workers` defaults to CPU count. Raises `RuntimeError` if any block fails. |

There is no `get_tables()` on this class — it *consumes* table families and
*emits* SQL/`.db` artifacts.

## Run it standalone

### CLI (component mode)

```bash
# Build the .sql (+ .db) from a merged tables JSON
python -m src.main --component dbgen --tables-json all_tables.json \
    --build-db --db out.db --sql out.sql --dialect postgresql
```

`dbgen` takes **no** source census — it reads all table families from
`--tables-json` (any omitted key is treated as empty). `--build-db` triggers the
concurrent SQLite build; `--injection-workers` sets the worker count. See the
`--tables-json` contract in [../USAGE.md](../USAGE.md).

### Docker (component mode in a container)

The `engine` service runs `python -m src.main`, so pass it the same args. `dbgen` reads its inputs from `--tables-json` and writes `--sql`/`--db` — keep all of them under `/artifacts` so the input JSON is readable and the artifacts persist to the host:

```bash
docker compose --profile engine run --build engine \
  --component dbgen --tables-json /artifacts/all_tables.json \
  --build-db --db /artifacts/out.db --sql /artifacts/out.sql --dialect postgresql
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="--component dbgen --tables-json /artifacts/all_tables.json --build-db --db /artifacts/out.db --sql /artifacts/out.sql --dialect postgresql" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`; output lands in `ARTIFACTS_DIR` (default `./artifacts`).

### Python

```python
from src import RepositoryDatabaseGenerator

generator = RepositoryDatabaseGenerator(
    folder_tables=(folders, extensions, files),
    code_analyzer_tables=code_tables,
    import_linkage_table=linkage,
    data_tables=data_tables,          # any subset of the *_tables families
    sql_dialect="sqlite",
    dump_sql_path="repository_schema.sql",
    schema_name="code_intelligence",
    drop_existing=True,
)
generator.generate()                                   # writes the .sql
generator.export_to_sqlite_db_concurrent("repository.db", workers=None)  # builds the .db
```

(Mirrors `main.py`'s `_run_dbgen_component`, which calls
`export_to_sqlite_db_concurrent(str(db_path), workers=args.injection_workers)`
only when `--build-db` is passed. `AnalysisEngine.run()` calls the same two
methods back to back.)

## Output

- The `.sql` dump at `dump_sql_path` (dialect per `sql_dialect`).
- The binary `.db` at `db_path` when an `export_*` method is called (always
  sqlite regardless of `sql_dialect`).

It consumes **all** `*_tables` families and folds them into one database; every
`v_*` view (see `src/views/sql/catalog.json`) reads the base tables this class
emits. (View DDL itself is installed separately by `AnalysisEngine`'s views
stage, not by this class.)

## How it fits the pipeline

Final data-emitting stage. `AnalysisEngine.run()` constructs it with the census
tuple plus every collected table family, calls `generate()` for the `.sql`, then
`export_to_sqlite_db_concurrent()` for the `.db`; the views stage runs afterward.

## Notes & gotchas

- **`postgresql` is normalized to `pgsql`.** `self.dialect` is lowercased and
  `postgresql` → `pgsql`; an unsupported dialect raises `ValueError`.
- **The `.db` is always sqlite.** Both `export_*` methods set
  `self.dialect = "sqlite"` before generating, so the binary build ignores a
  non-sqlite `sql_dialect` (only the text dump honors it).
- **Concurrency is per-table.** `_split_inserts_into_blocks` partitions the
  `INSERT` section by `-- Ingesting "<table>"` markers at real statement
  boundaries; each block targets a distinct table, so concurrent writers never
  conflict on rows. Foreign keys are OFF during the load and re-enabled at the end.
- **Value literals may contain embedded newlines** (they are not escaped), so
  block splitting only treats an `-- Ingesting` line as a delimiter at a genuine
  statement boundary (previous content line ends with `;`).
- **Bulk-load PRAGMAs.** The single-threaded builder uses
  `journal_mode=OFF`/`synchronous=OFF`; the concurrent one uses WAL +
  `busy_timeout=60000` per connection. The `.db` is a regenerable artifact, so
  durability during load is intentionally relaxed.
- **Concurrent injection failures are surfaced, not swallowed** — any failed
  block rolls back and raises `RuntimeError` listing the failed labels.

## See also

- [../USAGE.md](../USAGE.md)
- [README.md](README.md), [analysis-engine.md](analysis-engine.md), [repository-analyzer.md](repository-analyzer.md), [import-linkage.md](import-linkage.md)
