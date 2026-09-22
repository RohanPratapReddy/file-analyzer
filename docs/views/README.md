# views — the analysis views + concurrent reader layer

**Package:** `file_analyzer/views` · **Import:** `from file_analyzer.views import VIEW_CATALOG, VIEW_PREFIX, ViewDef, catalog_by_name, views_ddl, install_views_sqlite, append_views_to_sql_dump, export_catalog_json, write_sql_artifacts, sqlite_present_tables, list_views, read_view, read_all_views` (this package is imported as `file_analyzer.views`; it is **not** re-exported from the `file_analyzer` top level) · CLI: `python -m file_analyzer.views {install,dump,emit,artifacts,list,read}`

## What it does

`file_analyzer/views` is the **single source of truth** for the ready-made analysis views
(`v_*`) that denormalize the engine's raw relational output into ready-to-read
summaries. The views are defined once in Python
([`catalog.py`](../../packages/engine/file_analyzer/views/catalog.py)); the builder installs them into
every `repository.db` the engine produces and mirrors them into the
`repository_schema.sql` dump; the Python reader and the bundled Go reader program
then simply **discover** the installed `VIEW` objects from the database catalog
and `SELECT *` from them — no reader embeds any query SQL.

Add or change a view in `catalog.py` and every consumer (Python reader, Go
reader, the Postgres/Docker backend) picks it up with no code change.

## Key APIs / functions (real names + signatures from source)

### `catalog.py` — the catalog

- `@dataclass(frozen=True) class ViewDef(name: str, tables: Tuple[str, ...], select: str)`
  — one view: logical name, the base tables it needs, and its normalized
  `SELECT` body. `ViewDef.object_name` → the created DB object name,
  `f"{VIEW_PREFIX}{name}"`.
- `VIEW_PREFIX = "v_"` — every created object is named `v_<name>`.
- `VIEW_CATALOG: List[ViewDef]` — the ordered catalog (report order).
- `catalog_by_name() -> dict` — `{view_name: ViewDef}` lookup.

### `builder.py` — catalog → real objects / artifacts

- `views_ddl(dialect="sqlite", present_tables=None) -> str` — CREATE VIEW DDL
  for the catalog. With `present_tables` given, only views whose base tables are
  all present are emitted.
- `install_views_sqlite(db_path, drop_existing=False) -> List[str]` — create
  every catalog view whose base tables are present in the `.db`; idempotent
  (`CREATE VIEW IF NOT EXISTS`); returns the created object names. **This is the
  only write performed against the output database, and it only adds read-only
  VIEW objects — it never touches table data.**
- `append_views_to_sql_dump(sql_path, dialect=None) -> List[str]` — append the
  CREATE VIEW DDL to an existing `.sql` dump (only for tables that appear in the
  dump); idempotent via begin/end markers (an existing section is replaced, not
  duplicated). Dialect is auto-detected from the dump when not given.
- `write_sql_artifacts(out_dir) -> List[Path]` — emit the static reference
  artifacts: `views.sqlite.sql`, `views.pgsql.sql`, and `catalog.json` (all
  views, no present-table filter).
- Also: `export_catalog_json(path)`, `sqlite_present_tables(db_path)`.

Per-dialect wrapping is the only difference: `sqlite` →
`CREATE VIEW IF NOT EXISTS "v_name" AS <select>;`, `pgsql` →
`CREATE OR REPLACE VIEW "v_name" AS <select>;` (`"postgresql"` is normalized to
`pgsql`).

### `reader.py` — Python reads over the installed views

- `list_views(db_path) -> List[str]` — the installed `type='view'` object names,
  sorted (opened `mode=ro` + `PRAGMA query_only = ON`).
- `read_view(db_path, view_name, limit=50) -> (columns, rows)` — read one view;
  the name is validated against the installed set before it is interpolated.
- `read_all_views(db_path, limit=50) -> Dict[str, {"columns","rows"}]` — read
  every installed view; a view that errors at query time is captured as
  `{"error": "..."}` rather than aborting the whole read.

## CLI (views only)

`python -m file_analyzer.views <command>` ([`__main__.py`](../../packages/engine/file_analyzer/views/__main__.py)):

| command | args | what it does |
|---------|------|--------------|
| `install <db>` | `--drop` | create the analysis views in a SQLite `.db` |
| `dump <sql>` | `--dialect {sqlite,pgsql}` | append CREATE VIEW DDL to a `.sql` dump |
| `emit` | `--dialect {sqlite,pgsql}` | print CREATE VIEW DDL to stdout |
| `artifacts <out_dir>` | — | write `views.sqlite.sql` / `views.pgsql.sql` / `catalog.json` |
| `list <db>` | — | list the views installed in a `.db` |
| `read <db>` | `--view NAME`, `--limit N` | read installed view(s) and print them |

```bash
python -m file_analyzer.views install   repository.db
python -m file_analyzer.views dump      repository_schema.sql
python -m file_analyzer.views list      repository.db
python -m file_analyzer.views read      repository.db --view v_extension_distribution
python -m file_analyzer.views artifacts file_analyzer/views/sql       # (re)generate sql/ artifacts
```

## The view catalog — 33 views (`v_` prefix)

Counts verified against `catalog.py`: **10 core + 12 schema + 11 data = 33**.

- **core (10)** — RepositoryAnalyzer + code analyzers: `file_inventory`,
  `extension_distribution`, `folder_tree_depth`, `import_internal_vs_external`,
  `import_edges`, `top_classes_by_methods`, `functions_defined_vs_imported`,
  `symbols_by_kind`, `introspection_by_language`, `tensor_members_by_kind`.
- **schema (12)** — SchemaAnalyzer output: `schema_databases_by_engine`,
  `schema_tables_by_engine`, `schema_tables_by_kind`, `schema_top_column_types`,
  `schema_keys_by_type`, `schema_foreign_key_edges`,
  `schema_constraints_by_type`, `schema_triggers_by_timing`,
  `schema_methods_by_language`, `schema_types_by_category`,
  `schema_top_indexed_tables`, `schema_entities_per_file`.
- **data (11)** — DataAnalyzer output: `data_datasets_by_modality`,
  `data_datasets_by_category`, `data_datasets_by_format`, `data_analysis_status`,
  `data_largest_tabular`, `data_columns_by_inferred_type`,
  `data_top_correlations`, `data_tensors_by_dtype`, `data_largest_tensors`,
  `data_properties_by_group`, `data_entities_per_file`.

Each is created as a DB object named `v_<name>` (e.g. the view
`extension_distribution` becomes `v_extension_distribution`).

## How it fits the pipeline

`AnalysisEngine.run` calls `install_views_sqlite(...)` on the finished
`repository.db` and `append_views_to_sql_dump(...)` on the `.sql` dump (unless
`--no-views` is passed), so every artifact ships with its views. Consumers:

- **Python** — `read_view` / `read_all_views`.
- **Go reader** (`file_analyzer/views/go/main.go`) — pure-Go SQLite driver
  `modernc.org/sqlite` (no cgo / no gcc).
- **Docker/Postgres backend** — `.sql` dumps already carry the appended
  `CREATE OR REPLACE VIEW` statements; for `.db` artifacts loaded via `pgloader`
  (tables only), the loader then applies `file_analyzer/views/sql/views.pgsql.sql`.

The Go reader **discovers** the installed views from the catalog (`SELECT name
FROM sqlite_master WHERE type='view'`) rather than embedding query SQL, and reads
every view across a pool of goroutine workers. CLI flags: `-source`, `-workers`,
`-repeat`, `-verbose`. When the Go toolchain is absent, `native_reader.py` falls
back to a concurrent pure-Python read with the same discovered-views contract.

### Docker

**1. Postgres path — views materialized automatically on load.** Bringing the
stack up runs the one-shot `loader` service, which loads each artifact into its
own Postgres database and (re)creates the `v_*` views there:

```bash
ARTIFACTS_DIR=./artifacts docker compose up --build
```

- For `.db` artifacts, `pgloader` copies **tables only**, so the loader's
  `apply_views` step then applies `file_analyzer/views/sql/views.pgsql.sql` (bind-mounted
  in as `/loader/views.pgsql.sql`) after each load, running **without**
  `ON_ERROR_STOP` so views over base tables a given database lacks are skipped,
  not fatal — the same present-tables-only contract as the SQLite side.
- For **postgresql-dialect `.sql` dumps**, the appended `CREATE OR REPLACE VIEW`
  statements are already in the dump (from `append_views_to_sql_dump`), so `psql`
  creates the views on load; the loader re-applies `views.pgsql.sql` afterward
  too, which is idempotent.

Regenerate the bind-mounted `views.pgsql.sql` after editing `catalog.py` with
`python -m file_analyzer.views artifacts file_analyzer/views/sql`.

**2. Running the `python -m file_analyzer.views` CLI inside the engine image.** The engine
image's stage `COPY`s the whole `file_analyzer/` package (`COPY file_analyzer/ ./file_analyzer/`), so it
already contains `file_analyzer.views`. Its `ENTRYPOINT` is `python -m file_analyzer.main`; override
it with `--entrypoint python` to invoke the views CLI against a mounted artifact:

```bash
docker compose --profile engine run --build --entrypoint python engine \
  -m file_analyzer.views list /artifacts/repository.db

# read a specific view
docker compose --profile engine run --build --entrypoint python engine \
  -m file_analyzer.views read /artifacts/repository.db --view v_extension_distribution
```

(`docker compose run --entrypoint` replaces the entrypoint for that one run; the
arguments after the service name become the new entrypoint's argv.)

## Notes & gotchas

- **Present-tables-only contract.** A view is materialized **iff all of its base
  tables exist** (`_selectable` checks `all(t in present_tables ...)`). A
  database lacking the `schema_*` / `data_*` families simply never gets — and
  never errors on — those views. This gives readers a clean contract:
  *a view exists in the DB ⟺ its base tables exist*, so they can enumerate
  `type='view'` and `SELECT *` with zero skip-logic.
- **Installation is additive, idempotent, and the only write.** It creates
  read-only `VIEW` objects over existing tables and never touches table data;
  re-running it is safe (`CREATE VIEW IF NOT EXISTS`, and the `.sql` section is
  marker-delimited so it is replaced, not duplicated).
- **Read-only guarantees (Go reader), enforced in layers.**
  1. Open mode `mode=ro` (`SQLITE_OPEN_READONLY`).
  2. Every pooled connection sets `PRAGMA query_only = true`.
  3. A start-up **write canary** (`CREATE TABLE __readonly_canary__`) that must
     *fail* — if the write ever succeeds, the program aborts.
  4. Query-only code paths only (`db.Query*` in Go) — no `Exec`, no transactions,
     no commits.
  The Python reader mirrors this with `mode=ro` + `PRAGMA query_only = ON`.
- **SQL must stay portable** across SQLite and PostgreSQL: pure `SELECT`/`WITH`,
  no DDL/DML; reserved-word columns (`"count"`, `"value"`) are double-quoted so
  both engines accept them.
- **Regenerating artifacts.** After editing `catalog.py`, run
  `python -m file_analyzer.views artifacts file_analyzer/views/sql` to refresh
  `views.sqlite.sql`, `views.pgsql.sql`, and `catalog.json` (the Docker loader
  bind-mounts `views.pgsql.sql`).

## See also

- [../USAGE.md](../USAGE.md) — the `python -m file_analyzer.main` entry point and the
  `--no-views` gate.
- repo [README.md](../../README.md) — the "views layer" and "concurrent reader
  (Go)" sections (build/run instructions and Docker wiring).
