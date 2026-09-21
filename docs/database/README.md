# DatabaseAnalyzer — on-disk database-store profiler (schema + data)

**Package:** `src/database` · **Import:** `from src import DatabaseAnalyzer` · **Component:** `database`

## What it does

`DatabaseAnalyzer` turns each on-disk database *file* (an actual store, not a DDL
script) into normalized `database_*` tables that **merge** the two neighbouring
analyzers:

- the **structural view** a `SchemaAnalyzer` would give — tables, columns,
  declared types, keys, foreign-key relations, indexes; and
- the **profile view** a `DataAnalyzer` would give — row counts, per-column
  null/distinct/min/max and bounded samples, plus store-level technical
  properties.

For every catalogued database extension it runs a real, pure-stdlib parser (see
`src/database/db_formats.py`). It content-sniffs each file and only claims it when
the bytes match. SQLite (and everything SQLite-backed) is fully introspected;
dBASE/FoxPro/Paradox, Berkeley DB, GNU dbm, Samba TDB, LMDB/mdbx,
LevelDB/RocksDB SSTables, Redis RDB, djb cdb, QlikView QVD, MS ESE/Jet/ACE,
Outlook PST/OST/DBX, InnoDB/MyISAM/FRM, Firebird/InterBase, SQL Server MDF/NDF,
InfluxDB TSM, KeePass (header only), Realm, WiredTiger, Kyoto Cabinet and Btrieve
get real header/structure parses. Anything opaque, proprietary or encrypted
degrades to an honest forensic byte profile.

## Formats handled (from source)

The owned extension set is `DatabaseAnalyzer._known_exts()`, which is
`db_formats.known_exts()` — the extension→(engine, family) map in
`src/database/db_formats.py`. It is a broad, qualitative set of database-store
formats (relational engines, key-value/embedded stores, mail stores, columnar
and accounting stores, etc.). Per-format behavior is one of three tiers:

- **full parse** — schema + data profile (SQLite and SQLite-backed stores);
- **structural / partial parse** — real header/structure read where the payload
  needs a heavier decoder (e.g. `.frm` reads the header but marks
  `status="partial"` because the full column list needs the FRM packed-field
  decoder);
- **forensic fallback** — an honest byte/magic profile for opaque, proprietary or
  encrypted stores.

## Run it standalone

### CLI (component mode)

```bash
python -m src.main . --component database --emit database.json
```

### Docker (component mode in a container)

The `engine` service runs `python -m src.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component database --emit /artifacts/database.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component database --emit /artifacts/database.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`.

### Python

```python
from src import DatabaseAnalyzer
eng = DatabaseAnalyzer(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code plane: rewrite local file ids -> repository file ids and populate
# database_file_index, exactly like the per-shard worker:
eng.link_repository((folders, extensions, files), paths)
tables = eng.get_tables()
```

`analyze()` only processes paths whose extension is in `_known_exts()`; others
are skipped. Constructor signature:
`DatabaseAnalyzer(file_paths, dump_file_path="database_analysis.json", dump_file_type="memory")`.

## Output tables (real names)

`analyze()`/`get_tables()` emit these seven:

| table | holds |
|-------|-------|
| `database_stores_table` | one row per store (engine, family, format, size, page size/count, encoding, versions, table/record counts, `structural_parse`, `likely_encrypted`, `analysis_status`, `properties` json) |
| `database_tables_table` | tables within a store (kind, column/row counts, `estimated`) |
| `database_columns_table` | columns (declared + inferred type, nullability, keys, null/distinct/min/max, sample values) |
| `database_indexes_table` | indexes (unique flag, method, column names) |
| `database_relations_table` | foreign keys / relations (from/to table+column, method) |
| `database_properties_table` | flattened store-level technical metadata (never payload) |
| `database_file_index` | `dbfi_id, file_id, entity_kind, entity_id` — populated by `link_repository` |

> **No `v_*` views read these.** `src/views/catalog.py` currently ships analysis
> views for the `schema_*` and `data_*` families but none for `database_*`, so no
> `v_database_*` view is created. The tables are still emitted and loaded into the
> database by `RepositoryDatabaseGenerator`.

## How it fits the pipeline

Routing id `database` (see `resolve_analyzer` in `src/router/routing.py`), checked
**after** `code` and `schema`. As a non-code plane, the `database` component (and
the real per-shard worker) runs `link_repository()` after `analyze()` to rewrite
local file ids to repository ids and fill `database_file_index`.

## Notes & gotchas

- **Some extensions defer to `code`.** `resolve_analyzer` matches `code` before
  `database`, so any extension the code analyzers already claim is routed to the
  code plane even though `db_formats.py` has a parser for it — e.g. `.frm`
  (VB/Oracle form source) and `.sage` (SageMath). `db_formats.py` still contains
  handlers for those, but routing never sends them here.
- **Honesty guarantees (enforced in `db_formats.py`):**
  - **Never a fabricated schema** — an unreadable store yields a forensic byte
    profile, not invented tables/columns.
  - **Never the raw payload** — only counts, stats, bounded samples and technical
    metadata are stored.
  - **Encrypted stores are never decrypted** — KeePass and similar are
    header-only; `likely_encrypted` is flagged instead of attempting a decrypt.
- **Robust batch** — a parse or emit exception on one file is caught and logged
  (`Warning: DatabaseAnalyzer …`); the rest of the batch continues.
- **IDs are 1-based and disjoint per entity kind**; rows start with a local
  `file_id` that only `link_repository()` makes repository-global.

## See also — [../USAGE.md](../USAGE.md)
