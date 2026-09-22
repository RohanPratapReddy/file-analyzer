# AnalysisEngine — the end-to-end repository pipeline orchestrator

**Package:** `file_analyzer/core` · **Import:** `from file_analyzer import AnalysisEngine` · **Component:** engine-only / N/A (it *is* the full pipeline; run it via `python -m file_analyzer.main` with no `--component`)

## What it does

`AnalysisEngine` runs the whole tabgen flow in one process: the repository
census, the concurrent Go/Java router planes, cross-file import linkage, the
optional archive / binary / conversion post-plane stages, the single normalized
database, and the `v_*` analysis views. It writes exactly the two artifacts the
rest of the stack loads — `<db>` (binary SQLite) and `<sql>` (text dump) — and
returns a summary dict. On failure it leaves the `temp/` staging directory in
place for debugging; on success it removes it (unless `keep_temp_on_success`).

## Constructor

`AnalysisEngine(dir_path=".", db_path="repository.db", sql_path="repository_schema.sql", temp_dir=None, sql_dialect="sqlite", git_tracked=True, workers=None, plane_workers=None, injection_workers=None, python_exe=None, keep_temp_on_success=False, repository_kwargs=None, list_order_type="bfs", ignore_dirs=None, ignore_files=None, exclude_folder_signatures=None, exclude_file_signatures=None, extension_catalog_path=None, enable_import_linkage=True, enable_archives=True, max_archive_depth=8, enable_binary=True, enable_conversions=True, enable_conversion_analysis=True, conversions_dir=None, enable_views=True, schema_name="code_intelligence", drop_existing=True, _archive_depth=0)`

| param | default | meaning |
|-------|---------|---------|
| `dir_path` | `"."` | Repository root to analyze (resolved to absolute). |
| `db_path` | `"repository.db"` | Output SQLite database path. |
| `sql_path` | `"repository_schema.sql"` | Output SQL text-dump path. |
| `temp_dir` | `None` → `<dir_path>/temp` | Staging dir for `mapping.json` + `tables/*.json`. `main.py` defaults it under `--out` so a read-only source tree still analyzes. |
| `sql_dialect` | `"sqlite"` | Dump dialect (`sqlite` / `postgresql` / `pgsql`); the `.db` is always built in sqlite dialect regardless. |
| `git_tracked` | `True` | Census only git-tracked files; `False` walks every file on disk. |
| `workers` | `None` (→ CPU count) | Fallback worker count for **both** concurrent stages. |
| `plane_workers` | `None` (→ `workers`) | Workers per router plane (overrides `workers` for the routing stage). |
| `injection_workers` | `None` (→ `workers`) | Concurrent SQLite writer threads (overrides `workers` for the db-write stage). |
| `python_exe` | `None` (current interpreter) | Python the plane workers invoke for subprocess planes. |
| `keep_temp_on_success` | `False` | Keep `temp/` after a successful run. |
| `repository_kwargs` | `None` | Escape-hatch kwargs merged into the `RepositoryAnalyzer` census (wins over everything). |
| `list_order_type` | `"bfs"` | Census traversal order (`bfs`/`dfs`). |
| `ignore_dirs` / `ignore_files` | `None` | Census filter lists; only forwarded when non-`None` so the analyzer keeps its own baselines. |
| `exclude_folder_signatures` / `exclude_file_signatures` | `None` | Census regex/exact exclude signatures. |
| `extension_catalog_path` | `None` (bundled catalog) | Path to the authoritative `file_extensions.json` used for extension ids. |
| `enable_import_linkage` | `True` | Run `ImportLinkageAnalyzer` over the code tables. |
| `enable_archives` | `True` | Recurse into zip/tar/… containers with a nested engine. |
| `max_archive_depth` | `8` | Bound on nested-archive recursion. |
| `enable_binary` | `True` | Run the machine-code/object/bytecode deep-parse stage. |
| `enable_conversions` | `True` | Transcode opaque/legacy files to renderable artifacts (`FormatConverter`). |
| `enable_conversion_analysis` | `True` | Deep-parse each rendered artifact (`TextAnalyzer`) into `conversion_analysis`. |
| `conversions_dir` | `None` → `<db_stem>_renderable/` | Output dir for rendered artifacts. |
| `enable_views` | `True` | Install the `v_*` views into the `.db` and append them to the `.sql`. |
| `schema_name` | `"code_intelligence"` | Namespace/schema name for the postgresql/mysql dump. |
| `drop_existing` | `True` | Prepend `DROP TABLE IF EXISTS` to the dump. |
| `_archive_depth` | `0` | Internal: current nested-archive recursion level (set by the engine when it recurses; not for callers). |

## Key methods

| method | returns | notes |
|--------|---------|-------|
| `run()` | `dict` (summary) | The only public method. Executes the full pipeline and writes the `.db` + `.sql`. |

The summary dict contains: `repository_root`, `database`, `sql_dump`,
`file_count`, `shards` (`{analyzer_class: file_count}`), `import_linkages`,
`archives`, `archive_depth`, `binaries`, `views_installed`, `views_count`,
`temp_dir`, `temp_dir_removed`, plus (when conversions ran) the
`conversions_*` / `conversion_analysis_*` counters, and `views_error` /
`conversions_error` if a convenience stage failed. `main.py` adds `db_path` and
`sql_path` to it before printing.

## Run it

`AnalysisEngine` is the full pipeline, so there is no `--component` for it — the
default `python -m file_analyzer.main` invocation runs it.

### CLI

```bash
# Default: analyze the current repo into ./artifacts (sqlite artifacts + views)
python -m file_analyzer.main . --out ./artifacts

# Postgres-loadable dump for the docker loader
python -m file_analyzer.main . --out ./artifacts --dialect postgresql
```

See [../USAGE.md](../USAGE.md) for the complete flag surface.

### Docker

The `engine` service (compose profile `engine`, Dockerfile `engine` stage) has
ENTRYPOINT `["python","-m","file_analyzer.main"]`, so it runs the full pipeline directly.
Point `--out` at `/artifacts` so the `.db`/`.sql` persist to the host:

```bash
# Full pipeline over the repo mounted at /workspace
docker compose --profile engine run --build engine /workspace --out /artifacts

# Postgres-loadable dump (any full-pipeline flag works here)
docker compose --profile engine run --build engine /workspace --out /artifacts --dialect postgresql
```

Or pass the whole arg string via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --out /artifacts --dialect postgresql" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`; the
artifacts land in `ARTIFACTS_DIR` (default `./artifacts`). The `--help` surface
is the same, containerized:

```bash
docker compose --profile engine run --build engine --help
```

See the Docker section of [`../../README.md`](../../README.md) for the full container workflow.

### Python

```python
from pathlib import Path
from file_analyzer import AnalysisEngine

engine = AnalysisEngine(
    dir_path=Path("."),
    db_path=Path("artifacts/repository.db"),
    sql_path=Path("artifacts/repository_schema.sql"),
    temp_dir=Path("artifacts/temp"),
    sql_dialect="sqlite",
    git_tracked=True,
    enable_views=True,
)
summary = engine.run()
print(summary["database"], summary["file_count"], summary["views_count"])
```

(This mirrors how `main.py`'s `run()` instantiates the engine — it passes every
CLI flag straight through to the matching constructor argument.)

## Output

The engine does not itself return tables; it drives the other three core classes
and post-plane stages, then writes:

- `<db_path>` — the binary SQLite database (all base tables + installed `v_*` views).
- `<sql_path>` — the SQL text dump (same tables + appended `CREATE VIEW …`).

All `v_*` views (see `file_analyzer/views/sql/catalog.json`) are installed when
`enable_views` is on.

## How it fits the pipeline

`AnalysisEngine` sits at the top of the chain and calls the other three core
classes in order: `RepositoryAnalyzer` → router planes → `ImportLinkageAnalyzer`
→ `RepositoryDatabaseGenerator`, with `ArchiveAnalyzer`, `MachineCodeAnalyzer`,
and `FormatConverter`/`TextAnalyzer` as optional post-plane stages folded into
the generator's inputs. See [README.md](README.md) for the full diagram.

## Notes & gotchas

- **`temp/` is retained on failure.** Any exception (census, plane `PlaneError`,
  linkage, dbgen) propagates out of `run()` and leaves `temp/` for debugging;
  it is only removed on a clean success.
- **The `.db` is always sqlite.** `sql_dialect` only affects the `.sql` text
  dump; `export_to_sqlite_db_concurrent` forces the sqlite dialect for the binary.
- **Views/conversions are convenience layers, not load-bearing.** Failures there
  are caught and recorded (`views_error` / `conversions_error`) rather than
  failing the run.
- **View DDL is appended to the dump only for sqlite/pgsql dialects** — for any
  other dump dialect the append is skipped rather than emitting wrong SQL.
- **`workers` is only a fallback.** `plane_workers` and `injection_workers`
  each override it for their stage; unset values fall back to `workers`, then CPU count.
- **`_force_rmtree` handles read-only files** (chmod-then-retry) so `temp/`
  cleanup works on Windows.

## See also

- [../USAGE.md](../USAGE.md)
- [README.md](README.md) — the core package overview & chain diagram
- [repository-analyzer.md](repository-analyzer.md), [import-linkage.md](import-linkage.md), [db-generator.md](db-generator.md)
