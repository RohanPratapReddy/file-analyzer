# ImportLinkageAnalyzer — cross-file import & symbol linkage

**Package:** `src/core` · **Import:** `from src import ImportLinkageAnalyzer` · **Component:** `linkage`

## What it does

`ImportLinkageAnalyzer` correlates the filesystem tables from
`RepositoryAnalyzer` with the relational code tables from a code analyzer
(`PolyglotCodeAnalyzer` / `PythonCodeAnalyzer` / …) to produce one normalized
`import_linkage` table. Each row links a consumer file (the file that *contains*
the import) to the provider file the import *resolves to* in the repository,
flags standard-library / third-party imports as external, and projects the
variable/function/class ids the import brings in.

## Constructor

`ImportLinkageAnalyzer(repository_tables, code_analyzer_tables, analyzed_file_paths=None, code_file_map=None, dump_file_path="import_linkage.json", dump_file_type="memory")`

| param | default | meaning |
|-------|---------|---------|
| `repository_tables` | *(required)* | The `(folders, extensions, files)` tuple from `RepositoryAnalyzer.generate()`. |
| `code_analyzer_tables` | *(required)* | The code analyzer's tables dict (needs `imports_table`, `symbol_index`, `kind_reference`, `variables_table`, `functions_table`, `classes_table`). |
| `analyzed_file_paths` | `None` | Ordered list of paths exactly as the code analyzer consumed them, so index `i` → code `file_id == i+1`. Used to derive the code↔repo file-id bridge. |
| `code_file_map` | `None` | Explicit `{code_file_id: repository_file_id}` bridge; wins over `analyzed_file_paths`. |
| `dump_file_path` | `"import_linkage.json"` | Export path (only used when `dump_file_type` is a real format). |
| `dump_file_type` | `"memory"` | Export format (`json`/`yml`/`yaml`/`csv`/`tsv` or `memory` for none). |

## Key methods

| method | returns | notes |
|--------|---------|-------|
| `generate()` | `List[dict]` | Builds and returns the linkage rows; exports if `dump_file_type != "memory"`. |
| `get_table()` | `List[dict]` | Returns the already-built `linkage_table` (call after `generate()`). |

Each linkage row contains: `linkage_id`, `import_id`, `import_name`,
`import_source`, `alias`, `imported_by_file_id`/`_name`/`_type`/`_location`,
`imported_to_file_id`/`_name`/`_type`/`_location`, `is_external`,
`import_value_ids`, `import_value_variable_ids`, `import_value_function_ids`,
`import_value_class_ids`.

## Run it standalone

### CLI (component mode)

```bash
# Linkage over previously-emitted code + census tables
python -m src.main --component linkage --tables-json all_tables.json --emit linkage.json
```

`linkage` takes **no** source census — it reads its inputs from `--tables-json`
(keys `folders`/`extensions`/`files`, `code_tables`, and optionally
`analyzed_file_paths` / `code_file_map`). See the `--tables-json` contract in
[../USAGE.md](../USAGE.md).

### Docker (component mode in a container)

The `engine` service runs `python -m src.main`, so pass it the same args. `linkage` reads its inputs from `--tables-json` (place that merged JSON under `/artifacts` too so the container can read it) and emits into `/artifacts`:

```bash
docker compose --profile engine run --build engine \
  --component linkage --tables-json /artifacts/all_tables.json --emit /artifacts/linkage.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="--component linkage --tables-json /artifacts/all_tables.json --emit /artifacts/linkage.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`; output lands in `ARTIFACTS_DIR` (default `./artifacts`).

### Python

```python
from src import ImportLinkageAnalyzer

linkage = ImportLinkageAnalyzer(
    repository_tables=(folders, extensions, files),
    code_analyzer_tables=code_tables,
    analyzed_file_paths=code_paths,   # ordered paths the code analyzer consumed
    dump_file_type="memory",
).generate()
```

(Mirrors `main.py`'s `_run_linkage_component`; inside the full pipeline
`AnalysisEngine.run()` passes `code_paths = self._shard_file_paths("code")` as
`analyzed_file_paths`.)

## Output

The `import_linkage` table (produced under the JSON key `import_linkage`;
`RepositoryDatabaseGenerator` consumes it as `import_linkage_table`). Views that
read it: `v_import_edges`, `v_import_internal_vs_external` (see
`src/views/sql/catalog.json`).

## How it fits the pipeline

Fourth stage. `AnalysisEngine.run()` runs it after the code planes and only when
`enable_import_linkage` is on and `code_tables` is non-empty; the resulting rows
are passed to `RepositoryDatabaseGenerator(import_linkage_table=...)`.

## Notes & gotchas

- **Two distinct id spaces.** `symbol_index.file_id` (per code-analyzer run,
  from 1) is NOT `files.file_id` (assigned by `RepositoryAnalyzer`). Supply
  `code_file_map` **or** `analyzed_file_paths` to bridge them; with neither,
  `imported_by_file_id` is left `NULL` rather than guessed.
- **`_derive_code_file_map`** matches by longest relative-path suffix, then falls
  back to a *unique* basename match; ambiguous/unmatched entries map to `None`.
- **`is_external` is `True` when `imported_to_file_id is None`** — i.e. the
  import did not resolve to any repository file (stdlib/third-party).
- **Module resolution registers progressively shorter dotted suffixes** so both
  fully-qualified and bare references resolve; `__init__` files resolve to their
  package folder.
- **The import "kind" is discovered from `kind_reference`** (row with
  `kind_name == "import"`), defaulting to kind id `1` if absent.

## See also

- [../USAGE.md](../USAGE.md)
- [README.md](README.md), [analysis-engine.md](analysis-engine.md), [repository-analyzer.md](repository-analyzer.md), [db-generator.md](db-generator.md)
