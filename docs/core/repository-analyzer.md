# RepositoryAnalyzer — the repository file census

**Package:** `file_analyzer/core` · **Import:** `from file_analyzer.engine import RepositoryAnalyzer` · **Component:** `census` / `repo`

## What it does

`RepositoryAnalyzer` walks a repository (git-tracked files by default, or every
file on disk with `git_tracked=False`), applies ignore/exclude filters, and
produces three normalized metadata tables — `folders`, `extensions`, `files` —
with globally-stable extension ids sourced from a canonical catalog. It also
builds the file→analyzer mapping the router planes consume. It records metadata
only (sizes, packed 64-bit timestamps, folder lineage); it never reads file
contents.

## Constructor

`RepositoryAnalyzer(dir_path=".", dump_file_path="repo_export.json", dump_file_type="json", git_tracked=True, list_order_type="bfs", exclude_folder_signatures=None, exclude_file_signatures=None, ignore_files=None, ignore_dirs=None, extension_catalog_path=None, extension_catalog=None)`

| param | default | meaning |
|-------|---------|---------|
| `dir_path` | `"."` | Repository root (resolved to absolute). |
| `dump_file_path` | `"repo_export.json"` | Path for the exported dump (only used when `dump_file_type` is a real file format). |
| `dump_file_type` | `"json"` | Export format: `json` / `yml`/`yaml` / `csv`/`tsv` / `xlsx` / `memory`. `memory` writes nothing (what the engine and component mode use). |
| `git_tracked` | `True` | `True` → `git ls-files`; `False` → `os.walk` of the whole tree. |
| `list_order_type` | `"bfs"` | Sort order for folders/files: `bfs` (by path depth, then path) or `dfs` (by path). |
| `exclude_folder_signatures` | `None` → `[]` | Folder-path exclude signatures (exact, suffix, or regex — see `_matches_signature`). |
| `exclude_file_signatures` | `None` → `[]` | File-name exclude signatures (same matching). |
| `ignore_files` | `None` → `[]` | Exact file names to skip. |
| `ignore_dirs` | `None` → `['__pycache__', '.git', '.venv', 'venv', 'env', '.pytest_cache']` | Directory names to skip. **Passing a value replaces the default set entirely** (only applied when `git_tracked=False`, i.e. the `os.walk` path). |
| `extension_catalog_path` | `None` → `file_analyzer/extention-table/file_extensions.json` | Path to the authoritative extension-id catalog. |
| `extension_catalog` | `None` | An explicit `{extension_name: extension_id}` map that wins over the on-disk catalog. |

## Key methods

| method | returns | notes |
|--------|---------|-------|
| `generate()` | `Optional[Tuple[folders, extensions, files]]` | Gathers → filters → builds tables → exports. Returns `None` if git gathering failed (not a git repo). Also stashes `self.folders/.extensions/.files`. |
| `build_analyzer_mapping()` | `List[dict]` | One `{file_id, file_location, analyzer_class}` row per file (via `file_analyzer.router.routing.build_mapping`). Requires `generate()` first; files no engine claims get `analyzer_class: None`. |
| `emit_analyzer_mapping(temp_dir)` | `Path` | Writes `temp/mapping.json` (mapping + per-class `shards`) and `temp/repo_tables.json` (folders/extensions/files) for the Go plane. Returns the temp dir. |

## Run it standalone

### CLI (component mode)

```bash
# Census only
python -m file_analyzer.main . --component census --emit repo_tables.json

# Census + the file->analyzer mapping and per-class shards
python -m file_analyzer.main . --component census --mapping --emit repo_tables.json
```

`--mapping` additionally emits `mapping` and `shards` keys (via
`build_mapping` + `group_into_shards`).

### Docker (component mode in a container)

The `engine` service runs `python -m file_analyzer.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component census --mapping --emit /artifacts/census.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component census --mapping --emit /artifacts/census.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`; output lands in `ARTIFACTS_DIR` (default `./artifacts`).

### Python

```python
from file_analyzer.engine import RepositoryAnalyzer

repo = RepositoryAnalyzer(
    dir_path=".",
    dump_file_type="memory",      # engine/component mode pins this
    git_tracked=True,
    list_order_type="bfs",
)
generated = repo.generate()
if generated is None:
    raise RuntimeError("census produced no files (not a git repo? try git_tracked=False)")
folders, extensions, files = generated
```

(Mirrors `main.py`'s `_run_census`.)

## Output

Three table families (the same the `v_*` file/extension/folder views read):

| table | columns |
|-------|---------|
| `folders` | `folder_id`, `folder_name` (posix path; root is `.` with id 1), `parent_folder_id` |
| `extensions` | `extension_id`, `extension_name` (the exact "everything after the first dot" string; `None` for no extension, id `0`) |
| `files` | `file_id`, `file_name`, `file_extension_id`, `size`, `units`, `location` (list of folder ids, root-first), `created_at_ts64`, `modified_at_ts64` |

Views that read these: `v_file_inventory`, `v_extension_distribution`,
`v_folder_tree_depth` (see `file_analyzer/views/sql/catalog.json`).

## How it fits the pipeline

First stage of the chain. `AnalysisEngine.run()` calls `generate()` then
`emit_analyzer_mapping(temp_dir)`; the resulting `mapping.json` shards drive the
router planes, and the three tables become `folder_tables` for
`RepositoryDatabaseGenerator` and the `repository_tables` for
`ImportLinkageAnalyzer`.

## Notes & gotchas

- **`generate()` returns `None`, not `[]`, when git fails.** Callers must
  check for `None` (the engine raises, `main.py` returns exit 1).
- **`ignore_dirs` override is total.** Supplying it replaces the built-in
  default set — re-list `__pycache__`/`.git`/`.venv` etc. if you still want them
  skipped. It only takes effect on the `git_tracked=False` walk (git-tracked
  files are already filtered by git itself).
- **Extension ids are catalog-backed and globally stable.** Known extensions get
  their id from `file_extensions.json`; unknown/compound suffixes (e.g.
  `tar.gz`, `min.js`) get a deterministic hashed id at/above `10_000_000` so the
  same suffix maps identically across the main DB and every nested archive DB.
- **Extension key is "after the first dot".** `file_name` is the part before the
  first dot; the extension is everything after, so `archive.tar.gz` →
  name `archive`, extension `tar.gz`.
- **Timestamps are packed uint64 stored two's-complement signed** (`created_at_ts64`
  / `modified_at_ts64`) via `pack_timestamp64` + `as_signed64`; `None` when the
  file is gone or the epoch is unrepresentable (never fabricated). Use
  `unpack_timestamp64` to decode.
- **The 9-bit `tz_id` in each timestamp is a foreign key into the IANA timezone
  tables** in [`file_analyzer/tables/`](../../packages/engine/file_analyzer/tables), built verbatim from the IANA tz
  database (data.iana.org):
  - `iana_local_timezones.json` (used when the `local_tz` flag = **1**) — the
    comprehensive per-zone catalog: one row per real IANA canonical zone
    (`America/New_York`, `Asia/Kolkata`, …) plus the `Etc/GMT*` fixed-offset zones.
  - `iana_global_timezones.json` (flag = **0**) — the UTC-offset grid: one row per
    distinct standard offset, pointing back to the local rows at that offset.
  Each table's primary key `timezone_id` is a plain 1-based auto-increment id
  (local 1–339, global 1–37). The 9-bit field does **not** hold that PK — it holds
  the offset bucket `round(utc_offset_seconds/900) + 256`, matched against the
  table's `tz_slot` column. Every global-grid row and the `Etc/GMT*` rows of the
  local catalog carry a `tz_slot`, so a value derived only from an offset — all a
  bare mtime yields — resolves **directly** in either table. Call
  `resolve_timezone64(tz_id_value, local_tz)` to get the row; it returns `None` when
  no row carries that slot rather than inventing a zone.
- **`dump_file_type="memory"` writes nothing to disk** — the engine and
  component mode use it so the census leaves no stray `repo_export.json`.

## See also

- [../USAGE.md](../USAGE.md)
- [README.md](README.md), [analysis-engine.md](analysis-engine.md), [import-linkage.md](import-linkage.md), [db-generator.md](db-generator.md)
