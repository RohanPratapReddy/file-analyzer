# router — pure-Python file→analyzer routing and per-shard staging

**Package:** `src/router` · **Import:** `from src.router import resolve_analyzer, build_mapping, group_into_shards, reconstruct_paths, ANALYZER_CLASSES, RouterPlanes, PlaneError` (this package is **not** re-exported from the `src` top level — it is internal, imported by `AnalysisEngine`/`RepositoryAnalyzer`) · CLI: none (routing has no `--component` mode — see below)

## What it does

`router` is the pure-Python layer that decides *which analyzer plane owns each
file* and *how the census is partitioned* for the concurrent Go/Java/Python
analysis planes. It has three responsibilities, split across four modules:

- **`routing.py`** — the routing decision (`resolve_analyzer`), path
  reconstruction (`reconstruct_paths`), the file→analyzer census
  (`build_mapping`), and shard grouping (`group_into_shards`). Deliberately
  free of heavy imports: the analyzer engines are imported *lazily* (only when
  a plane's extension universe is first needed), so `RepositoryAnalyzer` can
  import it cheaply just to build the mapping.
- **`planes.py`** — `RouterPlanes`, the coordinator that runs the Go and Java
  planes concurrently (with a Python fallback), building each toolchain on
  demand.
- **`worker.py`** — the per-shard analysis worker CLI each plane fans out to as
  a subprocess.
- **`go/`, `java/`** — the Go (`plane.go`) and Java (`AnalyzerPlane.java`)
  plane drivers that invoke `worker.py`; they never touch the database.

Routing keys on the **true (last-component) lowercase suffix** — e.g.
`foo.tar.gz` and `bar.csv.gz` both resolve via `.gz`, so an archive stage can
decompress and re-route the extracted member on its own merits.

## Key APIs / functions (real names + signatures from source)

From `src/router/routing.py`:

- `resolve_analyzer(name_or_path: Union[str, Path]) -> Optional[str]` — map a
  filename/path to its analyzer-class id, or `None` if no plane claims the
  suffix. This is the single routing decision function.
- `build_mapping(dir_path, folders, extensions, files) -> List[Dict]` — produce
  the total file→analyzer census: one row per file
  `{"file_id", "file_location", "analyzer_class"}`. Unclaimed files are still
  emitted with `analyzer_class == None` (a faithful, total census).
- `group_into_shards(mapping: List[Dict]) -> List[Dict]` — group the mapping
  into one shard per plane-driven analyzer class:
  `{"shard_id": "shard_<cls>", "analyzer_class", "file_ids", "file_paths"}`.
- `reconstruct_paths(dir_path, folders, extensions, files) -> Dict[int, Path]`
  — rebuild each file's absolute on-disk path from the relational census tables,
  keyed by `file_id`.
- `ANALYZER_CLASSES: Dict[str, str]` — logical class id → flat-façade class name
  the worker imports (e.g. `"code" -> "PolyglotCodeAnalyzer"`).

From `src/router/planes.py`:

- `class RouterPlanes(readers_root, temp_dir, python_exe=None, workers_per_plane=None)`
  with `run(shards: List[Dict]) -> None`. Partitions shard ids across two
  planes (deterministic: even indices → Go, odd → Java), builds `go build` /
  `javac` on demand, runs both planes on the same wall clock, and falls back to
  an in-process Python worker pool for any plane whose toolchain is missing.
  Verifies every shard produced a `temp/status/<shard_id>.ok` marker and raises
  `PlaneError` (retaining `temp/`) otherwise.
- `class PlaneError(RuntimeError)` — raised when one or more shards fail.

From `src/router/worker.py`:

- `run_shard(readers_root, temp_dir, shard_id) -> Path` and a CLI `main()`
  (`python -m src.router.worker --readers-root … --temp … --shard …`). For each
  shard it loads `repo_tables.json` + `mapping.json`, runs the shard's engine
  over exactly that shard's files, calls `link_repository(...)` for every
  non-`code` plane (so local file_ids become repository file_ids and the
  `*_file_index` bridge is built), then writes `temp/tables/<shard_id>.json`
  plus a `.ok`/`.err` status marker.

### Plane priority order (verified against `resolve_analyzer` source)

`resolve_analyzer` checks the suffix against each plane's extension set in this
exact order and returns the first match:

```
code > schema > database > archive > binary > data
     > binary_format (→ "binary") > config > text > markup > document > misc
```

Notes on precedence, from the source:

- `binary_format` (the non-executable structural binary universe parsed by
  `BinaryFormatParser`) is checked **after** the semantic-data plane so a
  data-owned suffix is never shadowed; it returns the `"binary"` class id.
- Every set from `config` onward is computed by **subtracting all
  higher-priority planes' suffixes**, so each late plane can only add routes for
  previously-unrouted extensions — no earlier routing decision ever changes.
- Content-ambiguous `.json` / `.md` are intentionally routed to `data` (not
  `schema`); `SchemaAnalyzer` only claims suffixes that unambiguously identify a
  schema-definition language.
- `ANALYZER_CLASSES` lists 11 class ids (`code`, `schema`, `database`, `data`,
  `archive`, `binary`, `config`, `text`, `markup`, `document`, `misc`).

### Which classes become shards

`group_into_shards` emits shards **only** for the plane-driven engines, in this
tuple order:

```python
("code", "schema", "database", "data", "config", "text", "markup",
 "document", "misc")
```

`archive` and `binary` are deliberately excluded: archives are extracted and
recursed into by a nested `AnalysisEngine`, and binaries are deep-parsed by
`MachineCodeAnalyzer` — both are dedicated post-planes stages, not Go/Java
per-shard work. (The `binary_format` route also lands in the `binary` class, so
those files go through the binary stage too, not a shard.)

## CLI (views only)

Routing has **no standalone component / CLI mode.** It is internal machinery
invoked by `AnalysisEngine` (which constructs `RouterPlanes`) and by
`RepositoryAnalyzer` (which calls `build_mapping` / `group_into_shards`).

`python -m src.main --list-components` prints three groups — **special**
(`census`, `linkage`, `dbgen`), **planes** (`code`, `schema`, `database`,
`data`, `config`, `text`, `markup`, `document`, `misc`), and the
**language_analyzers** — and *routing is not among them*. Census, linkage, and
dbgen are the special runnable components; routing itself only ever runs as part
of the full pipeline (though `--component census --mapping` will emit the
file→analyzer mapping and shards that routing produced).

`src/router/worker.py` is executable as a subprocess (that is how the planes
invoke it), but it is a per-shard internal helper, not a user-facing command.

### Docker

Routing has no standalone entry point in Docker either — it runs **automatically
inside the `engine` container** during any full pipeline run (the engine stage's
`ENTRYPOINT` is `["python", "-m", "src.main"]`, and `src.main` invokes routing
internally):

```bash
# full run: routing fires as part of the pipeline
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  docker compose --profile engine run --build engine /workspace --out /artifacts
```

The components routing feeds — `census`, `linkage`, `dbgen` — ARE runnable
standalone in the same container via `--component` (routing itself is not; see
above). `--component census --mapping` will emit the file→analyzer mapping and
the shards routing produced:

```bash
docker compose --profile engine run --build engine \
  /workspace --component census --mapping --emit /artifacts/repo.json
```

## How it fits the pipeline

1. `RepositoryAnalyzer` censuses the tree (folders / extensions / files).
2. It calls `build_mapping(...)` → `group_into_shards(...)` to turn the census
   into per-plane shards, staged as `temp/mapping.json` + `temp/repo_tables.json`.
3. `AnalysisEngine` constructs `RouterPlanes(...)` and calls `run(shards)`,
   which drives the Go + Java planes (or the Python fallback) concurrently; each
   plane fans out to `worker.py`, one subprocess per shard.
4. Each worker writes `temp/tables/<shard_id>.json` and a status marker; the
   `archive` / `binary` stages run separately, and
   `RepositoryDatabaseGenerator` injects everything into the database.

## Notes & gotchas

- **`group_into_shards` tuple gotcha (critical).** A new analyzer plane class
  must be added to the class tuple inside `group_into_shards`
  (`("code", "schema", "database", "data", "config", "text", "markup",
  "document", "misc")`) — *and* to `ANALYZER_CLASSES`, `resolve_analyzer`, the
  worker's `engines` dict, and its `link_repository` branch. If the class is
  missing from the `group_into_shards` tuple, `build_mapping` may still route
  files to it, but **no shard is ever emitted**, the plane never runs, and its
  tables come back MISSING from the database — with no error. Wiring a new plane
  is a multi-touchpoint change; the shard tuple is the one most easily forgotten.
- **Priority is first-match, and late planes are subtractive.** Because each set
  from `config` onward subtracts every higher-priority plane's suffixes, adding
  a suffix to an early plane silently removes it from every later plane. Verify
  the intended plane wins by suffix, not by set membership alone.
- **Routing is by last-component suffix only.** Multi-part names like
  `foo.tar.gz` resolve on `.gz`; a file with no suffix returns `None`
  (unrouted). Files with no extension (e.g. a bare `LICENSE`) are never routed.
- **Lazy imports are load-bearing.** `routing.py` imports the heavy analyzer
  engines only inside the `_*_exts()` helpers, so importing it (e.g. from
  `RepositoryAnalyzer`) stays cheap. Keep new extension-universe lookups lazy.

## See also

- [../USAGE.md](../USAGE.md) — the `python -m src.main` entry point, full
  pipeline vs. component mode, and the component list.
- repo [README.md](../../README.md) — project overview and package layout
  (`src/router/` row).
