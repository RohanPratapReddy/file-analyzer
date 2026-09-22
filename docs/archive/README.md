# ArchiveAnalyzer — the archive-traversal pipeline stage

**Package:** `file_analyzer/archive` · **Import:** `from file_analyzer import ArchiveAnalyzer` (re-exported) · **Pipeline stage:** archive containers (step 4b in `AnalysisEngine.run()`; **no `--component`** — controlled by `--no-archives` / `--max-archive-depth`).

## What it does

`ArchiveAnalyzer` is the dedicated post-planes stage that owns the `archive`
routing class (zip/tar/compression *containers*). For every container the router
assigns to it, the stage:

1. **censuses the members** (name / kind / uncompressed size / compressed size /
   mtime) straight from the archive index — no extraction needed for the census,
   so it is cheap even for very large archives;
2. **extracts** the container into
   `<main temp>/sandbox/arc_<file_id>/extracted/`, guarded against zip-bombs by a
   member-count cap (`MAX_MEMBERS = 100_000`) and a total-uncompressed-size cap
   (`MAX_EXTRACT_BYTES = 2 GiB`), and against path traversal by the stdlib zip
   name sanitizer / the tar `data` filter;
3. **runs a *nested* `AnalysisEngine`** over the extracted tree (`git_tracked`
   off, `_archive_depth = depth + 1`). The nested run recurses into any archives
   it finds, one level deeper, up to `max_archive_depth`, producing a
   self-contained per-archive sub-database;
4. **links back** to the main database through the `archive_index` /
   `archive_members` relational tables. `archive_index.sub_database` holds the
   absolute path of the nested database, which a consumer can `ATTACH` for the
   full extracted-tree analysis.

It never re-implements analysis and never re-profiles archive *contents* itself —
all real analysis of extracted files goes back through the one `AnalysisEngine`
pipeline. Nested sub-databases are written **beside the main database** in
`<db_stem>_archives/` (they cannot live under `temp/`, which is wiped on success).

Data-meaningful single-file containers (`.npz` / `.docx` / `.xlsx` / `.pdf` /
`.glb` / `.gpkg` / `.ods`) are **not** archives here — they stay with
`DataAnalyzer`, which profiles them in place.

## Formats handled (from source)

Classification (`_classify`) is by true (last-component) suffix **and** by a
magic-byte header sniff, so a file whose extension is proprietary but whose bytes
are a standard container is still fully extracted (e.g. many `.obb` / `.tpz` are
ZIP/gzip).

Real extraction, in order of preference:

- **Standard library, always available:** the ZIP family and spec-guaranteed-ZIP
  packages (`.zip` / `.epub` / `.jar` / `.war` / `.apk` / `.whl` / `.xpi` /
  `.vsix` / `.nupkg` / `.asice` / `.siard` / `.pk3` / … — see `_ZIP_EXTS`),
  single-stream `gzip` / `bzip2` / `xz` / `lzma`, and `tar` (plain and
  transparently gzip/bzip2/xz-compressed, incl. `.mbz` Moodle backups and
  `.webdataset` shards).
- **Optional package if importable:** `zstandard` (`.zst` / `.tzst`), `7-Zip`
  (`.7z`), `brotli` (`.br`), `lz4` (`.lz4`), `snappy` (`.sz`), `rar` (`.rar`).
  When the backing package is missing the row degrades to
  `extraction_status = 'no-codec'` — honest metadata, never a stub extraction.
- **Recognised but no codec here** (`.ace` / `.arj` / `.lha` / `.lzh` / `.cab` /
  `.cpio` / `.sit` / `.zoo` / `.hqx` / proprietary game & enterprise containers —
  see `_NOCODEC_FORMATS`) and **split-volume parts** (`.001` / `.r00` / `.z01`,
  see `_SPLIT_PARTS`) are catalogued with their format label + compressed size and
  a `no-codec` status. The full recognised set is enumerated in `docs/archive.json`.

`extraction_status` values seen in `archive_index`: `extracted`, `no-codec`,
`depth-capped`, `truncated`, `unsupported`, `missing`, `empty`, `error`.

## How it runs (full pipeline)

Controlling flags: **`--no-archives`** (skip the stage entirely) and
**`--max-archive-depth N`** (default `8`; bounds the nested recursion).

There is **no standalone component mode** for this stage. It is **not** in
`main.py`'s `_SPECIAL_COMPONENTS`, `_PLANE_COMPONENTS`, or
`_lang_analyzer_registry()`, so `python -m file_analyzer.main --component archive` is not a
valid invocation and it does not appear in `--list-components`. It runs only
inside the full pipeline:

```bash
# archive traversal on (default), bounded to 4 nested levels
python -m file_analyzer.main <repo> --out ./artifacts --max-archive-depth 4

# skip archive extraction/recursion entirely
python -m file_analyzer.main <repo> --out ./artifacts --no-archives
```

`AnalysisEngine` invokes it as: gather `mapping["mapping"]` rows whose
`analyzer_class == "archive"`, then `ArchiveAnalyzer(self, archive_files).process()`.

### Docker

This stage runs as part of the full pipeline inside the `engine` service
(compose profile `engine`, entrypoint `python -m file_analyzer.main`); control it with the
same flags:

```bash
# bound nesting depth:
docker compose --profile engine run --build engine \
  /workspace --out /artifacts --max-archive-depth 4
# disable the stage:
docker compose --profile engine run --build engine \
  /workspace --out /artifacts --no-archives
```

Or set them via `ENGINE_ARGS="/workspace --out /artifacts --no-archives"`. Set
`SOURCE_DIR` to choose the mounted repo (mounts at `/workspace`); artifacts are
written to `/artifacts` (`ARTIFACTS_DIR`). Nested per-archive sub-databases land
under `/artifacts` alongside the main database.

## Python (direct use)

The constructor takes the owning engine (it reads `temp_dir`, `db_path`,
`sql_dialect`, `workers`, `python_exe`, `_archive_depth`, `max_archive_depth`,
etc. off it) and the pre-selected archive rows — so direct use in isolation is
awkward; normally you let `AnalysisEngine` drive it. The shape is:

```python
from file_analyzer import ArchiveAnalyzer

# `engine` is the owning AnalysisEngine; archive_files are router rows
# [{"file_id": ..., "file_location": ...}, ...] for the `archive` class.
analyzer = ArchiveAnalyzer(engine, archive_files)
tables = analyzer.process()   # {"archive_index": [...], "archive_members": [...]}
```

## Output tables (real family names)

The stage returns the `archive_tables` family (the `--tables-json` /
`RepositoryDatabaseGenerator` keyword name) containing two tables:

- **`archive_index`** — one row per container: `archive_id`, `file_id`,
  `archive_name`, `archive_format`, `member_count`, `compressed_size`,
  `extracted_size`, `extractable`, `extraction_status`, `sub_database`,
  `sub_file_count`, `sub_shard_summary`, `depth`, `notes`.
- **`archive_members`** — one row per member (capped at `MAX_MEMBER_ROWS = 5000`
  per archive): `member_id`, `archive_id` (FK → `archive_index`, ON DELETE
  CASCADE), `member_path`, `member_kind`, `member_size`, `compressed_size`,
  `modified`, `analyzer_class` (what the router *would* assign the member), and
  `file_id`.

**No `v_*` views** read these tables — `file_analyzer/views/catalog.py` defines no
`archive_*` views, so none are ever created. Query the base tables directly.

## Notes & gotchas

- **Honesty:** no codec ⇒ `extraction_status = 'no-codec'` (never a fake
  extraction); split-volume parts are catalogued, not reassembled; the raw
  payload is never persisted — extracted files live under `temp/sandbox` and are
  removed with `temp/` on success. Only the metadata tables and the nested
  sub-database survive.
- **Recursion depth:** each nested engine carries `_archive_depth = depth + 1`;
  once `depth >= max_archive_depth` the container is censused but not extracted
  (`extraction_status = 'depth-capped'`). Default max depth is 8.
- **Guards:** archives over `MAX_MEMBERS` members or `MAX_EXTRACT_BYTES`
  uncompressed are censused but not extracted (`truncated`).
- **Sub-databases persist:** `<db_stem>_archives/arc_<id>.db` + `_schema.sql`
  sit beside the main database. `ATTACH` them for the extracted-tree detail.
- One malformed archive never sinks the run — it is caught and recorded with an
  `error` status row.

## See also — [../USAGE.md](../USAGE.md)
