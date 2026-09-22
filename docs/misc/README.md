# MiscAnalyzer — the terminal (long-tail) plane

**Package:** `file_analyzer/misc` · **Import:** `from file_analyzer import MiscAnalyzer` · **Component:** `misc`

## What it does
`MiscAnalyzer` is the parent/super-class of the terminal `misc` analysis plane.
Every extension that survives all higher-priority planes (code / schema /
database / archive / binary / data / config / text / markup / document) and is
still a *structured, parseable* text format is dispatched to its own child parser
class (in `file_analyzer/misc/parsers.py`, each a `MiscTypeParser` subclass), and the
resulting real, structure-aware profile is flattened into normalized `misc_*`
tables in the shape `document → sections → records → fields (+ file-level
properties)`:

- one **section** row per top-level grouping (a QSS rule list, an OpenShot
  clip/file/effect list, a Camtasia source/track list, a pg_dump
  table/COPY/statement list),
- one **record** row per entry inside a section (a style rule, a timeline clip, a
  media source, a `CREATE TABLE`, a `COPY` block, …),
- one **field** row per typed name/value pair on a record.

Honesty contract (shared with text/config/document): content is sniffed first, an
inherently-binary payload degrades to an honest forensic byte profile with no
fabricated records, credential material is never decoded into its secret content,
the raw payload is never stored, and a partial parse is reported `partial`.

## Formats / extensions handled   (from source; qualitative unless verified)
The extension universe is defined by `misc_formats.known_exts()` /
`routing_suffixes()`, built from the child-parser registry
(`parsers.build_registry()`). Verified child parsers and their extensions:

- `StylesheetParser` — `.qss` (Qt Style Sheet, CSS-like widget styling)
- `VideoProjectParser` — `.osp` (OpenShot project, JSON clip timeline),
  `.tscproj` (Camtasia project, JSON scene/media tree)
- `SqlDumpParser` — `.pgdump` (PostgreSQL `pg_dump` SQL script)

These are the last long-tail formats; exact membership comes from `misc_formats`
/ `parsers`.

## Run it standalone
### CLI (component mode)
```bash
python -m file_analyzer.main . --component misc --emit misc.json
```

### Docker (component mode in a container)

The `engine` service runs `python -m file_analyzer.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component misc --emit /artifacts/misc.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component misc --emit /artifacts/misc.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`.

### Python
```python
from file_analyzer import MiscAnalyzer
eng = MiscAnalyzer(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code plane: also rewrite local ids -> repository ids and build the index
# eng.link_repository((folders, extensions, files), paths); tables = eng.get_tables()
```

Constructor: `MiscAnalyzer(file_paths, dump_file_path="misc_analysis.json",
dump_file_type="memory")`. Public methods verified in source: `analyze()`,
`get_tables()`, `link_repository(repository_tables, analyzed_file_paths=None)`,
plus classmethods `routing_suffixes()` / `_known_exts()`.

## Output tables (real names)
From `get_tables()`:

- `misc_files_table` — `misc_file_id`, `file_name`, `extension`, `content_kind`,
  `syntax_family`, `parse_engine`, `format_label`, `detected_via`,
  `format_class`, `size_bytes`, `encoding`, `line_count`, `section_count`,
  `record_count`, `field_count`, `property_count`, `analysis_status`, `notes`, `file_id`
- `misc_sections_table` — `misc_section_id`, `misc_file_id`, `section_name`,
  `section_path`, `section_type`, `ordinal`, `record_count`, `notes`, `file_id`
- `misc_records_table` — `misc_record_id`, `misc_file_id`, `misc_section_id`,
  `record_index`, `record_type`, `record_label`, `start_line`, `end_line`,
  `field_count`, `text_preview`, `notes`, `file_id`
- `misc_fields_table` — `misc_field_id`, `misc_record_id`, `misc_file_id`,
  `misc_section_id`, `field_name`, `field_key`, `field_type`, `field_value`,
  `ordinal`, `file_id`
- `misc_properties_table` — `property_id`, `misc_file_id`, `property_name`,
  `property_value`, `value_type`, `group_name`, `file_id`
- `misc_file_index` — `mfi_id`, `file_id`, `entity_kind`, `entity_id`
  (populated by `link_repository`)

Together these are the `misc_tables` family consumed by
`RepositoryDatabaseGenerator` (`misc_tables=` argument).

## How it fits the pipeline (routing id; link_repository step)
Routing id is `misc`. In `file_analyzer/router/routing.py`, `resolve_analyzer` checks
`misc` **last** of all planes; its suffix set already subtracts every other
plane, so only extensions that no earlier plane claimed route here. As a non-code
plane it runs `link_repository((folders, extensions, files), paths)` after
`analyze()` to rewrite each row's local `file_id` to the repository
`file_details.file_id` and build `misc_file_index`; the final tables come from
`get_tables()`.

## Notes & gotchas (only verified ones)
- **Wiring requires the class in `group_into_shards`.** Routing correctly returns
  `"misc"` for these files, but the per-shard fan-out only materializes shards for
  the classes listed in the `for cls in (...)` tuple inside `group_into_shards`
  (`file_analyzer/router/routing.py`). `"misc"` is present in that tuple today — if it is
  ever dropped, the shard never runs and the `misc_*` tables come back missing even
  though routing looks correct.
- `misc_file_index` uses the id prefix `mfi_id` — the same prefix name the markup
  plane uses; they are distinct tables in distinct families.
- One bad file never aborts the batch — parse/emit failures are caught, warned,
  and skipped; a binary payload under one of these extensions degrades to an
  honest forensic profile.
- No `v_*` analysis views are defined for this plane; `file_analyzer/views/catalog.py`
  covers only the core/schema/data view families (no `v_misc_*` view).

## See also — [../USAGE.md](../USAGE.md)
