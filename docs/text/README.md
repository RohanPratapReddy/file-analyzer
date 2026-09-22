# TextualAnalyzer — the text-record plane

**Package:** `file_analyzer/text` · **Import:** `from file_analyzer import TextualAnalyzer` · **Component:** `text`

## What it does
`TextualAnalyzer` decomposes one text-record *file* into normalized, relational
`document → sections → records → fields` tables. For every extension of the seven
*text-record* content kinds (`data_text`, `text`, `log`, `documentation`,
`template`, `scientific_data`, `subtitle`) it runs a real, pure-stdlib,
structure-aware parser (in `file_analyzer/text/textual_formats.py`) and flattens the result:

- one **section** row per top-level grouping (a caption track, a log event
  stream, a man-page `.SH` block, a template directive list, a bibliographic
  entry, an EDI segment group, …),
- one **record** row per entry inside a section (a caption cue, a log line, a
  checksum, a G-code command, a JSON object, a table row, …),
- one **field** row per typed name/value pair on a record.

Honesty contract (shared with the config plane): content is sniffed first, an
inherently-binary payload degrades to an honest forensic byte profile with no
fabricated records, credential material (e.g. JWT signatures) is redacted and
never decoded, the raw payload is never stored, and a partial parse is reported
`partial` — never stubbed.

## Formats / extensions handled   (from source; qualitative unless verified)
The extension universe is defined by `textual_formats.known_exts()` /
`routing_suffixes()`, spanning the seven text-record content kinds above
(data-text, plain text, logs, documentation, templates, scientific data,
subtitles). Exact suffix membership comes from `textual_formats`; do not
hard-code a list.

## Run it standalone
### CLI (component mode)
```bash
python -m file_analyzer.main . --component text --emit text.json
```

### Docker (component mode in a container)

The `engine` service runs `python -m file_analyzer.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component text --emit /artifacts/text.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component text --emit /artifacts/text.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`.

### Python
```python
from file_analyzer import TextualAnalyzer
eng = TextualAnalyzer(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code plane: also rewrite local ids -> repository ids and build the index
# eng.link_repository((folders, extensions, files), paths); tables = eng.get_tables()
```

Constructor: `TextualAnalyzer(file_paths, dump_file_path="text_analysis.json",
dump_file_type="memory")`. Public methods verified in source: `analyze()`,
`get_tables()`, `link_repository(repository_tables, analyzed_file_paths=None)`,
plus classmethods `routing_suffixes()` / `_known_exts()`.

## Output tables (real names)
From `get_tables()`:

- `text_files_table` — `text_file_id`, `file_name`, `extension`, `content_kind`,
  `syntax_family`, `parse_engine`, `format_label`, `detected_via`,
  `format_class`, `size_bytes`, `encoding`, `line_count`, `section_count`,
  `record_count`, `field_count`, `property_count`, `analysis_status`, `notes`, `file_id`
- `text_sections_table` — `text_section_id`, `text_file_id`, `section_name`,
  `section_path`, `section_type`, `ordinal`, `record_count`, `notes`, `file_id`
- `text_records_table` — `text_record_id`, `text_file_id`, `text_section_id`,
  `record_index`, `record_type`, `record_label`, `start_line`, `end_line`,
  `field_count`, `text_preview`, `notes`, `file_id`
- `text_fields_table` — `text_field_id`, `text_record_id`, `text_file_id`,
  `text_section_id`, `field_name`, `field_key`, `field_type`, `field_value`,
  `ordinal`, `file_id`
- `text_properties_table` — `property_id`, `text_file_id`, `property_name`,
  `property_value`, `value_type`, `group_name`, `file_id`
- `text_file_index` — `tfi_id`, `file_id`, `entity_kind`, `entity_id`
  (populated by `link_repository`)

Together these are the `text_tables` family consumed by
`RepositoryDatabaseGenerator` (`text_tables=` argument).

## How it fits the pipeline (routing id; link_repository step)
Routing id is `text`. In `file_analyzer/router/routing.py`, `resolve_analyzer` checks
`text` after config (and every higher-priority plane); the text suffix set
already subtracts those planes, so only previously-residual text extensions route
here. As a non-code plane it runs `link_repository((folders, extensions, files),
paths)` after `analyze()` to rewrite each row's local `file_id` to the repository
`file_details.file_id` and build `text_file_index`; the final tables come from
`get_tables()`.

## Notes & gotchas (only verified ones)
- One bad file never aborts the batch — parse/emit failures are caught, warned,
  and skipped.
- No `v_*` analysis views are defined for this plane; `file_analyzer/views/catalog.py`
  covers only the core/schema/data view families (no `v_text_*` view).

## See also — [../USAGE.md](../USAGE.md)
