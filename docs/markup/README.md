# MarkupAnalyzer — the markup plane

**Package:** `src/markup` · **Import:** `from src import MarkupAnalyzer` · **Component:** `markup`

## What it does
`MarkupAnalyzer` decomposes one markup *file* into normalized, relational tables
describing the tags/elements/sections present and the metrics of the content they
carry. For every residual *markup* extension it runs a real, pure-stdlib,
structure-aware parser (in `src/markup/markup_formats.py`) that decomposes the
document into `document → elements (+ attributes + namespaces) → sections +
properties`:

- one **element** row per distinct tag/element name, with content metrics
  (occurrence count, min/max nesting depth, child fan-out, leaf vs. text-bearing
  instances, total text length, attribute names, and a text sample),
- one **attribute** row per distinct (element, attribute) pair (occurrence count,
  distinct-value count, inferred value type, sample),
- one **namespace** row per XML namespace declaration,
- one **section** row per structural section (direct children of the XML root, or
  the headings of a non-XML markup) with an outline path,
- one **property** row per document-level fact (XML declaration, DOCTYPE, root
  element, per-family metadata, honest forensic facts).

Honesty contract (shared with config/text): content is sniffed first; gzip-wrapped
markup is transparently decompressed; a ZIP-packaged vocabulary degrades to an
honest forensic note (members not extracted here); an inherently-binary payload
degrades to a forensic byte profile with no fabricated tags; the raw payload is
never stored (only names, counts, metrics, short samples); a partial parse is
reported `partial`.

## Formats / extensions handled   (from source; qualitative unless verified)
The extension universe is defined by `markup_formats.known_exts()` /
`routing_suffixes()`: HTML/XHTML vocabularies, the ~200 XML application dialects,
OFX SGML, and lightweight markups (wiki, gemtext, roff, typst, MIF, markdown).
Exact suffix membership comes from `markup_formats`; do not hard-code a list.

## Run it standalone
### CLI (component mode)
```bash
python -m src.main . --component markup --emit markup.json
```

### Docker (component mode in a container)

The `engine` service runs `python -m src.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component markup --emit /artifacts/markup.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component markup --emit /artifacts/markup.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`.

### Python
```python
from src import MarkupAnalyzer
eng = MarkupAnalyzer(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code plane: also rewrite local ids -> repository ids and build the index
# eng.link_repository((folders, extensions, files), paths); tables = eng.get_tables()
```

Constructor: `MarkupAnalyzer(file_paths, dump_file_path="markup_analysis.json",
dump_file_type="memory")`. Public methods verified in source: `analyze()`,
`get_tables()`, `link_repository(repository_tables, analyzed_file_paths=None)`,
plus classmethods `routing_suffixes()` / `_known_exts()`.

## Output tables (real names)
From `get_tables()` (six tables):

- `markup_files_table` — file profile (`markup_file_id`, …, `content_kind`,
  `markup_language`, `dialect_profile`, `well_formed`, `root_element`,
  `namespace_count`, `element_count`, `distinct_element_count`,
  `attribute_count`, `distinct_attribute_count`, `max_depth`, `comment_count`,
  `pi_count`, `cdata_count`, `text_length`, `section_count`, `property_count`,
  `analysis_status`, `notes`, `file_id`)
- `markup_elements_table` — `markup_element_id`, `markup_file_id`, `tag_name`,
  `qualified_name`, `namespace_prefix`, `namespace_uri`, `occurrence_count`,
  `min_depth`, `max_depth`, `total_child_count`, `max_children`, `leaf_count`,
  `text_bearing_count`, `total_text_length`, `distinct_attribute_count`,
  `attribute_names`, `sample_text`, `is_root`, `ordinal`, `file_id`
- `markup_attributes_table` — `markup_attribute_id`, `markup_file_id`,
  `markup_element_id`, `element_tag`, `attribute_name`, `namespace_prefix`,
  `occurrence_count`, `distinct_value_count`, `value_type`, `sample_value`,
  `min_length`, `max_length`, `file_id`
- `markup_namespaces_table` — `markup_namespace_id`, `markup_file_id`, `prefix`,
  `uri`, `is_default`, `element_usage_count`, `file_id`
- `markup_sections_table` — `markup_section_id`, `markup_file_id`,
  `section_name`, `section_type`, `section_path`, `depth`, `ordinal`,
  `element_tag`, `child_count`, `text_length`, `title`, `file_id`
- `markup_properties_table` — `property_id`, `markup_file_id`, `property_name`,
  `property_value`, `value_type`, `group_name`, `file_id`
- `markup_file_index` — `mfi_id`, `file_id`, `entity_kind`, `entity_id`
  (populated by `link_repository`)

Together these are the `markup_tables` family consumed by
`RepositoryDatabaseGenerator` (`markup_tables=` argument).

## How it fits the pipeline (routing id; link_repository step)
Routing id is `markup`. In `src/router/routing.py`, `resolve_analyzer` checks
`markup` after text (and every higher-priority plane); the markup suffix set
already subtracts those planes, so only previously-residual markup extensions
route here. As a non-code plane it runs `link_repository((folders, extensions,
files), paths)` after `analyze()` to rewrite each row's local `file_id` to the
repository `file_details.file_id` and build `markup_file_index`; the final tables
come from `get_tables()`.

## Notes & gotchas (only verified ones)
- The `markup_file_index` id prefix is `mfi_id` — the same prefix name the misc
  plane uses; they are distinct tables in distinct families.
- One bad file never aborts the batch — parse/emit failures are caught, warned,
  and skipped.
- No `v_*` analysis views are defined for this plane; `src/views/catalog.py`
  covers only the core/schema/data view families (no `v_markup_*` view).

## See also — [../USAGE.md](../USAGE.md)
