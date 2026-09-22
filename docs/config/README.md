# ConfigAnalyzer — the configuration-file plane

**Package:** `file_analyzer/config` · **Import:** `from file_analyzer import ConfigAnalyzer` · **Component:** `config`

## What it does
`ConfigAnalyzer` decomposes one configuration *file* into normalized, relational
key/value tables. For every `config`-type extension it recognizes, it runs a
real, pure-stdlib parser (in `file_analyzer/config/config_formats.py`) that turns the file
into a canonical nested Python object (`dict` / `list` / scalar), then flattens
that tree into fully-normalized `config_*` tables:

- one **key** node per position in the config tree (name + path + parent),
- one **value** row per key node carrying the typed value (`DICT` / `LIST` /
  `STRING` / `INT` / `FLOAT` / `BOOL` / `NULL` / `BYTES`) linked to its parent key,
- top-level containers grouped into **sections** (INI `[section]`, systemd unit
  groups, TOML tables, deb822 stanzas, registry keys, …).

Honesty contract (shared with the database plane): content is sniffed first, a
binary payload degrades to an honest forensic byte profile with no fabricated
keys, credential digests are redacted, the raw payload is never stored, and a
partial parse is reported `partial` — never stubbed. Tree flattening is capped at
20000 nodes per file (`_NODE_BUDGET`); truncation is noted on the file row.

## Formats / extensions handled   (from source; qualitative unless verified)
The plane's extension universe is defined by `config_formats.known_exts()` /
`routing_suffixes()`. The module docstring describes it as the `config`-type
residual extensions (~57 syntax families) — INI, systemd unit files, TOML,
deb822/Debian control stanzas, registry, and other key/value config syntaxes.
Exact suffix membership comes from `config_formats`; do not hard-code a list.

## Run it standalone
### CLI (component mode)
```bash
python -m file_analyzer.main . --component config --emit config.json
```

### Docker (component mode in a container)

The `engine` service runs `python -m file_analyzer.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component config --emit /artifacts/config.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component config --emit /artifacts/config.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`.

### Python
```python
from file_analyzer import ConfigAnalyzer
eng = ConfigAnalyzer(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code plane: also rewrite local ids -> repository ids and build the index
# eng.link_repository((folders, extensions, files), paths); tables = eng.get_tables()
```

Constructor: `ConfigAnalyzer(file_paths, dump_file_path="config_analysis.json",
dump_file_type="memory")`. Public methods verified in source: `analyze()`,
`get_tables()`, `link_repository(repository_tables, analyzed_file_paths=None)`,
plus classmethods `routing_suffixes()` / `_known_exts()`. With
`dump_file_type` other than `"memory"`, `analyze()` also writes the JSON dump.

## Output tables (real names)
From `get_tables()`:

- `config_files_table` — per-file profile (`config_file_id`, `file_name`,
  `extension`, `syntax_family`, `parse_engine`, `format_label`, `detected_via`,
  `format_class`, `size_bytes`, `encoding`, `root_type`, `section_count`,
  `key_count`, `value_count`, `property_count`, `max_depth`, `analysis_status`,
  `notes`, `file_id`)
- `config_sections_table` — `section_id`, `config_file_id`, `section_name`,
  `section_path`, `section_type`, `parent_section_id`, `key_count`, `notes`, `file_id`
- `config_value_keys_table` — `config_value_key_id`, `config_file_id`,
  `section_id`, `config_value_key_name`, `key_path`,
  `config_value_parent_key_id`, `depth`, `node_type`, `child_count`, `file_id`
- `config_values_table` — `config_value_id`, `config_value_key_id`,
  `config_file_id`, `section_id`, `config_value_parent_key_id`,
  `config_value_type`, `scalar_value`, `list_index`, `is_leaf`, `file_id`
- `config_properties_table` — `property_id`, `config_file_id`, `property_name`,
  `property_value`, `value_type`, `group_name`, `file_id`
- `config_file_index` — `cfi_id`, `file_id`, `entity_kind`, `entity_id`
  (populated by `link_repository`)

Together these are the `config_tables` family consumed by
`RepositoryDatabaseGenerator` (`config_tables=` argument).

## How it fits the pipeline (routing id; link_repository step)
Routing id is `config`. In `file_analyzer/router/routing.py`, `resolve_analyzer` checks
`config` **after** code / schema / database / archive / binary / data /
binary-format — the config suffix set already subtracts every higher-priority
plane, so only previously-residual config extensions route here. As a non-code
plane, the per-shard worker (and `main.py` component mode) runs
`link_repository((folders, extensions, files), paths)` after `analyze()` to
rewrite each row's local `file_id` to the repository `file_details.file_id` and
build `config_file_index`; the final tables come from `get_tables()`.

## Notes & gotchas (only verified ones)
- Tree flattening is capped at 20000 nodes per file; on truncation the file row's
  `notes` records `tree truncated at <N> nodes`.
- One bad file never aborts the batch — parse/emit failures are caught, warned,
  and skipped.
- No `v_*` analysis views are defined for this plane. `file_analyzer/views/catalog.py`
  covers only the core/schema/data view families; there is no `v_config_*` view.

## See also — [../USAGE.md](../USAGE.md)
