# DataAnalyzer — metadata/stats/sampling-only data profiler

**Package:** `file_analyzer/data` · **Import:** `from file_analyzer import DataAnalyzer` · **Component:** `data`

## What it does

`DataAnalyzer` profiles *data* artifacts (not source code, not schema
definitions) and emits a normalized relational description of what each file
contains — structure, column/tensor shapes, per-column statistics and
inter-column correlations — **without ever storing the raw payload**.

The guiding constraint is that this is an *analysis, not a copy*: a 100 GB
parquet file is described by its row count, column list, dtypes, a capped
statistical sample and pairwise correlations, never by ingesting its contents.
Every handler reads only file metadata/headers or a bounded sample, governed by
explicit budgets (e.g. `SAMPLE_ROWS = 10000`, `MAX_COLUMNS = 4096`,
`MAX_SAMPLE_VALUES = 5`, correlation caps). When a file can only be partially
read, the dataset's `analysis_status` degrades honestly (e.g. `"partial"`) rather
than fabricating a stub.

## Formats handled (from source)

Routed by extension (curated `_EXT_*` sets checked before the
`docs/file_formats.json` catalog fallback). Qualitatively:

- **Tabular** — CSV/TSV/PSV and other delimited (`_EXT_DELIM`), Parquet/ORC/
  Arrow-Feather, Excel/ODS, JSON / JSON-Lines record sets, SQLite databases,
  Stata/SAS/SPSS statistical files → columns, dtypes, exact-or-sampled row
  counts, per-column stats and numeric pairwise correlations.
- **Tensors / ML models** — `.safetensors`, `.npy`/`.npz`, PyTorch
  `.pt/.pth/.ckpt/.pt2`, GGUF, ONNX, plus ML containers: ONNX Runtime `.ort`,
  TFLite, Keras v3, Flax/JAX msgpack, TFRecord, raw protobuf/GraphDef → tensor
  names, dtypes, shapes, element/byte counts (feeds `data_tensors_table` and
  `data_model_layers_table`); see `file_analyzer/data/model_formats.py`.
- **Images** — raster & vector via Pillow (`_EXT_IMAGE`) → format, mode,
  dimensions, channels, frame counts, embedded metadata.
- **Audio** — WAV/AIFF deep header parse + compressed formats (`_EXT_AUDIO`) →
  channels, sample rate, bit depth, duration.
- **Video** — containers (`_EXT_VIDEO`) → resolution, fps, frame count, duration,
  codec.
- **Documents** — PDF, DOCX, plain text / markdown / rST (`_EXT_PDF/_DOCX/_TEXT`)
  → page/paragraph/line/word/char counts and metadata.
- **Mesh / geospatial / graph / bio** — 3D meshes & point clouds (`_EXT_MESH`),
  vector & raster geo (`_EXT_GEO`, `_EXT_GEORASTER`, `.gml` sniff), graph/network
  (`_EXT_GRAPH`), bio/chem sequence & structure (`_EXT_BIO`), medical imaging
  (`_EXT_MEDICAL`, technical tags only, no PII) → record/feature/vertex/node
  counts, bounding boxes, CRS.
- **Serialization** — pickle/joblib via opcode scan, **no code execution**
  (`_EXT_PICKLE`).
- **Science + asset-text + catalog formats** — see `file_analyzer/data/science_formats.py`,
  `file_analyzer/data/asset_text_formats.py`, and the catalog wiring in
  `file_analyzer/data/catalog_text_formats.py` / `catalog_binary_formats.py`.
- **Everything else** → a generic descriptor (size + magic bytes + catalog
  classification).

## Run it standalone

### CLI (component mode)

```bash
python -m file_analyzer.main . --component data --emit data.json
```

### Docker (component mode in a container)

The `engine` service runs `python -m file_analyzer.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component data --emit /artifacts/data.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component data --emit /artifacts/data.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`.

### Python

```python
from file_analyzer import DataAnalyzer
eng = DataAnalyzer(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code plane: rewrite local file ids -> repository file ids and populate
# data_file_index, exactly like the per-shard worker:
eng.link_repository((folders, extensions, files), paths)
tables = eng.get_tables()
```

Constructor signature:
`DataAnalyzer(file_paths, dump_file_path="data_analysis.json", dump_file_type="memory")`.

## Output tables (real names)

`analyze()`/`get_tables()` emit these seven:

| table | holds |
|-------|-------|
| `data_datasets_table` | one row per file (category/subcategory, modality, format, size, row/column/record/tensor counts, `analysis_status`, `properties`) |
| `data_columns_table` | per-column stats (data + inferred type, null/non-null/unique counts, min/max/mean/std, sample values) |
| `data_tensors_table` | tensors (dtype, shape, rank, element/byte counts) |
| `data_relations_table` | inter-column relations (e.g. `pearson_correlation`, left/right column, value) |
| `data_properties_table` | flattened technical properties grouped by `group_name` |
| `data_model_layers_table` | model-layer breakdown for ML container formats |
| `data_file_index` | `dfi_id, file_id, entity_kind, entity_id` — populated by `link_repository` |

Analysis views in `file_analyzer/views/catalog.py` that read these:
`v_data_datasets_by_modality`, `v_data_datasets_by_category`,
`v_data_datasets_by_format`, `v_data_analysis_status`, `v_data_largest_tabular`,
`v_data_columns_by_inferred_type`, `v_data_top_correlations`,
`v_data_tensors_by_dtype`, `v_data_largest_tensors`,
`v_data_properties_by_group`, `v_data_entities_per_file`. (No view currently
reads `data_model_layers_table`; a view materializes only when all its base
tables are present.)

## How it fits the pipeline

Routing id `data` (see `resolve_analyzer` in `file_analyzer/router/routing.py`), checked
after `code`, `schema`, `database`, `archive` and `binary` — so a data-owned
suffix is never shadowed and code/schema/database/binary extensions win first. As
a non-code plane, the `data` component (and the real per-shard worker) runs
`link_repository()` after `analyze()` to rewrite local file ids to repository ids
and fill `data_file_index`. Note the `data` plane's owned suffixes derive from
`_known_exts`, so no extra routing wiring is needed when new data formats are
added.

## Notes & gotchas

- **Never stores raw payload** — only counts, header/metadata, bounded samples
  and derived statistics. Bounded by the class-level budgets (`SAMPLE_ROWS`,
  `MAX_COLUMNS`, `MAX_SAMPLE_VALUES`, `SAMPLE_VALUE_CHARS`, `CORR_*`, the various
  `MAX_*_BYTES` ceilings).
- **Honest degradation** — a file that cannot be fully read yields a `"partial"`
  (or otherwise honest) `analysis_status` and whatever it could measure, never a
  fabricated stub.
- **No code execution** — pickle/joblib are inspected by opcode scan only; the
  payload is never unpickled/executed.
- **IDs are 1-based and disjoint per entity kind**; rows start with a local
  `file_id` that only `link_repository()` makes repository-global.

## See also — [../USAGE.md](../USAGE.md)
