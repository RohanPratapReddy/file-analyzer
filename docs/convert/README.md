# FormatConverter (+ TextAnalyzer) — the conversion helpers

**Package:** `src/convert` · **Imports:** `from src import FormatConverter, TextAnalyzer` (both re-exported) · **Pipeline stage:** renderable transcoding (step 4d in `AnalysisEngine.run()`; **no `--component`** — controlled by `--no-conversions` / `--no-conversion-analysis` / `--conversions-dir`).

## What it does

The rest of the pipeline is strictly read-only — it *parses* files and never
rewrites them. `FormatConverter` is the one component that deliberately *produces*
a new artifact: it takes a file the analyzers cannot structurally parse (opaque /
legacy / proprietary) and, where genuinely feasible, transcodes it into a
renderable target a human or a browser/player can actually open:

```
images -> PNG      audio -> WAV      video -> MP4      text/legacy docs -> TXT / PDF
```

Two honest tiers:

- **Pure-Python (always available, zero dependencies):** real decoders for simple
  / legacy raster formats (Netpbm, BMP, QOI, farbfeld, Sun raster, TGA, PCX, XBM)
  re-encoded through a real stdlib PNG encoder (`encode_png`); Sun-AU and
  AIFF/AIFF-C PCM audio re-wrapped as WAV via the stdlib `wave` writer; RTF
  flattened to plain text.
- **External-engine delegation (only if the tool is on `PATH`):** most video,
  chiptune/console-music dumps, and proprietary office/editor documents are handed
  to `ffmpeg` / `soffice` (LibreOffice) / ImageMagick `magick` when present.

After conversion, `TextAnalyzer.analyze_conversions()` deep-parses each rendered
artifact and records per-format structural metrics as a 1:1 companion table.

The renderable universe is `RENDERABLE_TARGETS = {png, wav, mp4, pdf, txt, html,
gif}`.

## Formats handled (from source)

Format lists live in the module's decoder/handler tables — do not hard-code them
here; query them at runtime:

```python
FormatConverter().capabilities()   # pure_python + external routes actually available
```

`capabilities()` reports the pure-Python routes (`_IMAGE_DECODERS`,
`_AUDIO_HANDLERS`, `_TEXT_HANDLERS`), which external tools were found
(`ffmpeg` / `soffice` / `magick`), and the external routes those unlock
(`_FFMPEG_AUDIO`, `_FFMPEG_VIDEO`, `_SOFFICE_DOCS`, `_MAGICK_IMAGES`).
`target_for(name_or_ext)` returns the renderable target an extension *would* aim
for (or `None`); `can_convert(name_or_ext)` is `True` only when a route exists
**and** its tool is currently runnable.

## How it runs (full pipeline)

Controlling flags:

- **`--no-conversions`** — skip renderable transcoding entirely.
- **`--no-conversion-analysis`** — transcode, but skip the structural deep-parse
  of the rendered artifacts (`TextAnalyzer`).
- **`--conversions-dir PATH`** — output dir for rendered artifacts (default:
  `<db_stem>_renderable/` beside the db).

There is **no standalone component mode** for this stage. Neither
`FormatConverter` nor `TextAnalyzer` is in `main.py`'s `_SPECIAL_COMPONENTS`,
`_PLANE_COMPONENTS`, or `_lang_analyzer_registry()`, so
`python -m src.main --component convert` is not valid and it does not appear in
`--list-components`. It runs only inside the pipeline:

```bash
# transcode + analyze (default), custom output dir
python -m src.main <repo> --out ./artifacts --conversions-dir ./artifacts/renderable

# transcode but do not deep-parse the rendered artifacts
python -m src.main <repo> --out ./artifacts --no-conversion-analysis

# skip conversions entirely
python -m src.main <repo> --out ./artifacts --no-conversions
```

`AnalysisEngine` attempts every censused file with a renderable route
(`converter.target_for(...) is not None`) — so `tool_unavailable` is recorded too,
documenting what *could* be rendered given the right tool. Conversions are a
convenience layer, not load-bearing: any exception in this stage is caught and
recorded, never breaking an otherwise-successful run.

### Docker

This stage runs as part of the full pipeline inside the `engine` service
(compose profile `engine`, entrypoint `python -m src.main`); control it with the
same flags:

```bash
# transcode + analyze (default), custom rendered-artifact dir:
docker compose --profile engine run --build engine \
  /workspace --out /artifacts --conversions-dir /artifacts/renderable
# transcode but skip the structural deep-parse:
docker compose --profile engine run --build engine \
  /workspace --out /artifacts --no-conversion-analysis
# disable the stage:
docker compose --profile engine run --build engine \
  /workspace --out /artifacts --no-conversions
```

Or set them via `ENGINE_ARGS="/workspace --out /artifacts --no-conversions"`. Set
`SOURCE_DIR` to choose the mounted repo (mounts at `/workspace`); artifacts are
written to `/artifacts` (`ARTIFACTS_DIR`). Keep `--conversions-dir` under
`/artifacts` so rendered files land on the writable mount.

## Python (direct use)

```python
from src import FormatConverter, TextAnalyzer

conv = FormatConverter(allow_external=True)      # allow_external=False = hermetic
conv.target_for("legacy.pcx")                    # -> "png" (or None)
conv.can_convert("clip.avi")                     # -> True only if ffmpeg on PATH

# One file -> renderable artifact on disk. Never raises for an unconvertible file.
res = conv.convert("legacy.pcx", out_dir="renderable")
#   res["status"] in {converted, unsupported, tool_unavailable, skipped_exists, error}

# Batch, analyzer-shaped ({file_id, file_location} rows):
tables = conv.convert_files(rows, out_dir="renderable")   # {"format_conversions": [...]}

# Deep-parse the rendered artifacts (adds the companion table):
analysis = TextAnalyzer().analyze_conversions(tables)     # {"conversion_analysis": [...]}
```

## Output tables (real family names)

The stage feeds the `conversion_tables` family (the `--tables-json` /
`RepositoryDatabaseGenerator` keyword) with:

- **`format_conversions`** — one row per attempted file: `conversion_id`,
  `file_id`, `source_file`, `source_path`, `source_ext`, `target_format`,
  `status`, `method`, `tool`, `output_file`, `output_size`, `detail`. `status` is
  one of `converted` / `unsupported` / `tool_unavailable` / `skipped_exists` /
  `error`.
- **`conversion_analysis`** — the 1:1 companion produced by `TextAnalyzer`
  (present only when `--no-conversion-analysis` is not set); merged into the same
  `conversion_tables` dict under the `conversion_analysis` key. Non-converted
  outcomes are logged as `not_analyzed`. Analyzable targets:
  `ANALYZABLE_TARGETS = {png, wav, mp4, pdf, txt, gif, html, htm}`.

**No `v_*` views** read these tables — `src/views/catalog.py` defines no
`conversion_*` / `format_conversions` views, so none are ever created. Query the
base tables directly.

## Notes & gotchas

- **Never fabricates:** a file with no route returns `status="unsupported"`; a
  file whose only route needs a missing tool returns `status="tool_unavailable"`
  naming the tool. Nothing is faked.
- **Raw payload is never stored** in any database — the only output is the new
  renderable file written under the explicit output dir.
- **PATH-tier tools:** `ffmpeg`, `soffice`/`libreoffice`, and ImageMagick
  `magick` are used only if found on `PATH` (`_find_magick()` avoids Windows'
  unrelated `system32\convert.exe`). Pass `allow_external=False` for a hermetic,
  pure-Python-only run.
- **Bounds:** pure-Python decoders enforce `_MAX_PIXELS = 64 Mpx`; external tools
  time out after `_EXTERNAL_TIMEOUT = 120 s`. Existing outputs are left in place
  (`skipped_exists`) unless `overwrite=True`.

## See also — [../USAGE.md](../USAGE.md)
