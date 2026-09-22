# MachineCodeAnalyzer + BinaryFormatParser — the binary plane

**Package:** `file_analyzer/binary` · **Imports:** `from file_analyzer import MachineCodeAnalyzer, BinaryFormatParser, BinaryForensicsAnalyzer` (all re-exported) · **Pipeline stage:** binary deep-parse (step 4c in `AnalysisEngine.run()`; **no `--component`** — controlled by `--no-binary`).

## What it does

The binary plane owns the `binary` routing class and deep-parses every file the
router assigns to it. It is a post-planes stage, like archives — **not** driven by
the Go/Java per-shard workers. Three cooperating classes:

- **`MachineCodeAnalyzer`** — the stage entry point. Pure-stdlib `struct` readers
  (no third-party deps, no external tools) for executable / object / bytecode /
  firmware containers: ELF, PE/COFF, Mach-O, Java `.class`, Python `.pyc`,
  WebAssembly, Android DEX, `ar` static libraries, LLVM bitcode, UF2, OLE/MSI.
- **`BinaryForensicsAnalyzer`** — the format-agnostic layer (size / sha256 /
  magic / detected-format / entropy / byte distribution / string extraction) plus
  the `binaries.json` taxonomy. Composed by `MachineCodeAnalyzer` so every
  `binary_index` row carries honest forensic metrics even when the deep parser
  only partially understands a format. Usable standalone.
- **`BinaryFormatParser`** (`format_parsers.py`) — deep, **magic-driven**
  structural parsers for the *non-executable* binary universe (~1100 registered
  extensions across media / image / 3D-model / disk-image / firmware / scientific
  / serialization / font / ROM / packet-capture families). Consulted by
  `MachineCodeAnalyzer` when the executable dispatcher does not claim a file,
  before falling back to a bare forensic note.

Everything is **metadata only** — section/segment *contents* are never stored; at
most a bounded byte window (`_SECTION_ENTROPY_CAP = 1 MiB`) is read to measure
per-section entropy. Any single malformed file is caught, recorded with a
`notes`/`error` marker, and never sinks the batch.

## Formats handled (from source)

- **`MachineCodeAnalyzer.ROUTED_EXTS`** (the extensions it claims exclusively via
  the router): ELF & generic (`.elf`, `.o`, `.ko`, `.so`, `.prx`, `.axf`,
  `.bin`), PE/COFF (`.exe`, `.dll`, `.sys`, `.efi`, `.ocx`, `.cpl`, `.scr`,
  `.drv`, `.mui`, `.winmd`), Mach-O (`.dylib`, `.macho`), JVM (`.class`), Python
  bytecode (`.pyc`, `.pyo`), WASM (`.wasm`), Android runtime (`.dex`, `.odex`,
  `.oat`, `.vdex`, `.art`), OCaml/LLVM/firmware (`.bc`, `.llbc`, `.cma`, `.cmo`,
  `.cmx`, `.cmxs`, `.uf2`, `.hex`, `.srec`, `.s19`, `.s28`, `.s37`), installer/OLE
  (`.msi`, `.msm`). Deliberately free of collisions with the higher-priority
  `code` / `data` / `archive` classes (`.mod`, `.ll`, `.msp`, `.bundle` are owned
  elsewhere and intentionally absent).
- **`BinaryFormatParser`** covers the ~1100 non-executable extensions
  (`BinaryFormatParser.EXTS`) via a per-extension family registry plus a curated
  magic-signature table: ISO-BMFF box trees, RIFF/IFF chunks, EBML, Ogg pages,
  TIFF IFD tags, PNG/JPEG segments, JPEG-2000 boxes, sfnt table directories, MIDI,
  ROM cartridge headers, disk-image superblocks/footers, ASN.1 DER TLV,
  HDF5/HDF4/NetCDF/FITS scientific headers, GPU-texture headers, ML-model
  container headers, and binary serialization wire formats. Detection is by real
  content signatures — the per-extension hint is only a fallback for magicless
  formats. Public surface: `analyze(path) -> dict`, `EXTS`, `routing_suffixes()`,
  `claims(name)`.

## How it runs (full pipeline)

Controlling flag: **`--no-binary`** (skip the machine-code / object / bytecode
deep-parse stage).

There is **no standalone component mode** for this stage. It is **not** in
`main.py`'s `_SPECIAL_COMPONENTS`, `_PLANE_COMPONENTS`, or
`_lang_analyzer_registry()` — `python -m file_analyzer.main --component binary` is not
valid and it does not appear in `--list-components`. (Note: the component-mode
`data` / `code` / etc. planes are the Go/Java-driven shard planes; the binary
plane is a separate post-planes engine stage.) It runs only inside the pipeline:

```bash
# binary deep-parse on (default)
python -m file_analyzer.main <repo> --out ./artifacts

# skip the binary stage
python -m file_analyzer.main <repo> --out ./artifacts --no-binary
```

`AnalysisEngine` invokes it as: gather `mapping["mapping"]` rows whose
`analyzer_class == "binary"`, then `MachineCodeAnalyzer(self, binary_files).process()`.

### Docker

This stage runs as part of the full pipeline inside the `engine` service
(compose profile `engine`, entrypoint `python -m file_analyzer.main`); control it with the
same flag:

```bash
# binary deep-parse on (default):
docker compose --profile engine run --build engine \
  /workspace --out /artifacts
# disable the stage:
docker compose --profile engine run --build engine \
  /workspace --out /artifacts --no-binary
```

Or set it via `ENGINE_ARGS="/workspace --out /artifacts --no-binary"`. Set
`SOURCE_DIR` to choose the mounted repo (mounts at `/workspace`); artifacts are
written to `/artifacts` (`ARTIFACTS_DIR`).

## Python (direct use)

```python
from file_analyzer import MachineCodeAnalyzer, BinaryFormatParser, BinaryForensicsAnalyzer

# Deep-parse a set of routed binary rows. `engine` is optional (read for attrs
# only); files_rows are [{file_id, file_location, analyzer_class}, ...].
tables = MachineCodeAnalyzer(engine=None, files_rows=rows).process()
#   -> {"binary_index": [...], "binary_sections": [...], "binary_symbols": [...],
#       "binary_imports": [...], "binary_properties": [...]}

# One non-executable file, structurally:
info = BinaryFormatParser().analyze("model.safetensors")
#   -> {"format", "family", "detected_via", "properties", "sections", "notes"}

# Format-agnostic forensic profile of any file:
forensics = BinaryForensicsAnalyzer()
```

## Output tables (real family names)

The stage returns the `binary_tables` family (the `--tables-json` /
`RepositoryDatabaseGenerator` keyword) with five tables:

- **`binary_index`** — one row per file: format, arch, bitness, endianness, entry
  point, stripped/dynamic/PIC flags, section/symbol/import/export counts, sha256,
  size, entropy, how the format was detected, notes.
- **`binary_sections`** — one row per section/segment (name, type, virtual
  address, file offset, size, flags, per-section entropy where cheap).
- **`binary_symbols`** — one row per symbol (name, kind, binding, address, size,
  section, import/export flags, library).
- **`binary_imports`** — one row per imported library / symbol dependency.
- **`binary_properties`** — flexible `(group, name, value)` bag for
  format-specific facts (OS/ABI, machine string, PE characteristics, Mach-O load
  commands, WASM section sizes, class-file version, pyc magic, …).

Children (`binary_sections` / `_symbols` / `_imports` / `_properties`) carry a FK
to their `binary_index` parent. **No `v_*` views** read these tables —
`file_analyzer/views/catalog.py` defines no `binary_*` views, so none are ever created.
Query the base tables directly.

## Notes & gotchas

- **Honest forensics, never fabricated:** for proprietary or undocumented
  payloads `BinaryFormatParser` records a `forensic` disposition (size / sha256 /
  entropy / byte distribution / strings) — the real analysis such payloads admit.
  Nothing invents fields it did not read.
- **Encrypted content is never decoded** and raw payload / section contents are
  never stored — only measured (bounded entropy windows).
- **No external tools, no third-party deps** for the executable parsers — pure
  stdlib `struct`.
- Bounded reads guard against hostile/truncated headers:
  `_MAX_SECTIONS = 20_000`, `_MAX_SYMBOLS = 200_000`, `_MAX_IMPORTS = 100_000`.
- Detection is content-first (magic bytes), so a mis-extensioned binary is still
  identified by its real signature.

## See also — [../USAGE.md](../USAGE.md)
