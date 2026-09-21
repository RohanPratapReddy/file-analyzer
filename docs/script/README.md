# `src/script` — mainstream command-language / build-script dialects folded into `code`

**Package:** `src/script` · **Import:** `from src import PowerShellAnalyzer` (and the other dialect classes) · **Component:** `code` / `polyglot` (script files are analyzed as part of the code plane) · `<ClassName>` for a single dialect

## What it does

`src/script` holds the residual `script`-kind extensions — the mainstream
command-language and build-script dialects: bash/sh/zsh/ksh, fish, PowerShell,
batch, CMake, Gradle, Bazel Starlark, F# script, and Perl. Like shell scripts,
these are code (they define functions, variables and sourced/imported files), so
every analyzer emits the **same `code`-domain relational tables** as every
programming-language analyzer, and the whole package folds into the single `code`
domain — exactly like `src/shell`.

There are nine analyzers, grouped into four modules:

| module | analyzers | extensions | strategy |
|--------|-----------|------------|----------|
| `shells.py` | `PosixScriptShellAnalyzer`, `FishShellAnalyzer` | `.sh` `.bash` `.zsh` `.ksh` / `.fish` | POSIX family **subclasses the real `PosixShellAnalyzer`** (shell subpackage) unchanged; fish gets its own real `ShellScriptBase` analyzer (distinct grammar). |
| `windows.py` | `PowerShellAnalyzer`, `BatchScriptAnalyzer` | PowerShell / batch | genuine gaps → **new hand-written parsers**. |
| `build_tools.py` | `CMakeAnalyzer`, `GradleBuildAnalyzer`, `BazelExtensionAnalyzer` | `.cmake` / `.gradle` / `.bzl` | CMake → new `RegexCodeAnalyzer` parser; Gradle **subclasses the real `GroovyAnalyzer`**; Bazel `.bzl` **subclasses the real `StarlarkAnalyzer`** (ast-backed). |
| `reused.py` | `FSharpScriptAnalyzer`, `PerlScriptAnalyzer` | F# script / Perl | subclass the existing F#/Perl parsers, changing only the owned extension. |

The design rule (stated in the package header): where a dialect exactly matches a
language that already has a real parser (Groovy / Starlark / F# / Perl /
POSIX-shell), the analyzer **subclasses that parser and only changes the owned
extension — never a placeholder**. Genuine gaps (PowerShell, batch, CMake, fish)
get their own real hand-written parsers.

## Extensions / languages handled — `SCRIPT_EXT_MAP`

`SCRIPT_EXT_MAP` (in `src/script/__init__.py`) is `ext → analyzer class`. As in
`src/shell`, it is **built from each analyzer's own `EXTENSIONS` tuple** — the
`__init__` iterates a `_ANALYZERS` tuple of the nine classes and registers every
lower-cased suffix each one owns, raising a `RuntimeError` on any collision. So the
map can never drift out of sync with the analyzers. Read the live set with
`from src import SCRIPT_EXT_MAP` (it is exported), or `sorted(SCRIPT_EXT_MAP)`.
It covers roughly fifteen suffixes across the nine dialects; the authoritative
list is the union of the classes' `EXTENSIONS` tuples.

## Run it standalone

### CLI (component mode)

Script files are part of the `code` plane, so the pipeline analyzes them via
`--component code`. There is no separate `script` plane component:

```bash
python -m src.main . --component code --emit code.json
```

Each dialect class is also registered as a language component (it appears under
`language_analyzers` in `--list-components`, since it lives in the merged
`EXT_MAP`):

```bash
python -m src.main . --component PowerShellAnalyzer --emit ps.json
python -m src.main . --component CMakeAnalyzer      --emit cmake.json
python -m src.main --list-components
```

### Docker (component mode in a container)

The `engine` service (compose profile `engine`) runs `python -m src.main`, so pass
it the same args. The repo mounts at `/workspace` and artifacts at `/artifacts`, so
emit into `/artifacts` for the JSON to land on the host:

```bash
# script files are analyzed as part of the code plane
docker compose --profile engine run --build engine \
  /workspace --component code --emit /artifacts/code.json

# or a single script dialect analyzer
docker compose --profile engine run --build engine \
  /workspace --component PowerShellAnalyzer --emit /artifacts/ps.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component code --emit /artifacts/code.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`
(default `./workspace`); artifacts persist to `ARTIFACTS_DIR` (default `./artifacts`).

### Python

```python
from src import PowerShellAnalyzer
tables = PowerShellAnalyzer(
    file_paths=["build.ps1"],
    dump_file_type="memory",
).analyze()
```

There is no separate script dispatcher class — in standalone use you either run a
single dialect analyzer as above, or run `PolyglotCodeAnalyzer` (which has the
script extensions merged into its `EXT_MAP`).

## Output tables

Identical to the `code_tables` family produced by `src/prog_lang` — `kind_reference`,
`symbol_index`, `imports_table`, `variables_table`, `functions_table`,
`classes_table`, `args_table`, `outputs_table`, `tensor_members_table`,
`introspection_metadata_table`, `temp_kind_details`. Script files add rows to the
same tables the `v_*` views already read (see
[../prog_lang/README.md](../prog_lang/README.md) for the table reference).

## How it fits the pipeline

`src/prog_lang/polyglot.py`, at module bottom (just after the shell fold-in), does
`from ..script import SCRIPT_EXT_MAP` and merges every entry into
`PolyglotCodeAnalyzer.EXT_MAP` (refusing to overwrite a different existing
analyzer). Because the router derives its `code` extension universe lazily from
`EXT_MAP` (`_code_exts()`), **merging `SCRIPT_EXT_MAP` into `EXT_MAP` is exactly
what routes every script extension to the `code` plane** — no router edit and no
schema change.

## Notes & gotchas

- **Real parsers, no stubs.** Dialects that match an existing language reuse that
  language's parser by subclassing it and overriding only `LANG_KEY` /
  `EXTENSIONS` (Gradle → Groovy, Bazel → Starlark, F#/Perl → their parsers,
  bash/zsh/ksh → POSIX shell). Only true gaps get new parsers.
- **`SCRIPT_EXT_MAP` is generated, not authored** — change an analyzer's
  `EXTENSIONS`, not the map.
- **CRLF:** the shared regex bases normalize `\r\n`/`\r` → `\n` before
  line-anchored (`$`-anchored / multiline) regexes run — important for
  Windows-authored `.ps1` / `.bat` scripts.
- **Fold order:** the script fold runs after the shell fold in `polyglot.py`, so a
  script extension colliding with a shell or language analyzer is caught at import.

## See also

- [../USAGE.md](../USAGE.md) — the full CLI and component mode.
- [../prog_lang/README.md](../prog_lang/README.md) — the code plane, `EXT_MAP`, and the `code_tables` reference.
- [../shell/README.md](../shell/README.md) — the sibling `src/shell` fold-in.
