# `file_analyzer/shell` — shell / command-language / automation-script analyzers folded into `code`

**Package:** `file_analyzer/shell` · **Import:** `from file_analyzer.engine import ShellScriptAnalyzer` (and the individual analyzers, e.g. `from file_analyzer.engine import PosixShellAnalyzer`) · **Component:** `code` / `polyglot` (shell files are analyzed as part of the code plane) · `<ClassName>` for a single dialect

## What it does

`file_analyzer/shell` provides real, syntax-aware analyzers for the shell / command-language
/ automation-script families (the ones catalogued in `docs/shell_scripts.json`).
Scripts *are* code — they define functions, variables and sourced/imported files —
so every analyzer emits the **identical `code`-domain relational tables** as the
programming-language analyzers, and shell files fold into the single `code`
routing class with no schema changes.

The package mirrors `file_analyzer/prog_lang` exactly:

- **`ShellScriptBase`** (`shell_base.py`) — the shared base for command-language
  analyzers (regex / grammar based). It is the shell counterpart of
  `RegexCodeAnalyzer`: it owns id allocation, symbol indexing and the two-pass
  driver, and provides shell-specific row helpers (`_add_shell_function`,
  `_add_variable`, `_add_alias`, `_add_sourced`, `_record_shebang`,
  `_record_module_meta`, `_strip_comments`, …). Concrete analyzers set `LANG_KEY`
  / `EXTENSIONS` and implement `_register_types` and `_extract_entities`.
- Six Python-syntax recipe DSLs (Conan/SCons/Spack/Sage/Abaqus-journal/Starlark
  in `python_dsls.py`) instead subclass `PythonEmbeddedAnalyzer` and get a real
  `ast` parse.
- One concrete analyzer per family, grouped into topic modules — POSIX shell
  (`posix_shell.py`), modern shells (`modern_shells.py` — Elvish, Nushell), Tcl
  (`tcl_family.py`), statistics scripts (`statistics.py` — Stata/SAS/SPSS), math
  scripting (`math_scripting.py` — GAP/PARI-GP/Maple), text processing
  (`text_processing.py` — awk/sed), Windows scripting (`windows_scripting.py` —
  VBScript/WSF), automation (`automation.py` — AutoIt/AutoHotkey/gdbinit),
  installers (`installers.py` — Inno Setup/NSIS), mainframe (`mainframe.py` —
  JCL/REXX/CLIST/CLP/DCL), build scripts (`build_scripts.py` — m4/Jenkinsfile/
  Vagrantfile), misc langs (`misc_langs.py` — C# script/Elixir mix/NimScript),
  domain scripts (`domain_scripts.py` — Nuke/Painless/Wezterm/PAC), plus AppleScript
  (`applescript.py`), binary templates (`binary_template.py`) and compiled/encoded
  scripts (`compiled_scripts.py`).
- **`ShellScriptAnalyzer`** (`__init__.py`) — a standalone polyglot dispatcher
  that subclasses `PolyglotCodeAnalyzer` with `EXT_MAP = dict(SHELL_EXT_MAP)`. It
  reuses the exact id-reconciliation / per-analyzer failure-isolation machinery,
  and exists for standalone analysis and testing of the shell subpackage. In
  production the shell extensions are instead merged into the main `EXT_MAP`.

## Extensions / languages handled — `SHELL_EXT_MAP`

`SHELL_EXT_MAP` (in `file_analyzer/shell/__init__.py`) is `ext → analyzer class`. It is not
hand-maintained: it is **built from each analyzer's own `EXTENSIONS` tuple**, by
iterating a tuple of ~44 analyzer classes and registering every lower-cased suffix
each one owns. A collision (two analyzers claiming the same suffix) raises a
`RuntimeError`, so the map can never silently drift out of sync with the analyzers.

Because it is derived, the authoritative list of owned extensions is the union of
the `EXTENSIONS` tuples of the classes in the `_ANALYZERS` tuple (each analyzer
module documents its own). Read the live set with
`from file_analyzer.engine import SHELL_EXT_MAP; sorted(SHELL_EXT_MAP)`.

## Run it standalone

### CLI (component mode)

Shell files are part of the `code` plane, so the pipeline analyzes them via
`--component code`. There is no separate `shell` plane component:

```bash
# shell files are analyzed together with all other code
python -m file_analyzer.main . --component code --emit code.json
```

Individual shell analyzers are also registered as language components (their class
names appear under `language_analyzers` in `--list-components`) because they live
in the merged `EXT_MAP`:

```bash
python -m file_analyzer.main . --component PosixShellAnalyzer --emit posix.json
python -m file_analyzer.main --list-components         # PosixShellAnalyzer, TclAnalyzer, ...
```

### Docker (component mode in a container)

The `engine` service (compose profile `engine`) runs `python -m file_analyzer.main`, so pass
it the same args. The repo mounts at `/workspace` and artifacts at `/artifacts`, so
emit into `/artifacts` for the JSON to land on the host:

```bash
# shell files are analyzed as part of the code plane
docker compose --profile engine run --build engine \
  /workspace --component code --emit /artifacts/code.json

# or a single shell dialect analyzer
docker compose --profile engine run --build engine \
  /workspace --component PosixShellAnalyzer --emit /artifacts/posix.json
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
from file_analyzer.engine import ShellScriptAnalyzer     # standalone dispatcher over SHELL_EXT_MAP
tables = ShellScriptAnalyzer(
    file_paths=["deploy.sh", "build.tcl"],
    dump_file_type="memory",
).analyze()

# or a single dialect analyzer (same call shape as prog_lang):
from file_analyzer.engine import PosixShellAnalyzer
sh_tables = PosixShellAnalyzer(file_paths=["deploy.sh"], dump_file_type="memory").analyze()
```

## Output tables

Identical to the `code_tables` family produced by `file_analyzer/prog_lang` — `kind_reference`,
`symbol_index`, `imports_table`, `variables_table`, `functions_table`,
`classes_table`, `args_table`, `outputs_table`, `tensor_members_table`,
`introspection_metadata_table`, `temp_kind_details`. That is the whole point of
the fold-in: shell files add rows to the same tables the `v_*` views already read
(see [../prog_lang/README.md](../prog_lang/README.md) for the table reference).

## How it fits the pipeline

`file_analyzer/prog_lang/polyglot.py`, at module bottom, does
`from ..shell import SHELL_EXT_MAP` and merges every entry into
`PolyglotCodeAnalyzer.EXT_MAP` (refusing to overwrite a different existing
analyzer). Since the router derives its `code` extension universe lazily from
`EXT_MAP` (`_code_exts()`), **registering the shell extensions there — and nowhere
else — is what routes every shell extension to `code`.** No router edit, no schema
change: shell files are analyzed in the same `code` pass as programming-language
files, with the same id reconciliation and identical table shape.

Import-order note: `SHELL_EXT_MAP` is fully built *before* `polyglot` is imported
(the shell `__init__` imports `polyglot` only after the map exists), which breaks
the circular import regardless of which module is imported first.

## Notes & gotchas

- **Compiled / encoded scripts are byte-metadata-only.** `CompiledScriptAnalyzer`
  (`.scpt`, `.scptd`, `.atn`, `.jse`, `.vbe`, `.macro`, `.wpm`, `.xlm`) covers
  opaque binaries and deliberately obfuscated payloads. There is no honest way to
  reconstruct functions/variables from opaque bytes, so it **fabricates no symbol
  rows**. It records only module-level introspection metadata from a real
  byte-level inspection — magic bytes, size, Shannon entropy, Script-Encoder
  marker detection, embedded printable-string count/ratio, sha256 — with an
  explicit `symbols_extracted=False`. (`BinaryTemplateAnalyzer` is similarly
  binary-oriented.)
- **`SHELL_EXT_MAP` is generated, not authored** — change an analyzer's
  `EXTENSIONS`, not the map.
- **CRLF:** the shared regex bases normalize `\r\n`/`\r` → `\n` before
  line-anchored regexes run.

## See also

- [../USAGE.md](../USAGE.md) — the full CLI and component mode.
- [../prog_lang/README.md](../prog_lang/README.md) — the code plane, `EXT_MAP`, and the `code_tables` reference.
- [../script/README.md](../script/README.md) — the sibling `file_analyzer/script` fold-in.
