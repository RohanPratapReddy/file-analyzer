# `file_analyzer/prog_lang` — the polyglot code analyzer family

**Package:** `file_analyzer/prog_lang` · **Import:** `from file_analyzer.engine import PolyglotCodeAnalyzer` (and any `{Lang}Analyzer`, e.g. `from file_analyzer.engine import RustAnalyzer`) · **Component:** `code` / `polyglot` (whole plane) · `<ClassName>` (a single language)

## What it does

`prog_lang` is the `code` plane. It parses source files across a very large set of
programming languages into one uniform relational dataset — the `code_tables`
family (classes, functions, symbols, imports, …) that the `v_*` views and the
downstream database read.

The package has three layers:

1. **Engine bases** — the shared machinery every per-language analyzer builds on.
   Concrete analyzers subclass one of these; the base owns id allocation, the
   `kind_reference` table, symbol indexing, introspection rows and the two-pass
   `analyze()` driver, so each language file only implements the real syntax of
   its own language.
   - `BaseCodeAnalyzer` (`base_code_analyzer.py`) — the root: relational row
     stores, auto-increment counters, `get_tables()`, and the JSON/memory export.
   - `RegexCodeAnalyzer` (`regex_base.py`) — base for grammar-free (regex /
     heuristic) analyzers. Subclasses set `LANG_KEY` / `EXTENSIONS` and implement
     `_register_types` (pass 1) and `_extract_entities` (pass 2). This is the
     majority of the languages.
   - `BaseTreeSitterAnalyzer` (`tree_sitter_base.py`) — base for tree-sitter
     backed analyzers (the JavaScript/TypeScript family and others). A missing
     tree-sitter backend degrades to *skipping only those files*, never aborting.
   - `PythonEmbeddedAnalyzer` (`python_embedded_base.py`) — base for DSLs that are
     really Python (parsed with the real `ast` module).
   - `PythonCodeAnalyzer` (`python_analyzer.py`, aliased `PythonAnalyzer`) — the
     Python analyzer, which uses reflection/introspection in addition to AST.

2. **Per-language `{Lang}Analyzer` classes** — one module per language
   (`rust_analyzer.py` → `RustAnalyzer`, `go_analyzer.py` → `GoAnalyzer`, etc.).
   Each declares the extensions it owns via its `EXTENSIONS` tuple / its entry in
   `EXT_MAP`, and emits the identical `code_tables` shape. Every class exported
   from the package is listed in `file_analyzer/prog_lang/__init__.py` `__all__` and is
   re-exported from `file_analyzer.engine` (so `from file_analyzer.engine import RustAnalyzer` works).

3. **`PolyglotCodeAnalyzer`** (`polyglot.py`) — the dispatcher. It routes each
   input file to the right `{Lang}Analyzer` via `EXT_MAP`, runs each, and merges
   every analyzer's tables into one reconciled relational dataset.

### The merge / id-reconciliation step (why `PolyglotCodeAnalyzer` is more than a loop)

Every per-language analyzer numbers its own tables from 1 (`file_id`, `class_id`,
`function_id`, … plus the static `kind_reference`). `PolyglotCodeAnalyzer.analyze()`
merges them safely:

- `kind_reference` (a constant lookup) is emitted exactly once.
- each analyzer's entity ids are shifted into a disjoint numeric range, and every
  id-valued reference column (scalar *and* list-of-id) is shifted by the same base
  so intra-analyzer links stay valid.
- `file_id` is remapped to the Polyglot run's global file ordering, matching the
  `analyzed_file_paths` the caller later hands to `ImportLinkageAnalyzer`.
- `temp_kind_details` is rebuilt once over the fully-merged tables.

A per-language backend that raises (e.g. tree-sitter not installed) is caught and
its files skipped with a warning — the languages that *can* be analyzed still are.

## Extensions / languages handled — `EXT_MAP`

`PolyglotCodeAnalyzer.EXT_MAP` is the **authoritative ext → analyzer routing
table**. It is a plain `dict` literal in `polyglot.py` mapping a lower-cased file
suffix to the analyzer class that owns it (e.g. `".rs": RustAnalyzer`,
`".py": PythonCodeAnalyzer`, `".cpp": CppAnalyzer`). Several suffixes may map to
one analyzer (`.cpp`/`.hpp`/`.cc`/`.cxx`/`.c++`/`.hh`/… → `CppAnalyzer`), and
some entries are pure aliases onto an existing analyzer of the same syntax family.

Two other packages **extend the same table** at import time (see *How it fits the
pipeline*):

- `file_analyzer/shell` merges its `SHELL_EXT_MAP` into `EXT_MAP` (shell / command-language
  / automation-script families).
- `file_analyzer/script` merges its `SCRIPT_EXT_MAP` into `EXT_MAP` (bash/sh/zsh/ksh, fish,
  PowerShell, batch, CMake, Gradle, Bazel Starlark, F# script, Perl).

Both merges refuse to overwrite an existing, different analyzer (they raise a
`RuntimeError` on collision), so `EXT_MAP` stays the single, conflict-free
universe of code extensions. The exact count is best read from source
(`len(PolyglotCodeAnalyzer.EXT_MAP)` after import, or
`python -m file_analyzer.main --list-components`) — it spans well over 250 suffixes and the
full `language_analyzers` class list is what `--list-components` prints.

**Routing vs. selection.** The router (`file_analyzer/router/routing.py`) derives its `code`
extension universe *lazily* from `EXT_MAP` (`_code_exts()`), and `resolve_analyzer`
returns `"code"` for any suffix in that set — checked **first**, before every
other plane. So merging an extension into `EXT_MAP` (and nowhere else) is all it
takes to route that extension to the `code` plane.

## Run it standalone

### CLI (component mode)

```bash
# the whole code plane (every code file routing assigns to `code`)
python -m file_analyzer.main . --component code --emit code.json

# a single language analyzer over ONLY the files whose extensions it claims
python -m file_analyzer.main . --component RustAnalyzer   --emit rust.json
python -m file_analyzer.main . --component PythonAnalyzer --emit py.json      # alias of PythonCodeAnalyzer

# discover every valid name (planes + language_analyzers)
python -m file_analyzer.main --list-components
```

Component names are case-insensitive; `PythonAnalyzer` is accepted as an alias for
`PythonCodeAnalyzer`. For the `code` plane, the census runs and `resolve_analyzer`
selects exactly the files the plane owns. For a single `{Lang}Analyzer`, only files
whose suffix that class claims (the `EXT_MAP` inverse) are selected. If nothing
matches, the component emits empty tables and warns.

### Docker (component mode in a container)

The `engine` service (compose profile `engine`) runs `python -m file_analyzer.main`, so pass
it the same args. The repo mounts at `/workspace` and artifacts at `/artifacts`, so
emit into `/artifacts` for the JSON to land on the host:

```bash
# the whole code plane
docker compose --profile engine run --build engine \
  /workspace --component code --emit /artifacts/code.json

# a single language analyzer
docker compose --profile engine run --build engine \
  /workspace --component RustAnalyzer --emit /artifacts/rust.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component code --emit /artifacts/code.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`
(default `./workspace`); artifacts persist to `ARTIFACTS_DIR` (default `./artifacts`).

### Python

The public constructor mirrors what component mode calls
(`engine_cls(file_paths=[...], dump_file_type="memory")` then `.analyze()`):

```python
from file_analyzer.engine import PolyglotCodeAnalyzer

eng = PolyglotCodeAnalyzer(
    file_paths=["a.py", "b.rs", "c.go"],   # list[str | Path]
    dump_file_type="memory",               # "memory" = don't write; return dict
)
tables = eng.analyze()                      # -> the code_tables dict

# A single language analyzer has the same call shape:
from file_analyzer.engine import RustAnalyzer
rust_tables = RustAnalyzer(file_paths=["lib.rs"], dump_file_type="memory").analyze()
```

`PolyglotCodeAnalyzer.__init__` also accepts `dump_file_path` (default
`"polyglot_analysis.json"`); with the default `dump_file_type="json"` it writes
that file, with `"memory"` it only returns the dict.

## Output tables (`code_tables`)

`analyze()` returns (and `BaseCodeAnalyzer.get_tables()` exposes) these tables.
This is the `code_tables` family referenced throughout `main.py` / `USAGE.md`:

| table | what it holds |
|-------|---------------|
| `kind_reference` | static lookup: kind_id → kind_name (import, variable, function, class/struct/interface, tensor_member/field, arg/parameter, introspection_metadata). Emitted once. |
| `symbol_index` | one row per declared symbol: `symbol_id`, `file_id`, `kind_id`, `target_entity_id` — the cross-table index into the entity tables. |
| `imports_table` | imports / sourced / required modules (`import_id`, name, source, alias). |
| `variables_table` | module/function-scope variables (`variable_id`, name, value, scope, `is_imported`, `source_import_id`). |
| `functions_table` | functions/methods (`function_id`, `class_id` if a method, `is_imported`, arg/output id lists). |
| `classes_table` | classes/structs/interfaces (`class_id`, parents, `method_ids`, `attr_ids`, `tensor_member_ids`, …). |
| `args_table` | function/method parameters (`args_id`). |
| `outputs_table` | function return/output entries (`output_id`). |
| `tensor_members_table` | tensor/field members (`member_id`, `kind`, `count`, …) — used by the ML-aware analyzers. |
| `introspection_metadata_table` | per-entity introspection (`metadata_id`, `entity_id`, `entity_type`, `language`, `inspection_source`, bytecode/AST dump, structural props). |
| `temp_kind_details` | denormalized per-kind detail rows (+ Mermaid flowcharts), rebuilt once over the merged tables. |

**Derived downstream, not produced here:** the views in `file_analyzer/views/catalog.py`
also read `junction_class_methods` and `import_linkage_table`. Those are **not**
emitted by the analyzers — `RepositoryDatabaseGenerator` builds
`junction_class_methods` from `classes_table.method_ids`, and
`ImportLinkageAnalyzer` (component `linkage`) produces `import_linkage_table`. The
tables the analyzer output feeds directly into views are `classes_table`,
`functions_table`, `symbol_index` (with `kind_reference`),
`introspection_metadata_table` and `tensor_members_table` — see these views:

- `v_top_classes_by_methods` — `classes_table` ⋈ `junction_class_methods`
- `v_functions_defined_vs_imported` — `functions_table`
- `v_symbols_by_kind` — `symbol_index` ⋈ `kind_reference`
- `v_introspection_by_language` — `introspection_metadata_table`
- `v_tensor_members_by_kind` — `tensor_members_table`
- `v_import_internal_vs_external`, `v_import_edges` — `import_linkage_table`

## How it fits the pipeline

- Routing id: **`code`** (`resolve_analyzer` → `"code"`, checked first).
- The `code` universe is derived lazily from `EXT_MAP`, so `shell` and `script`
  fold in by registering their maps into `EXT_MAP` at import time — no router
  changes, no schema changes; shell/script files are analyzed in the same `code`
  pass with the same id reconciliation and identical table shape.
- In the full pipeline the per-shard worker runs `PolyglotCodeAnalyzer` over the
  `code` shard; `ImportLinkageAnalyzer` then links imports across files, and
  `RepositoryDatabaseGenerator` writes the tables (+ derived junctions) to the db.

## Notes & gotchas

- **CRLF normalization:** `RegexCodeAnalyzer._read_source` normalizes `\r\n` and
  bare `\r` to `\n` before the `$`-anchored / multiline regexes run — Windows
  line endings would otherwise break line-anchored matching.
- **`code_tables` ≠ final schema:** `junction_class_methods` and
  `import_linkage_table` are built later (dbgen / linkage), not by these analyzers.
- **Backend failures are isolated:** a language whose backend is unavailable (e.g.
  tree-sitter not installed) skips only its files with a warning; the run continues.
- **Single-analyzer selection differs from the plane:** `--component RustAnalyzer`
  selects by the `EXT_MAP` inverse (the suffixes that class claims); `--component
  code` selects via `resolve_analyzer`.

## See also

- [../USAGE.md](../USAGE.md) — the full CLI, component mode, and the `--tables-json` contract.
- [../shell/README.md](../shell/README.md) — the `file_analyzer/shell` fold-in.
- [../script/README.md](../script/README.md) — the `file_analyzer/script` fold-in.
