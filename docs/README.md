# file-analyzer — documentation

`file-analyzer` is a **repository intelligence platform**: a static core that turns
a source tree into a queryable SQLite/PostgreSQL database **without executing it**,
wrapped in live/agentic layers — a background monitor (incremental re-analysis), an
MCP agent-enrichment tier, and a document-intelligence engine. Everything you need
to run it, use it as a library, or understand a single module on its own is here.

Start here:

- **[USAGE.md](USAGE.md)** — the `python -m src.main` CLI surface: every flag for
  the full pipeline, plus **component mode** (`--component NAME`) for running one
  block standalone, the `--quiet` pure-JSON contract, and
  [Part 4 — AI agents (MCP)](USAGE.md#part-4--ai-agents-mcp). Read this first.
- **[../README.md](../README.md)** — project overview: what the tool produces, the
  views layer, the Go/Java readers, and the Docker workflow.
- **[../AGENTS.md](../AGENTS.md)** — driving `file-analyzer` from an AI agent
  (Claude, opencode, Cursor, Grok, DeepSeek, …): the MCP server
  ([`mcp_server.py`](../mcp_server.py)), the `--quiet` CLI, and
  [`../tools.json`](../tools.json) function-calling definitions. A Claude Code skill
  lives at [`../.claude/skills/file-analyzer/SKILL.md`](../.claude/skills/file-analyzer/SKILL.md).

## Live & agentic layers

Beyond the one-shot static pipeline, the platform adds continuous and agent-driven
layers:

- **[monitor.md](monitor.md)** — the always-on **background monitor**
  (`python -m src monitor`): watches a repository and re-analyzes changed files
  incrementally across a Go/Python worker pool, with a FIFO diff DB, a durable
  change log, and an optional soft MCP agent tier. MCP tools + a Docker profile.
- **[document-engine-agents.md](document-engine-agents.md)** — the
  **DocumentParser** document-intelligence engine: static Part-A metrics + a
  dynamic **agent/code loop** (Part B) + a full **evaluation** stack (Part C).
- **[document-engine-libraries.md](document-engine-libraries.md)** — the optional
  library/system-binary backends behind each document-engine layer, and the
  pure-stdlib fallbacks.

## Runtime & operations

- **[runtime-containment.md](runtime-containment.md)** — the CLI entrypoints refuse
  to run on bare-metal host hardware; they start only inside a container or VM
  (fail-closed, exit code 3, `FILE_ANALYZER_ALLOW_BARE_METAL` override).

## Per-module reference

Below, one folder per `src/` subpackage. Each doc explains what that module does,
how to use it on its own (component-mode CLI where one exists, plus the Python
import), the tables it emits, and its gotchas.

## Orchestration — `src/core`

The glue that ties every analyzer into one pipeline and writes the artifacts.

- **[core/README.md](core/README.md)** — package overview + how the four classes chain.
- [core/analysis-engine.md](core/analysis-engine.md) — `AnalysisEngine` (drives the whole flow).
- [core/repository-analyzer.md](core/repository-analyzer.md) — `RepositoryAnalyzer`, the file census (component `census`).
- [core/import-linkage.md](core/import-linkage.md) — `ImportLinkageAnalyzer`, cross-file symbol resolution (component `linkage`).
- [core/db-generator.md](core/db-generator.md) — `RepositoryDatabaseGenerator`, the `.sql`/`.db` emitter (component `dbgen`).

## Code analyzers

Source-code planes. Everything folds into the `code` family via
`PolyglotCodeAnalyzer.EXT_MAP`.

- **[prog_lang/README.md](prog_lang/README.md)** — `PolyglotCodeAnalyzer` + the per-language `{Lang}Analyzer` fleet (component `code`, plus one component per language).
- [shell/README.md](shell/README.md) — the shell-script analyzers, folded into `code` via `SHELL_EXT_MAP`.
- [script/README.md](script/README.md) — the scripting-language analyzers, folded into `code` via `SCRIPT_EXT_MAP`.

## Schema & data planes

- [schema/README.md](schema/README.md) — `SchemaAnalyzer`: SQL DDL + IDL formats → `schema_*` tables (component `schema`).
- [database/README.md](database/README.md) — `DatabaseAnalyzer`: database files, schema+data merged → `database_*` tables (component `database`).
- [data/README.md](data/README.md) — `DataAnalyzer`: metadata/stats/sampling-only data profiler → `data_*` tables (component `data`).

## Text-record planes

Document → sections → records → fields shapes for the long tail of file types.

- [config/README.md](config/README.md) — `ConfigAnalyzer` → `config_*` tables (component `config`).
- [text/README.md](text/README.md) — `TextualAnalyzer` → `text_*` tables (component `text`).
- [markup/README.md](markup/README.md) — `MarkupAnalyzer` → `markup_*` tables (component `markup`).
- [document/README.md](document/README.md) — `DocumentAnalyzer` → `document_*` tables (component `document`).
- [misc/README.md](misc/README.md) — `MiscAnalyzer`, the terminal long-tail plane → `misc_*` tables (component `misc`).

## Pipeline support stages

Post-plane stages driven by `AnalysisEngine` flags — no `--component` of their own.

- [archive/README.md](archive/README.md) — nested archive traversal (`--no-archives`, `--max-archive-depth`).
- [binary/README.md](binary/README.md) — machine-code + binary-format parsers (`--no-binary`).
- [convert/README.md](convert/README.md) — opaque→renderable conversion helpers (`--no-conversions`, `--conversions-dir`).

## Infrastructure

- [router/README.md](router/README.md) — pure-Python routing/staging: `resolve_analyzer`, plane priority order, and shard grouping.
- [views/README.md](views/README.md) — the views layer + Go/Java readers: the `v_*` view catalog, the "present tables only" contract, and the read-only guarantees.

---

Every plane analyzer shares the same standalone shape:

```python
from src import <Analyzer>
eng = <Analyzer>(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code planes then map local ids to repository ids:
eng.link_repository((folders, extensions, files), paths)
tables = eng.get_tables()
```

…or run any registered block from the CLI without writing code:

```bash
python -m src.main . --component <name> --emit <name>.json
python -m src.main --list-components   # every runnable block
```

…or run that same block **inside the Docker `engine` container** (entrypoint
`python -m src.main`) — emit under `/artifacts` so output reaches the host:

```bash
docker compose --profile engine run --build engine \
  /workspace --component <name> --emit /artifacts/<name>.json
```

Each module doc carries its own **Docker** section with the exact container
invocation for that module (component mode, or the full-pipeline flags for the
archive/binary/convert stages). See the [../README.md](../README.md) Docker
section for the full stack (Postgres + loader + pgAdmin) and the `SOURCE_DIR` /
`ARTIFACTS_DIR` env vars.
