# file-analyzer

**Point it at a repository, get back a queryable database of everything in it.**

`file-analyzer` is a **repository intelligence platform**. Its core walks a source
tree — code, schemas, data files, archives, binaries, configs, docs — **without ever
executing it**, and emits a single **SQLite** (or **PostgreSQL**) database describing
what it found: files and folders, per-language symbols (classes, functions, imports
and the links between them), database schemas (tables, columns, keys, constraints,
triggers), data-artifact profiles (datasets, columns, tensors, correlations), and
more. A layer of ready-made **analysis views** (`v_*`) sits on top so you can answer
questions with plain `SELECT`s, and a **concurrent reader** (Go, with a pure-Python
fallback) demonstrates strictly read-only access to those views.

On top of that static core it adds **live and agentic layers**:

- a **background monitor** that watches a repository and re-analyzes changed files
  incrementally across a Go/Python worker pool, with a FIFO diff DB and a durable
  change log ([docs/monitor.md](docs/monitor.md));
- an optional **MCP agent tier** that enriches each file (summaries, quality /
  security findings, symbol docs) alongside the deterministic metrics;
- a **document-intelligence engine** (DocumentParser) combining static metrics with
  a dynamic agent/code loop and a full evaluation stack
  ([docs/document-engine-agents.md](docs/document-engine-agents.md));
- a **unified database** that merges every per-source layer into one queryable `.db`
  + `.sql`.

It never executes the code it analyzes, never modifies the source tree, never stores
raw file payloads, and degrades honestly — when a format can only be partially
understood, it records what it could determine and marks the rest, rather than
fabricating results.

> **🔒 IP-safe by design.** It stores **metadata, structure and statistics — never
> file payloads**, and never dumps verbatim strings out of binaries. The little
> free text it does keep (header fields, config/DB values, sample cells, document
> previews, monitor diffs) is scrubbed of **secrets and PII** at a single choke
> point (`file_analyzer.core.guardrails`) before storage. It is a defensive tool,
> not a secret-harvesting or copyright-lifting one. See the acceptable-use policy:
> **[ACCEPTABLE_USE.md](ACCEPTABLE_USE.md)** (`python -m file_analyzer.main --acceptable-use`).

> **⚠️ Runs in a container or VM only.** The CLI entrypoints (`file-analyzer` /
> `python -m file_analyzer.main` and the monitor `file-analyzer-monitor` / `python -m file_analyzer`)
> **refuse to run directly on bare-metal host hardware** — they start only inside a
> container (Docker/Podman/containerd/LXC/Kubernetes) or a virtual machine, exiting
> with code **3** otherwise. Use the Docker workflow below (recommended), or set
> `FILE_ANALYZER_ALLOW_BARE_METAL=1` to opt out on an already-isolated box. The MCP
> server is unaffected. Full details: **[docs/runtime-containment.md](docs/runtime-containment.md)**.

## What it produces

Running the engine over a repository yields two artifacts (both carry the `v_*`
views):

- `repository.db` — a binary SQLite database, opened in place, read-only.
- `repository_schema.sql` — a portable text dump (SQLite or PostgreSQL dialect).

## Quick start

The engine must run inside a container or VM (see the note above). The one-line
Docker recipe below satisfies that automatically. To run the Python CLI directly,
do it inside a VM/container, or export `FILE_ANALYZER_ALLOW_BARE_METAL=1` first:

```bash
pip install file-analyzer          # the analysis profile (client + engine); see "Installation & packaging" below

# Analyze a repository (the source must be a git repo, or pass --no-git).
python -m file_analyzer.main /path/to/repo --out ./artifacts

# Postgres-loadable dump instead of SQLite:
python -m file_analyzer.main /path/to/repo --out ./artifacts --dialect postgresql

# All flags (works on any host — --help is exempt from the containment guard):
python -m file_analyzer.main --help
```

Flags: `--out`, `--db`, `--sql`, `--dialect {sqlite,postgresql}`, `--temp`
(staging dir; defaults under `--out`, so a read-only source still analyzes),
`--workers`, `--no-archives`, `--no-git`, `--keep-temp`, `--quiet` (stdout carries
only the final JSON — for pipes/agents). Prints a JSON summary on success.

### Install as a command

`pip`/`pipx`-install to get a `file-analyzer` command invocable from any directory
(no `python -m`, no specific cwd):

```bash
pipx install file-analyzer   # or: pip install file-analyzer
file-analyzer /path/to/repo --out ./artifacts --quiet
file-analyzer-mcp         # start the MCP server (extras: pip install "file-analyzer[agent]")
```

## Installation & packaging

The platform ships as **four PyPI distributions** so you install only what a given
machine needs — a client box never pulls the analyzer fleet, and a server host
never pulls it either. All of them contribute to one shared, importable
`file_analyzer` package (a [PEP 420](https://peps.python.org/pep-0420/) namespace),
so whatever you install lands under the same import root.

| Distribution | Install where | Dependencies | Gives you |
|--------------|---------------|--------------|-----------|
| **`file-analyzer`** (meta) | wherever you want to *analyze* | pulls `-client` **+** `-engine` | the analysis profile — the CLI, the library, the monitor, MCP. **Most users want this.** |
| **`file-analyzer-client`** | client / query-only boxes | **none** (pure stdlib) | connect to a hosted server and query it, and read/query a local `.db` offline — no analyzer fleet, no bloat. |
| **`file-analyzer-engine`** | analysis workers | `-client` + optional extras | the analyzer fleet on its own (equivalent to the meta minus the meta's convenience name). |
| **`file-analyzer-server`** | the database-hosting host **only** | `-client` | the DB-hosting server (session-token catalog, backups, token-auth control plane). Deliberately a separate install — the meta does **not** pull it. |

```bash
# Analyze (CLI + library + monitor + MCP):
pip install file-analyzer

# A thin client that only queries a hosted server or a local .db — zero third-party deps:
pip install file-analyzer-client

# A DB-hosting server host (installs the client foundation too, not the fleet):
pip install file-analyzer-server

# Server side-by-side with analysis on the same box (opt in via the meta's extra):
pip install "file-analyzer[server]"
```

**Optional analysis extras** live on the engine (and are forwarded by the meta), so
`pip install "file-analyzer[agent]"` and `pip install "file-analyzer-engine[agent]"`
are equivalent. Extras: `agent` (MCP SDK), `document`, `parse`, `ocr`, `pii`, `eval`,
`monitor-postgres`, `monitor-mysql`. The engine's pure-stdlib core runs with none of
them — each extra upgrades a format from a bounded "partial" profile to a full parse.

**From source:** each distribution builds from its own directory under
[`packages/`](packages/) (`packages/client`, `packages/server`, `packages/engine`)
and the meta from the repo root. For a dev checkout, `pip install -e packages/engine`
(plus `-e packages/client`) gives you the fleet editable; the analysis extras are
also enumerated in [`requirements.txt`](requirements.txt) and the MCP SDK in
[`requirements-agent.txt`](requirements-agent.txt).

### Or one-line Docker (no local Python)

The Dockerfile's `engine` stage runs the analyzer over a repo mounted at
`/workspace` and writes artifacts to `/artifacts`:

```bash
docker build --target engine -t file-analyzer .
docker run --rm -v "$PWD:/workspace:ro" -v "$PWD/artifacts:/artifacts" \
  file-analyzer /workspace --out /artifacts --quiet
```

Then query the result:

```bash
sqlite3 ./artifacts/repository.db "SELECT * FROM v_extension_distribution;"
```

## Use with AI agents (MCP)

`file-analyzer` ships an [MCP](https://modelcontextprotocol.io) server so agents
(Claude Code/Desktop, opencode, Cursor, Cline, Windsurf, …) can drive the engine.
The intended loop is **analyze once, then ask questions with SQL** over the `v_*`
views — the agent writes ordinary `SELECT`s instead of parsing walls of text.

```bash
pip install -r requirements-agent.txt      # the MCP SDK
python -m mcp_server                        # stdio transport (or: file-analyzer-mcp)

# register with Claude Code (other agents take the same command in their config):
claude mcp add file-analyzer -- python -m mcp_server
```

Tools: `analyze_repository`, `query`, `list_views`, `read_views`,
`describe_schema`, `run_component`, `list_components`. `query` is read-only
(`mode=ro` + `PRAGMA query_only`, single `SELECT`/`WITH` only); `read_views`
bulk-reads many `v_*` views at once through the native Go reader's concurrent
worker pool (with a concurrent pure-Python fallback).

Not using MCP? The CLI is agent-friendly too: pass **`--quiet`** so stdout carries
only the final JSON (progress goes to stderr), and see **[`AGENTS.md`](AGENTS.md)**
for the driving guide and **[`tools.json`](tools.json)** for function-calling
(Grok/DeepSeek/OpenAI-style) tool definitions.

## Using the pipeline as a library

Import the public classes from the `file_analyzer.engine` facade (after
`pip install file-analyzer`, or `file-analyzer-engine`):

```python
from file_analyzer.engine import (RepositoryAnalyzer, PolyglotCodeAnalyzer, ImportLinkageAnalyzer,
                 SchemaAnalyzer, DataAnalyzer, RepositoryDatabaseGenerator,
                 AnalysisEngine)

engine = AnalysisEngine()
summary = engine.run("/path/to/repo", out_dir="./artifacts")
```

### Package layout

The tables below describe the **import layout** — the modules under the shared
`file_analyzer` namespace, all provided by the **engine** distribution (its source
lives in [`packages/engine/`](packages/engine/)). The public fleet + SDK are imported
via the `file_analyzer.engine` facade (`from file_analyzer.engine import …`); the
stdlib foundation (`file_analyzer.runtime_guard`, `file_analyzer.store`,
`file_analyzer.client`, …) is provided by the **client** distribution
([`packages/client/`](packages/client/)), and `file_analyzer.server` by the **server**
distribution. See [Installation & packaging](#installation--packaging) for which
distribution ships what.

| package                | role                                                                      |
|------------------------|---------------------------------------------------------------------------|
| `file_analyzer/core/`            | orchestration glue — `analysis_engine`, `repository_analyzer`, `import_linkage`, `db_generator` (re-exported via the `file_analyzer.engine` facade). |
| `file_analyzer/prog_lang/`       | per-language source analyzers (classes, functions, imports, symbols).     |
| `file_analyzer/schema/`          | SQL DDL / IDL schema analyzers → `schema_*` tables.                        |
| `file_analyzer/data/`            | data-artifact profiler (metadata / stats / sampling only) → `data_*` tables. |
| `file_analyzer/database/`        | database-file analyzers (merges schema + data for DB formats).            |
| `file_analyzer/archive/`         | archive traversal (nested, bounded depth).                                |
| `file_analyzer/binary/`          | machine-code and binary-format analyzers.                                 |
| `file_analyzer/config/`, `file_analyzer/text/`, `file_analyzer/markup/`, `file_analyzer/document/`, `file_analyzer/script/`, `file_analyzer/shell/`, `file_analyzer/misc/` | format-family analyzers for the long tail of file types. |
| `file_analyzer/convert/`         | opaque → renderable format conversion helpers.                            |
| `file_analyzer/router/`          | pure-Python routing / staging that dispatches files to analyzers.         |
| `file_analyzer/views/`           | the views + reads layer (single source of truth — see below).             |
| `file_analyzer/tables/` | canonical reference tables — the extension catalog (`file_extensions.json`) and the IANA timezone tables (`iana_local_timezones.json`, `iana_global_timezones.json`). |

## The views layer (`file_analyzer/views`)

The analysis views are defined **once**, in Python, and installed into every
database the engine produces (and mirrored into the `.sql` dump). The Go reader
embeds no query SQL — it **discovers** the installed `VIEW` objects from the
database catalog. Add or change a view in
[`file_analyzer/views/catalog.py`](packages/engine/file_analyzer/views/catalog.py) and the reader, plus the
Postgres/Docker backend, picks it up with no code changes.

| module        | role                                                                       |
|---------------|----------------------------------------------------------------------------|
| `catalog.py`  | the view catalog: `VIEW_CATALOG` of `ViewDef(name, tables, select)`; DB object names are `v_<name>`. |
| `builder.py`  | turns the catalog into real objects: `install_views_sqlite(db)`, `append_views_to_sql_dump(sql)`, `views_ddl(dialect)`, `write_sql_artifacts(dir)`. |
| `reader.py`   | Python reads over the installed views: `list_views`, `read_view`, `read_all_views`. |
| `native_reader.py` | concurrent bulk reads: `read_views_native` hands the view set to the Go (`go/`) reader, which fans out across a goroutine pool; `read_views_python` is the toolchain-free concurrent fallback. |
| `__main__.py` | CLI (`python -m file_analyzer.views …`).                                             |
| `sql/`        | generated artifacts: `views.sqlite.sql`, `views.pgsql.sql`, `catalog.json`. |
| `go/`         | the native concurrent Go view reader (`-json` mode) that `native_reader.py` builds on demand — the Go reader program (below). |

A view is created only when **all of its base tables are present**, so a database
lacking the `schema_*` / `data_*` families simply never gets (and never errors on)
those views. This gives readers a clean contract: *a view exists in the DB ⟺ its
base tables exist*, so they can enumerate `type='view'` and `SELECT *` with zero
skip-logic. Installation is **additive, idempotent, and the only write**: it creates
read-only `VIEW` objects over existing tables and never touches table data.

```bash
python -m file_analyzer.views install   repository.db
python -m file_analyzer.views dump      repository_schema.sql
python -m file_analyzer.views list      repository.db
python -m file_analyzer.views read      repository.db --view v_extension_distribution
python -m file_analyzer.views artifacts packages/engine/file_analyzer/views/sql   # (re)generate sql/ artifacts
```

### View catalog — 33 views over the `v_` prefix

- **core (10):** `file_inventory`, `extension_distribution`, `folder_tree_depth`,
  `import_internal_vs_external`, `import_edges`, `top_classes_by_methods`,
  `functions_defined_vs_imported`, `symbols_by_kind`, `introspection_by_language`,
  `tensor_members_by_kind`.
- **schema (12):** `schema_databases_by_engine`, `schema_tables_by_engine`,
  `schema_tables_by_kind`, `schema_top_column_types`, `schema_keys_by_type`,
  `schema_foreign_key_edges`, `schema_constraints_by_type`,
  `schema_triggers_by_timing`, `schema_methods_by_language`,
  `schema_types_by_category`, `schema_top_indexed_tables`,
  `schema_entities_per_file`.
- **data (11):** `data_datasets_by_modality`, `data_datasets_by_category`,
  `data_datasets_by_format`, `data_analysis_status`, `data_largest_tabular`,
  `data_columns_by_inferred_type`, `data_top_correlations`,
  `data_tensors_by_dtype`, `data_largest_tensors`, `data_properties_by_group`,
  `data_entities_per_file`.

## The concurrent reader (Go)

A single **Go** program opens the artifact and reads every discovered view across
a pool of goroutine workers, concurrently and **strictly read-only**. When the Go
toolchain is absent, `native_reader.py` falls back to a concurrent pure-Python
read with the same discovered-views contract and read-only guarantees.

### Read-only guarantees

Zero writes, zero changes, zero commits by the workers. Enforced in layers:

1. **Open mode** — the database is opened `mode=ro` (`SQLITE_OPEN_READONLY`).
2. **Engine pragma** — every pooled connection sets `PRAGMA query_only = true`.
3. **Start-up canary** — before any worker starts, the program attempts a write
   (`CREATE TABLE __readonly_canary__`) and *requires it to fail*. If the write
   ever succeeds, the program aborts. You'll see `read-only : verified (write
   canary rejected)` on success.
4. **Query-only code paths** — workers only ever call the read API (`db.Query*` in
   Go). No `Exec`, no transactions, no commits.

Each reader accepts either the `.db`/`.sqlite` (opened in place, read-only) or the
`.sql` dump (loaded **once** into a private temp snapshot the workers then read;
the original file is never modified and the temp file is deleted on exit).

### CLI

| flag        | default        | meaning                                            |
|-------------|----------------|----------------------------------------------------|
| `-source`   | `repository.db`| path to the `.db` or `.sql` produced by the engine |
| `-workers`  | CPU count      | number of concurrent goroutine workers             |
| `-repeat`   | `1`            | replay the whole view set N times for sustained load|
| `-verbose`  | off            | print every result body (default: once per view)   |

### Go

Pure-Go SQLite driver (`modernc.org/sqlite`) — no cgo / no gcc needed.

```bash
cd packages/engine/file_analyzer/views/go
go mod tidy          # fetches modernc.org/sqlite
go build -o repo-reader .
# point -source at an artifact the engine produced (absolute path shown; adjust to yours):
./repo-reader -source /path/to/artifacts/repository.db -workers 6 -repeat 2
./repo-reader -source /path/to/artifacts/repository_schema.sql -workers 4
```

## Docker — Postgres backend + frontend + views

`docker-compose.yml` (the default compose file, so no `-f` needed) brings up
Postgres, a one-shot `loader`, and pgAdmin, loading every artifact the engine
produced (see the compose file header for usage).

An **optional containerized engine** (compose `engine` profile, Dockerfile `engine`
stage) *produces* those artifacts by running `python -m file_analyzer.main` against a mounted
source repository — so the whole flow can run in containers:

```bash
# 1. produce artifacts from a source repo into ./artifacts
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  docker compose --profile engine run --build engine

# 2. bring up Postgres + loader to ingest ./artifacts
ARTIFACTS_DIR=./artifacts docker compose up --build
```

The `engine` service runs `python -m file_analyzer.main` and accepts **any** of its
arguments. Pass them as one `ENGINE_ARGS` string (shell-split and appended to the
entrypoint), or inline after the service name:

```bash
# via ENGINE_ARGS (overrides the default command):
SOURCE_DIR=/path/to/repo \
  ENGINE_ARGS="/workspace --out /artifacts --dialect postgresql --no-git --workers 8" \
  docker compose --profile engine run --build engine

# or inline (replaces the command for that run):
docker compose --profile engine run --build engine \
  /workspace --out /artifacts --dialect postgresql

# see every flag:
docker compose --profile engine run --build engine --help
```

The views are wired in two ways:

- **`.sql` dumps** (postgresql dialect) already contain the appended
  `CREATE OR REPLACE VIEW` statements, so `psql` creates them on load.
- **`.db` artifacts** go through `pgloader`, which copies *tables only*; the loader
  then applies [`file_analyzer/views/sql/views.pgsql.sql`](packages/engine/file_analyzer/views/sql/views.pgsql.sql)
  (bind-mounted in) to (re)create the views per database. Views over absent tables
  are skipped, matching the SQLite-side contract.

An **optional containerized Go reader** (compose `reader` profile) runs the same
view-reading worker against a mounted artifact:

```bash
docker compose --profile reader run --build reader
# point at another artifact / tune workers:
docker compose --profile reader run --build reader -source /artifacts/some_archive.db -workers 8
```

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE). No
third-party components are bundled; the Go reader/plane build against
`modernc.org/sqlite` (BSD-3-Clause), fetched at build time and not redistributed
in this repo. See [NOTICE](NOTICE) for attribution.
