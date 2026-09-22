# file-analyzer

**Point it at a repository, get back a queryable database of everything in it.**

`file-analyzer` is a **repository intelligence platform**. Its core walks a source
tree — code, schemas, data files, archives, binaries, configs, docs — **without ever
executing it**, and emits a single **SQLite** (or **PostgreSQL**) database describing
what it found: files and folders, per-language symbols (classes, functions, imports
and the links between them), database schemas (tables, columns, keys, constraints,
triggers), data-artifact profiles (datasets, columns, tensors, correlations), and
more. A layer of ready-made **analysis views** (`v_*`) sits on top so you can answer
questions with plain `SELECT`s, and two independent **concurrent readers** (Go and
Java) demonstrate strictly read-only access to those views.

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

> **⚠️ Runs in a container or VM only.** The CLI entrypoints (`file-analyzer` /
> `python -m src.main` and the monitor `file-analyzer-monitor` / `python -m src`)
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
pip install -r requirements.txt

# Analyze a repository (the source must be a git repo, or pass --no-git).
python -m src.main /path/to/repo --out ./artifacts

# Postgres-loadable dump instead of SQLite:
python -m src.main /path/to/repo --out ./artifacts --dialect postgresql

# All flags (works on any host — --help is exempt from the containment guard):
python -m src.main --help
```

Flags: `--out`, `--db`, `--sql`, `--dialect {sqlite,postgresql}`, `--temp`
(staging dir; defaults under `--out`, so a read-only source still analyzes),
`--workers`, `--no-archives`, `--no-git`, `--keep-temp`, `--quiet` (stdout carries
only the final JSON — for pipes/agents). Prints a JSON summary on success.

### Install as a command

`pip`/`pipx`-install to get a `file-analyzer` command invocable from any directory
(no `python -m`, no specific cwd):

```bash
pipx install .            # or: pip install .
file-analyzer /path/to/repo --out ./artifacts --quiet
file-analyzer-mcp         # start the MCP server (extras: pip install ".[agent]")
```

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
bulk-reads many `v_*` views at once, splitting them across the native Go and Java
readers concurrently (with a concurrent pure-Python fallback).

Not using MCP? The CLI is agent-friendly too: pass **`--quiet`** so stdout carries
only the final JSON (progress goes to stderr), and see **[`AGENTS.md`](AGENTS.md)**
for the driving guide and **[`tools.json`](tools.json)** for function-calling
(Grok/DeepSeek/OpenAI-style) tool definitions.

## Using the pipeline as a library

Import the public classes from the `src` package (run from the repo root so `src`
is importable):

```python
from src import (RepositoryAnalyzer, PolyglotCodeAnalyzer, ImportLinkageAnalyzer,
                 SchemaAnalyzer, DataAnalyzer, RepositoryDatabaseGenerator,
                 AnalysisEngine)

engine = AnalysisEngine()
summary = engine.run("/path/to/repo", out_dir="./artifacts")
```

### Package layout

| package                | role                                                                      |
|------------------------|---------------------------------------------------------------------------|
| `src/core/`            | orchestration glue — `analysis_engine`, `repository_analyzer`, `import_linkage`, `db_generator` (re-exported at the package top level). |
| `src/prog_lang/`       | per-language source analyzers (classes, functions, imports, symbols).     |
| `src/schema/`          | SQL DDL / IDL schema analyzers → `schema_*` tables.                        |
| `src/data/`            | data-artifact profiler (metadata / stats / sampling only) → `data_*` tables. |
| `src/database/`        | database-file analyzers (merges schema + data for DB formats).            |
| `src/archive/`         | archive traversal (nested, bounded depth).                                |
| `src/binary/`          | machine-code and binary-format analyzers.                                 |
| `src/config/`, `src/text/`, `src/markup/`, `src/document/`, `src/script/`, `src/shell/`, `src/misc/` | format-family analyzers for the long tail of file types. |
| `src/convert/`         | opaque → renderable format conversion helpers.                            |
| `src/router/`          | pure-Python routing / staging that dispatches files to analyzers.         |
| `src/views/`           | the views + reads layer (single source of truth — see below).             |
| `src/tables/` | canonical reference tables — the extension catalog (`file_extensions.json`) and the IANA timezone tables (`iana_local_timezones.json`, `iana_global_timezones.json`). |

## The views layer (`src/views`)

The analysis views are defined **once**, in Python, and installed into every
database the engine produces (and mirrored into the `.sql` dump). The Go and Java
readers embed no query SQL — they **discover** the installed `VIEW` objects from
the database catalog. Add or change a view in
[`src/views/catalog.py`](src/views/catalog.py) and every reader, plus the
Postgres/Docker backend, picks it up with no code changes.

| module        | role                                                                       |
|---------------|----------------------------------------------------------------------------|
| `catalog.py`  | the view catalog: `VIEW_CATALOG` of `ViewDef(name, tables, select)`; DB object names are `v_<name>`. |
| `builder.py`  | turns the catalog into real objects: `install_views_sqlite(db)`, `append_views_to_sql_dump(sql)`, `views_ddl(dialect)`, `write_sql_artifacts(dir)`. |
| `reader.py`   | Python reads over the installed views: `list_views`, `read_view`, `read_all_views`. |
| `native_reader.py` | concurrent bulk reads: `read_views_native` splits the views across the Go (`go/`) and Java (`java/`) readers and runs them at the same wall-clock time; `read_views_python` is the toolchain-free concurrent fallback. |
| `__main__.py` | CLI (`python -m src.views …`).                                             |
| `sql/`        | generated artifacts: `views.sqlite.sql`, `views.pgsql.sql`, `catalog.json`. |
| `go/`, `java/` | native concurrent view readers (`-json` mode) that `native_reader.py` builds on demand. |
| `go/`, `java/`| the Go + Java reader programs (below).                                     |

A view is created only when **all of its base tables are present**, so a database
lacking the `schema_*` / `data_*` families simply never gets (and never errors on)
those views. This gives readers a clean contract: *a view exists in the DB ⟺ its
base tables exist*, so they can enumerate `type='view'` and `SELECT *` with zero
skip-logic. Installation is **additive, idempotent, and the only write**: it creates
read-only `VIEW` objects over existing tables and never touches table data.

```bash
python -m src.views install   repository.db
python -m src.views dump      repository_schema.sql
python -m src.views list      repository.db
python -m src.views read      repository.db --view v_extension_distribution
python -m src.views artifacts src/views/sql       # (re)generate sql/ artifacts
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

## The concurrent readers (Go + Java)

Two independent programs — one **Go**, one **Java** — open the artifact and read
every discovered view across a pool of workers, concurrently and **strictly
read-only**. They are functionally equivalent: same discovered views, same read-only
guarantees, same CLI flags.

### Read-only guarantees

Zero writes, zero changes, zero commits by the workers. Enforced in layers:

1. **Open mode** — the database is opened `mode=ro` (`SQLITE_OPEN_READONLY`).
2. **Engine pragma** — every pooled connection sets `PRAGMA query_only = true`.
3. **Start-up canary** — before any worker starts, the program attempts a write
   (`CREATE TABLE __readonly_canary__`) and *requires it to fail*. If the write
   ever succeeds, the program aborts. You'll see `read-only : verified (write
   canary rejected)` on success.
4. **Query-only code paths** — workers only ever call the read API (`db.Query*` in
   Go, `Statement.executeQuery` in Java). No `Exec`/`executeUpdate`, no
   transactions, no commits.

Each reader accepts either the `.db`/`.sqlite` (opened in place, read-only) or the
`.sql` dump (loaded **once** into a private temp snapshot the workers then read;
the original file is never modified and the temp file is deleted on exit).

### CLI (identical for both readers)

| flag        | default        | meaning                                            |
|-------------|----------------|----------------------------------------------------|
| `-source`   | `repository.db`| path to the `.db` or `.sql` produced by the engine |
| `-workers`  | CPU count      | number of concurrent workers (goroutines / threads)|
| `-repeat`   | `1`            | replay the whole view set N times for sustained load|
| `-verbose`  | off            | print every result body (default: once per view)   |

### Go

Pure-Go SQLite driver (`modernc.org/sqlite`) — no cgo / no gcc needed.

```bash
cd src/views/go
go mod tidy          # fetches modernc.org/sqlite
go build -o repo-reader .
# repository.db lives four levels up (repo root), from src/views/go:
./repo-reader -source ../../../repository.db -workers 6 -repeat 2
./repo-reader -source ../../../repository_schema.sql -workers 4
```

### Java (JDK 17+)

Needs the SQLite JDBC driver (`org.xerial:sqlite-jdbc`) and its runtime dependency
`org.slf4j:slf4j-api` — both jars ship alongside the source in `src/views/java`.

```bash
cd src/views/java
javac -cp "sqlite-jdbc-3.45.3.0.jar" RepositoryReader.java
# Windows classpath separator is ';', Unix is ':'
java -cp ".;sqlite-jdbc-3.45.3.0.jar;slf4j-api-2.0.13.jar" RepositoryReader -source ../../../repository.db -workers 6 -repeat 2   # Windows
java -cp ".:sqlite-jdbc-3.45.3.0.jar:slf4j-api-2.0.13.jar" RepositoryReader -source ../../../repository.db -workers 6 -repeat 2   # Unix
```

> sqlite-jdbc 3.45.x prints a one-line `SLF4J: No providers were found` notice and
> defaults to a no-op logger — harmless. Add `slf4j-nop` to silence it.

## Docker — Postgres backend + frontend + views

`docker-compose.yml` (the default compose file, so no `-f` needed) brings up
Postgres, a one-shot `loader`, and pgAdmin, loading every artifact the engine
produced (see the compose file header for usage).

An **optional containerized engine** (compose `engine` profile, Dockerfile `engine`
stage) *produces* those artifacts by running `python -m src.main` against a mounted
source repository — so the whole flow can run in containers:

```bash
# 1. produce artifacts from a source repo into ./artifacts
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  docker compose --profile engine run --build engine

# 2. bring up Postgres + loader to ingest ./artifacts
ARTIFACTS_DIR=./artifacts docker compose up --build
```

The `engine` service runs `python -m src.main` and accepts **any** of its
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
  then applies [`src/views/sql/views.pgsql.sql`](src/views/sql/views.pgsql.sql)
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

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE). The
bundled `sqlite-jdbc` (Apache-2.0) and `slf4j-api` (MIT) jars under
`src/views/java/` are redistributed under their own licenses; see [NOTICE](NOTICE)
for attribution.
