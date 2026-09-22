# USAGE

`python -m file_analyzer.main` is the single entry point. It has **two modes**:

1. **Full pipeline** (default) — run the whole `AnalysisEngine` over a repository
   and write the `repository.db` + `repository_schema.sql` artifacts (with the
   `v_*` analysis views installed).
2. **Component mode** (`--component NAME`) — run *one* building block in isolation
   and dump only its tables as JSON. This is the escape hatch for debugging a
   single analyzer, re-running one plane, or assembling a database from
   externally-produced tables.

```bash
# full pipeline
python -m file_analyzer.main <source-dir> --out ./artifacts

# component mode
python -m file_analyzer.main <source-dir> --component <NAME> --emit out.json
python -m file_analyzer.main --list-components          # discover valid component names
```

Run it as a module (`python -m file_analyzer.main …`, from the repo root so `file_analyzer` imports)
or by path (`python file_analyzer/main.py …`; `main.py` bootstraps its own package root, so
it works from any cwd or inside the container).

> **⚠️ Containment: container or VM only.** `python -m file_analyzer.main` (and the monitor,
> `python -m file_analyzer`) **refuse to run on bare-metal host hardware** — they start only
> inside a container (Docker/Podman/containerd/LXC/Kubernetes) or a virtual machine,
> and otherwise exit with code **3** and a refusal banner on stderr. `--help` is
> exempt (the check runs after argument parsing), so you can always inspect the flag
> surface. Deliberate opt-out on an already-isolated box: `FILE_ANALYZER_ALLOW_BARE_METAL=1`.
> The [Docker workflow](#part-3--running-any-of-this-in-docker) satisfies this
> automatically. Full detail: [runtime-containment.md](runtime-containment.md).

The source must be a **git repository** — the census walks git-tracked files.
Pass `--no-git` to census every file on disk instead. On success a JSON summary is
printed to stdout. On failure the engine keeps its `temp/` staging dir for
debugging and the process exits non-zero.

> **Driving this from a script or an AI agent?** Add **`--quiet`** so the engine's
> progress lines go to stderr and **stdout carries only the final JSON** — safe to
> pipe straight into a parser. See [Part 4 — AI agents (MCP)](#part-4--ai-agents-mcp)
> for the MCP server and the cross-agent guide.

### Installing it as a command

You can run the CLI three ways — all equivalent:

```bash
python -m file_analyzer.main <source-dir> --out ./artifacts     # from the repo root
python file_analyzer/main.py <source-dir> --out ./artifacts      # by path, from any cwd
file-analyzer <source-dir> --out ./artifacts           # after `pip install .`
```

`pip install .` (or `pipx install .`) puts a **`file-analyzer`** command on your
`PATH`, invocable from any directory, and a **`file-analyzer-mcp`** command that
starts the MCP server. Everything documented below applies identically to all
three forms.

---

## Part 1 — Full-pipeline arguments

### Positional & output

| argument | default | what it does |
|----------|---------|--------------|
| `source` | `.` | Directory to analyze. Must be a git repo unless `--no-git`. |
| `-o`, `--out PATH` | `.` | Output directory for the artifacts. Created if missing. |
| `--db NAME` | `repository.db` | SQLite database filename, written under `--out`. |
| `--sql NAME` | `repository_schema.sql` | SQL text-dump filename, written under `--out`. |
| `--dialect {sqlite,postgresql,pgsql}` | `sqlite` | SQL dump dialect. Use `postgresql` for a `psql`-loadable dump (what the docker loader wants). |
| `--temp PATH` | `<out>/temp` | Staging dir for intermediate files. Point it somewhere writable when the source tree is read-only (e.g. in a container). |
| `--keep-temp` | off | Keep the `temp/` staging dir on success (for debugging). |
| `-q`, `--quiet` | off | Route the engine's incidental progress lines to stderr so **stdout carries only the final JSON result**. Use it when piping to a parser or driving from an agent. Applies to component mode too. |

### Concurrency

The pipeline has two concurrent stages: the **routing planes** (per-shard analyzer
fan-out) and the **table-injection** SQLite export (concurrent writers).

| argument | default | what it does |
|----------|---------|--------------|
| `--workers N` | CPU count | Default worker count for **both** concurrent stages. |
| `--plane-workers N` | `--workers` | Workers per analysis plane; overrides `--workers` for the routing stage only. |
| `--injection-workers N` | `--workers` | Concurrent writer threads for the SQLite export; overrides `--workers` for the db-write stage only. |
| `--python-exe PATH` | current interpreter | Python the plane workers invoke for subprocess planes. |

### Census (RepositoryAnalyzer)

Controls how the file census walks the tree and which files it records.

| argument | default | what it does |
|----------|---------|--------------|
| `--order {bfs,dfs}` | `bfs` | Directory-traversal order. |
| `--ignore-dir NAME` | analyzer default set | Directory name to skip (repeatable). **Overrides the default ignore set entirely** — so if you use it, re-list any of `__pycache__` / `.git` / `.venv` you still want skipped. |
| `--ignore-file NAME` | — | File name to skip (repeatable). |
| `--exclude-folder REGEX` | — | Regex; folders whose path matches are excluded (repeatable). |
| `--exclude-file REGEX` | — | Regex; files whose path matches are excluded (repeatable). |
| `--ext-catalog PATH` | bundled catalog | Path to the authoritative `file_extensions.json` used for extension ids. |
| `--no-git` | off | Census every file on disk instead of only git-tracked files. |

### Pipeline stage gates

Each flag turns **off** an optional stage (all stages are on by default).

| argument | what it does when set |
|----------|-----------------------|
| `--no-linkage` | Skip cross-file import linkage over the code tables (no `import_linkage_table`). |
| `--no-archives` | Do not recurse into archive containers (zip/tar/…). |
| `--max-archive-depth N` (default `8`) | Max nested-archive recursion depth. |
| `--no-binary` | Skip the machine-code / object / bytecode deep-parse stage. |
| `--no-conversions` | Skip renderable transcoding of opaque/legacy files. |
| `--no-conversion-analysis` | Transcode, but skip the structural deep-parse of the rendered artifacts. |
| `--conversions-dir PATH` (default `<db_stem>_renderable/`) | Output dir for rendered artifacts. |
| `--no-views` | Do not install the `v_*` analysis views into the db/dump. |

### Database generation (RepositoryDatabaseGenerator)

| argument | default | what it does |
|----------|---------|--------------|
| `--schema-name NAME` | `code_intelligence` | Namespace/schema name for the postgresql/mysql dump. |
| `--no-drop` | off | Do **not** prepend `DROP TABLE IF EXISTS` statements to the dump. |

### Full-pipeline examples

```bash
# Default: analyze the current repo into ./artifacts (sqlite artifacts + views)
python -m file_analyzer.main . --out ./artifacts

# Postgres-loadable dump for the docker loader
python -m file_analyzer.main . --out ./artifacts --dialect postgresql

# Analyze a read-only tree in a container; stage under a writable dir
python -m file_analyzer.main /workspace --out /artifacts --temp /tmp/staging

# Non-git tree, code only (skip archives/binary/conversions), 8 workers
python -m file_analyzer.main ./src --no-git --no-archives --no-binary --no-conversions --workers 8

# Keep it lean: no views, no drop statements
python -m file_analyzer.main . --out ./artifacts --no-views --no-drop
```

---

## Part 2 — Component mode: run the modules separately

Component mode bypasses `AnalysisEngine` and runs a single block. Discover the
valid names first:

```bash
python -m file_analyzer.main --list-components
```

which prints three groups: **special** (`census`, `linkage`, `dbgen`), **planes**
(`code`, `schema`, `database`, `data`, `config`, `text`, `markup`, `document`,
`misc`), and **language_analyzers** (every `{Lang}Analyzer` class name). Names are
**case-insensitive**, and `PythonAnalyzer` is accepted as an alias for
`PythonCodeAnalyzer`.

### Component-mode arguments

| argument | applies to | what it does |
|----------|-----------|--------------|
| `--list-components` | — | Print every valid `--component` value and exit. |
| `-C`, `--component NAME` | — | Run only this block and dump its tables as JSON. |
| `--emit PATH` | most components | Output JSON path (default: `<component>_analysis.json` under `--out`). Ignored by `dbgen`. |
| `--tables-json PATH` | `linkage`, `dbgen` | **Input** tables JSON these two table-driven components consume (see below). |
| `--build-db` | `dbgen` | Also materialize the SQLite `.db` (concurrently) after writing the `.sql`. |
| `--mapping` | `census` | Also emit the file→analyzer mapping and per-class shards. |

Component mode also reuses the relevant full-pipeline args: the census flags
(`--order`, `--ignore-*`, `--exclude-*`, `--ext-catalog`, `--no-git`) shape the
census that feeds every source-scanning component; `--out`, `--db`, `--sql`,
`--dialect`, `--schema-name`, `--no-drop`, and `--injection-workers` steer `dbgen`.

### The modules, one by one

Each component maps to a public class you can also import directly from `file_analyzer`.
The right-hand column names the table family it produces (the same families the
`v_*` views read).

| component | class | scans | produces |
|-----------|-------|-------|----------|
| `census` / `repo` | `RepositoryAnalyzer` | the whole tree | `folders`, `extensions`, `files` (+ `mapping`/`shards` with `--mapping`) |
| `code` / `polyglot` | `PolyglotCodeAnalyzer` | every code file | `code_tables` (classes, functions, symbols, imports, …) |
| `<Lang>Analyzer` | e.g. `RustAnalyzer`, `PythonCodeAnalyzer`, `GoAnalyzer`, `CppAnalyzer` | only that language's files | that analyzer's slice of `code_tables` |
| `schema` | `SchemaAnalyzer` | SQL DDL / IDL files | `schema_tables` (tables, columns, keys, constraints, triggers, …) |
| `database` | `DatabaseAnalyzer` | database files | `database_tables` |
| `data` | `DataAnalyzer` | data artifacts (csv/parquet/tensors/…) | `data_tables` (datasets, columns, tensors, relations, …) |
| `config` | `ConfigAnalyzer` | config files | `config_tables` |
| `text` | `TextualAnalyzer` | text/log/doc-ish records | `text_tables` |
| `markup` | `MarkupAnalyzer` | XML/HTML/wiki/markdown/… | `markup_tables` |
| `document` | `DocumentAnalyzer` | document formats | `document_tables` |
| `misc` | `MiscAnalyzer` | the long-tail formats | `misc_tables` |
| `linkage` | `ImportLinkageAnalyzer` | *(no census; reads `--tables-json`)* | `import_linkage` |
| `dbgen` / `db` | `RepositoryDatabaseGenerator` | *(no census; reads `--tables-json`)* | the `.sql` dump (+ `.db` with `--build-db`) |

**How selection works.** For a plane (`code`, `schema`, …), the census runs and
routing (`resolve_analyzer`) picks exactly the files that plane owns. For a single
`{Lang}Analyzer`, only files whose extension that analyzer claims are selected. The
non-code planes additionally run `link_repository()` — exactly like the real
per-shard worker — so their emitted rows carry repository-wide file ids, not
local ones. If nothing matches, the component emits empty tables and warns.

### Component examples

```bash
# Census only, with the file->analyzer mapping and shards
python -m file_analyzer.main . --component census --mapping --emit repo_tables.json

# One language analyzer over just its files
python -m file_analyzer.main . --component RustAnalyzer --emit rust.json
python -m file_analyzer.main . --component PythonAnalyzer --emit py.json

# All code, or a single non-code plane
python -m file_analyzer.main . --component code   --emit code.json
python -m file_analyzer.main . --component data   --emit data.json
python -m file_analyzer.main . --component schema --emit schema.json

# Linkage over previously-emitted code tables
python -m file_analyzer.main --component linkage --tables-json all_tables.json --emit linkage.json

# Build the .sql (+ .db) from a merged tables JSON
python -m file_analyzer.main --component dbgen --tables-json all_tables.json \
    --build-db --db out.db --sql out.sql --dialect postgresql
```

### The `--tables-json` contract (for `linkage` and `dbgen`)

Both table-driven components read a single JSON object. Recognized keys:

- `folders`, `extensions`, `files` — the repository census tables.
- `code_tables` — the code analyzer output.
- `import_linkage` — the linkage rows (consumed by `dbgen`; produced by `linkage`).
- `schema_tables`, `database_tables`, `data_tables`, `config_tables`,
  `text_tables`, `markup_tables`, `document_tables`, `misc_tables`,
  `archive_tables`, `binary_tables`, `conversion_tables` — the per-plane outputs.
- `linkage` additionally reads `analyzed_file_paths` (and optional `code_file_map`).

Any key you omit is simply treated as empty, so you can assemble a database from
whatever subset of planes you ran.

### Rebuilding the full pipeline by hand

Because every stage is a separately-runnable component, you can reproduce the full
run as a chain — useful when you want to inspect or swap one stage:

```bash
# 1. census (+ mapping)
python -m file_analyzer.main . --component census --mapping --emit repo.json
# 2. run the planes you care about
python -m file_analyzer.main . --component code   --emit code.json
python -m file_analyzer.main . --component data   --emit data.json
python -m file_analyzer.main . --component schema --emit schema.json
# 3. merge repo.json/code.json/data.json/schema.json into all_tables.json
#    (folders/extensions/files + code_tables + *_tables), then linkage:
python -m file_analyzer.main --component linkage --tables-json all_tables.json --emit linkage.json
# 4. add import_linkage to the merged JSON, then generate the database:
python -m file_analyzer.main --component dbgen --tables-json all_tables.json --build-db \
    --db repository.db --sql repository_schema.sql
```

(The default `python -m file_analyzer.main .` does all of this in one process, with
concurrency and the `v_*` views installed — the manual chain is for when you need
to see or modify an intermediate stage.)

---

## Part 3 — Running any of this in Docker

Everything above works unchanged inside the containerized **`engine`** service
(compose profile `engine`, Dockerfile `engine` stage). Its entrypoint **is**
`python -m file_analyzer.main`, so **any argument in Part 1 or Part 2 is passed through
verbatim** — you are running the exact same CLI, just in a container.

### Mounts and env vars

| host env var | mounts to | mode | meaning |
|--------------|-----------|------|---------|
| `SOURCE_DIR` (default `./workspace`) | `/workspace` | read-only | the repo to analyze (positional `source`) |
| `ARTIFACTS_DIR` (default `./artifacts`) | `/artifacts` | read-write | where `--out` / `--emit` / `--conversions-dir` output must land |

Because `/workspace` is **read-only**, point `--out`, `--emit`, `--temp` and
`--conversions-dir` **under `/artifacts`** (or another writable mount) so they
persist to the host and don't fail writing into the source tree.

### Two ways to pass arguments

```bash
# (a) inline after the service name — replaces the service's default command:
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  docker compose --profile engine run --build engine \
    /workspace --out /artifacts --dialect postgresql --no-git --workers 8

# (b) as one ENGINE_ARGS string — shell-split and appended to the entrypoint:
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  ENGINE_ARGS="/workspace --out /artifacts --dialect postgresql --no-git --workers 8" \
  docker compose --profile engine run --build engine

# discover the argument surface, containerized:
docker compose --profile engine run --build engine --help
docker compose --profile engine run --build engine --list-components
```

### Component mode in the container

Same `--component` names as Part 2 — just emit under `/artifacts`:

```bash
# one plane / one language, JSON out to the host
docker compose --profile engine run --build engine \
  /workspace --component data --emit /artifacts/data.json
docker compose --profile engine run --build engine \
  /workspace --component RustAnalyzer --emit /artifacts/rust.json

# census with mapping
docker compose --profile engine run --build engine \
  /workspace --component census --mapping --emit /artifacts/repo.json

# table-driven components read their input JSON from /artifacts too
docker compose --profile engine run --build engine \
  --component dbgen --tables-json /artifacts/all_tables.json --build-db \
  --db /artifacts/repository.db --sql /artifacts/repository_schema.sql
```

### The views CLI in the container

The `engine` image also contains `file_analyzer.views`. Override the entrypoint to run it
against an artifact already in `/artifacts`:

```bash
docker compose --profile engine run --build --entrypoint python engine \
  -m file_analyzer.views list /artifacts/repository.db
```

### Full stack (Postgres + loader + pgAdmin)

Producing artifacts with `--dialect postgresql`, then bringing the stack up, loads
them into Postgres and (re)creates the `v_*` views automatically:

```bash
# 1. produce postgres-loadable artifacts
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  docker compose --profile engine run --build engine \
    /workspace --out /artifacts --dialect postgresql
# 2. load them (postgres + one-shot loader + pgAdmin on :8080)
ARTIFACTS_DIR=./artifacts docker compose up --build
```

See [`../README.md`](../README.md) for the full stack details (the `loader`
applies `file_analyzer/views/sql/views.pgsql.sql` after each `.db` load, since `pgloader`
copies tables only) and [`views/README.md`](views/README.md) for the view layer.

---

## Part 4 — AI agents (MCP)

`file-analyzer` ships an **[MCP](https://modelcontextprotocol.io) server** so AI
agents (Claude Code/Desktop, opencode, Cursor, Cline, Windsurf, Antigravity, …)
can drive the engine directly. The intended loop is **analyze once, then ask
questions with SQL** over the `v_*` views — the agent writes ordinary `SELECT`s
instead of parsing walls of text.

```bash
pip install -r requirements-agent.txt     # the MCP SDK (mcp[cli])
python -m mcp_server                       # stdio transport
#   or, after `pip install .`:  file-analyzer-mcp

# register with an agent (Claude Code shown; others take the same command):
claude mcp add file-analyzer -- python -m mcp_server
```

### Tools

| tool | what it does |
|------|--------------|
| `analyze_repository(path, out_dir?, dialect?, no_git?, workers?, plane_workers?, injection_workers?)` | Run the full pipeline; returns the JSON summary incl. the `database` path and a `toolchains` map. The analysis planes fan out across Go/Java when available. Output defaults to `<path>/.file-analyzer`. |
| `query(sql, db_path, limit?)` | Run a **single read-only** `SELECT`/`WITH` against the database (opened `mode=ro` + `PRAGMA query_only`). |
| `list_views(db_path)` | List the installed `v_*` analysis views. |
| `read_views(db_path, views?, limit?, engine?, workers?)` | **Bulk-read** many `v_*` views at once. `engine="auto"` splits them across the Go and Java readers concurrently (read-only), falling back to concurrent Python when no toolchain is present. |
| `describe_schema(db_path, include_views?)` | Base tables + columns, plus the view catalog SQL. |
| `run_component(component, path, out_dir?)` | Run one analyzer block (a language/plane/`census`) in isolation — the [Part 2](#part-2--component-mode-run-the-modules-separately) blocks. |
| `list_components()` | Enumerate valid `run_component` names. |

Resource `file-analyzer://views` returns the full view catalog (name, base tables,
SQL) as JSON for context. The MCP server wraps the **same** in-process engine as
the CLI, and routes the engine's stdout chatter to stderr so it never corrupts the
JSON-RPC stream.

### Other agent surfaces

- **[`../AGENTS.md`](../AGENTS.md)** — the cross-agent driving guide (both the MCP
  and the `--quiet` CLI paths, plus a question → SQL cheat-sheet).
- **[`../tools.json`](../tools.json)** — JSON-schema function definitions to drop
  into a function-calling `tools` array (Grok/DeepSeek/OpenAI-style).
- **[`../.claude/skills/file-analyzer/SKILL.md`](../.claude/skills/file-analyzer/SKILL.md)**
  — a Claude Code skill so the analyzer is reached for proactively on whole-repo
  questions.
- Non-MCP agents can just shell out to `file-analyzer … --quiet` and parse stdout.

---

## Exit codes

| code | meaning |
|------|---------|
| `0` | success — JSON summary printed to stdout. |
| `1` | a stage failed (census / analyzer / linkage / dbgen / engine). The engine keeps `temp/` for debugging. |
| `2` | bad invocation — source is not a directory, unknown component, or a table-driven component was run without `--tables-json`. |
| `3` | **containment refusal** — running on bare-metal host hardware (no container/VM detected and `FILE_ANALYZER_ALLOW_BARE_METAL` not set). See [runtime-containment.md](runtime-containment.md). |

## See also

- [`../README.md`](../README.md) — project overview, the views layer, the Go/Java
  readers, and the Docker workflow.
- [Part 4 — AI agents (MCP)](#part-4--ai-agents-mcp) and [`../AGENTS.md`](../AGENTS.md)
  — drive the engine from Claude/opencode/Cursor/Grok/DeepSeek/… via the MCP server,
  `tools.json`, or the `--quiet` CLI.
- `python -m file_analyzer.views --help` — install/list/read the `v_*` analysis views over an
  existing database.
- `docker compose --profile engine run --build engine --help` — the same
  `main.py` argument surface, containerized (pass args via `ENGINE_ARGS`).
- [`runtime-containment.md`](runtime-containment.md) — why the CLI refuses to run
  on bare metal, what counts as a container/VM, and the `FILE_ANALYZER_ALLOW_BARE_METAL`
  override.
- [`monitor.md`](monitor.md) — the always-on background monitor
  (`python -m file_analyzer monitor`): incremental re-analysis, durable change log, worker
  pool, and the soft MCP agent tier.
