# AGENTS.md — driving file-analyzer from an AI agent

This file tells an AI coding agent (Claude, opencode, Cursor, Cline, Windsurf,
Antigravity, Grok, DeepSeek, …) how to use `file-analyzer`. It is a repository
intelligence platform that turns a repository into a **queryable SQLite database** of
everything in it — files, per-language symbols and imports, DB schemas, data-file
profiles, archives, binaries, configs, docs — and adds live/agentic layers on top (a
background monitor with incremental re-analysis, an MCP agent-enrichment tier, and a
document-intelligence engine). It never executes the analyzed code, never modifies
the source tree, and never stores raw file payloads.

**The intended loop for an agent is: analyze once → then ask questions with SQL.**
The database ships denormalized `v_*` analysis views, so you answer questions with
plain `SELECT`s instead of parsing walls of text.

---

## Two ways to connect

### 1. MCP server (recommended for MCP-speaking agents)

Launch over stdio:

```bash
python -m mcp_server              # or: file-analyzer-mcp  --  needs: pip install "mcp[cli]"
```

Register it (Claude Code shown; other agents take the same command in their MCP config):

```bash
claude mcp add file-analyzer -- python -m mcp_server
```

The server starts fast (it doesn't load the analyzer fleet at import) and warms
that fleet in a background thread so the first tool call runs at full speed. To
warm it ahead of time at install/registration (e.g. in a Dockerfile or CI), run
`python -m mcp_server --precompile` once — it bytecode-compiles `src/`, imports
the engine, and exits. Disable the background warm-up with `FILE_ANALYZER_MCP_NO_WARM=1`.

Tools exposed:

| Tool | What it does |
|---|---|
| `analyze_repository(path, out_dir?, dialect?, no_git?, workers?, plane_workers?, injection_workers?)` | Build the database. The analysis planes fan out across Go/Java when available; returns a summary incl. the `database` path and a `toolchains` map. |
| `query(sql, db_path, limit?)` | Run a **single read-only** `SELECT`/`WITH` against the database. |
| `list_views(db_path)` | List the installed `v_*` analysis views. |
| `read_views(db_path, views?, limit?, engine?, workers?)` | **Bulk-read** many `v_*` views in one call. `engine="auto"` splits them across the Go and Java readers concurrently, falling back to concurrent Python when no toolchain is present. |
| `describe_schema(db_path, include_views?)` | Base tables + columns, plus the view catalog SQL. |
| `run_component(component, path, out_dir?)` | Run one analyzer block (a language/plane/`census`) in isolation. |
| `list_components()` | Enumerate valid `run_component` names. |

Resource `file-analyzer://views` returns the full view catalog (name, base tables,
SQL) as JSON for context.

### 2. Plain CLI (for any agent that can run a shell)

Every command prints a **JSON result to stdout**. Pass `--quiet` so stdout is
*only* that JSON (progress goes to stderr) — parse stdout directly.

```bash
# Analyze a repo (must be a git repo, or add --no-git). Pure-JSON summary on stdout:
python -m src.main /path/to/repo --out ./artifacts --quiet

# Then query the produced database (the v_* views carry the analysis):
sqlite3 ./artifacts/repository.db "SELECT * FROM v_extension_distribution;"

# Run one building block and get its tables as JSON:
python -m src.main /path/to/repo --component PythonAnalyzer --emit py.json --quiet
python -m src.main --list-components --quiet
```

Exit codes: `0` success · `1` runtime failure (details on stderr) · `2` bad usage.

---

## Worked examples (question → SQL)

After `analyze_repository`, call `query(sql, db_path)` with these. Prefer `v_*`
views; drop to base tables (see `describe_schema`) for anything they don't cover.

| You want to know… | Query |
|---|---|
| Language / file-type breakdown | `SELECT * FROM v_extension_distribution` |
| The biggest files | `SELECT * FROM v_file_inventory` |
| What symbols exist and how many | `SELECT * FROM v_symbols_by_kind` |
| Import edges between files | `SELECT * FROM v_import_edges` |
| Internal vs third-party imports | `SELECT * FROM v_import_internal_vs_external` |
| Classes with the most methods | `SELECT * FROM v_top_classes_by_methods` |
| DB tables found, by engine | `SELECT * FROM v_schema_tables_by_engine` |
| Foreign-key relationships | `SELECT * FROM v_schema_foreign_key_edges` |
| Data files / datasets by format | `SELECT * FROM v_data_datasets_by_format` |
| Strongest column correlations | `SELECT * FROM v_data_top_correlations` |

`list_views(db_path)` returns the full set for the specific database (views only
exist when their base tables are present, so a repo with no DB schemas simply
won't have the `v_schema_*` views).

**One view vs. many.** Use `query` for a single view or a custom `SELECT`. To pull
a whole batch of views (or all of them) at once, use `read_views` — with
`engine="auto"` it partitions the set across the native Go and Java readers and
runs them at the same wall-clock time, so a wide sweep of large views is faster
than issuing one `query` per view. It transparently falls back to a concurrent
pure-Python read when neither toolchain is on PATH; for a handful of small views,
`engine="python"` avoids the subprocess/JVM start-up and is quickest.

---

## Rules & guarantees for agents

- **Read-only.** `query` opens the database `mode=ro` with `PRAGMA query_only` and
  accepts only a single `SELECT`/`WITH`. Writes and multi-statements are rejected.
- **Analyze before querying.** `query`/`list_views`/`describe_schema` need a
  `db_path` — the `database` field returned by `analyze_repository`.
- **Git by default.** The census walks git-tracked files; pass `no_git=True`
  (MCP) / `--no-git` (CLI) for a non-git tree.
- **Honest degradation.** Optional parsers (see `requirements.txt`) upgrade
  formats from a partial profile to a full deep-parse; nothing is fabricated when
  a parser is absent.
- **Machine contract.** See `tools.json` for JSON-schema tool definitions you can
  drop straight into a function-calling `tools` array (Grok/DeepSeek/OpenAI-style).
