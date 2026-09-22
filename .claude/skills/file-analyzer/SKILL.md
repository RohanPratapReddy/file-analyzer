---
name: file-analyzer
description: >-
  Turn a repository into a queryable SQLite database and answer questions about it
  with SQL. Use when the user wants to understand an unfamiliar or large codebase's
  structure, dependencies, or database schemas — e.g. "what does this repo contain",
  "map the imports / dependencies", "what tables/foreign keys are defined", "what
  data files or datasets are here", "break down files by language", "find the
  biggest files or the classes with the most methods". Prefer this over grepping
  file-by-file when the question is about the repo as a whole.
---

# file-analyzer

`file-analyzer` statically analyzes a whole repository (code, DB schemas, data
files, archives, binaries, configs, docs) — without executing it — and emits a
**SQLite database** carrying ready-made `v_*` analysis views. The workflow is:
**analyze once, then answer questions with SQL** instead of reading files one by
one.

## When to use

Reach for this when the user's question is about the repository as a whole:
- "What's in this codebase / give me an overview / break it down by language"
- "Map the dependencies" / "what imports what" / "internal vs third-party imports"
- "What database tables, columns, keys, foreign keys, triggers are defined"
- "What data files / datasets / tensors are here, and their shapes/types"
- "Biggest files", "classes with the most methods", "symbol counts by kind"

For a single known string in a single known file, plain search is faster — use
this when you'd otherwise fan out across many files.

## How to run it

Two interchangeable interfaces — pick whichever is wired up:

**MCP tools** (if the `file-analyzer` MCP server is connected): call
`analyze_repository(path)` → it returns a `database` path → then `query(sql,
db_path)`, with `list_views` / `describe_schema` to discover what to query.

**CLI** (always available; add `--quiet` so stdout is pure JSON):
```bash
# 1. Analyze (must be a git repo, else add --no-git). Prints a JSON summary
#    whose "database" field is the .db to query.
python -m file_analyzer.main /path/to/repo --out ./artifacts --quiet
#    (or, if pip-installed:  file-analyzer /path/to/repo --out ./artifacts --quiet)

# 2. Ask questions over the v_* views:
sqlite3 ./artifacts/repository.db "SELECT * FROM v_extension_distribution;"
```

## Answering with the views (question → SQL)

| Question | Query |
|---|---|
| Language / file-type mix | `SELECT * FROM v_extension_distribution` |
| Biggest files | `SELECT * FROM v_file_inventory` |
| Symbols by kind | `SELECT * FROM v_symbols_by_kind` |
| Import edges | `SELECT * FROM v_import_edges` |
| Internal vs external imports | `SELECT * FROM v_import_internal_vs_external` |
| Classes with most methods | `SELECT * FROM v_top_classes_by_methods` |
| DB tables by engine | `SELECT * FROM v_schema_tables_by_engine` |
| Foreign-key edges | `SELECT * FROM v_schema_foreign_key_edges` |
| Data files by format | `SELECT * FROM v_data_datasets_by_format` |
| Strongest column correlations | `SELECT * FROM v_data_top_correlations` |

Views only exist when their base tables are present (a repo with no SQL schemas
won't have `v_schema_*`), so run `list_views` / `SELECT name FROM sqlite_master
WHERE type='view'` first if unsure, and `describe_schema` (or `.schema`) to drop
to base tables for anything the views don't cover.

## Guarantees to rely on

- **Read-only & safe:** never executes the analyzed code, never stores raw file
  payloads; the database is opened read-only for querying.
- **Honest degradation:** optional parsers upgrade a format from a partial
  profile to a full deep-parse — nothing is fabricated when a parser is absent.
- See [`AGENTS.md`](../../../AGENTS.md) for the full driving guide and
  [`tools.json`](../../../tools.json) for function-calling tool definitions.
