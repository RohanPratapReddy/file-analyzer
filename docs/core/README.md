# `file_analyzer/core` — the orchestration package

`file_analyzer/core` is the glue that ties the per-domain analyzers together into one
repository-analysis pipeline. It holds four classes; the top-level package
re-exports all of them, so they import flat as `from file_analyzer.engine import ...`.

| class | one-line role | component name | doc |
|-------|---------------|----------------|-----|
| `AnalysisEngine` | Drives the whole flow end to end and writes the `.db` + `.sql` artifacts (with `v_*` views). | *engine-only / N/A* | [analysis-engine.md](analysis-engine.md) |
| `RepositoryAnalyzer` | File census: walks the tree into `folders`/`extensions`/`files` and builds the file→analyzer mapping. | `census` / `repo` | [repository-analyzer.md](repository-analyzer.md) |
| `ImportLinkageAnalyzer` | Cross-file import/symbol resolution over the code tables → `import_linkage`. | `linkage` | [import-linkage.md](import-linkage.md) |
| `RepositoryDatabaseGenerator` | Consumes every `*_tables` family and emits the `.sql` dump (+ builds the `.db`). | `dbgen` / `db` | [db-generator.md](db-generator.md) |

The router package (`file_analyzer.router`) owns routing and the Go language plane
(with a pure-Python fallback); `file_analyzer/core` owns the orchestration around them.

## How the four classes chain

```
AnalysisEngine.run()          # file_analyzer/core/analysis_engine.py — the orchestrator
│
├─ 1. RepositoryAnalyzer            census: folders / extensions / files
│        .generate()               + emit_analyzer_mapping() → temp/mapping.json
│                                     (per-analyzer-class shards)
│
├─ 2. RouterPlanes(...).run(shards)  Go concurrent per-shard fan-out (Python fallback);
│                                     each file routed by extension to its engine
│                                     (PolyglotCodeAnalyzer / SchemaAnalyzer /
│                                      DataAnalyzer / …); tables staged in temp/tables/*.json
│
├─ 3. _collect_shard_tables()        load staged code_tables + each *_tables family
│
├─ 4. ImportLinkageAnalyzer          cross-file import linkage over code_tables
│        .generate()               → import_linkage rows
│     (+ ArchiveAnalyzer, MachineCodeAnalyzer, FormatConverter/TextAnalyzer
│        post-plane stages, each optional)
│
├─ 5. RepositoryDatabaseGenerator    one normalized DB from ALL the table families
│        .generate()               → repository_schema.sql (dialect dump)
│        .export_to_sqlite_db_concurrent()  → repository.db (concurrent injectors)
│
├─ 5b. install_views_sqlite / append_views_to_sql_dump   → the v_* analysis views
│
└─ 6. temp/ cleanup (kept on failure for debugging; removed on success)
```

Every stage is also runnable in isolation through `python -m file_analyzer.main --component
NAME` (see [../USAGE.md](../USAGE.md)); component mode instantiates these same
classes directly. The per-component docs each mirror the exact call `main.py`
makes.

Every stage also runs inside the Docker `engine` service (ENTRYPOINT
`python -m file_analyzer.main`) — see the Docker section in each per-doc page below and the
Docker workflow in [`../../README.md`](../../README.md).

## See also

- [../USAGE.md](../USAGE.md) — the `python -m file_analyzer.main` CLI surface (full pipeline + component mode).
- [`../../README.md`](../../README.md) — project overview, the views layer, the Go reader (with Python fallback), and the Docker workflow.
- The per-class docs listed in the table above.
