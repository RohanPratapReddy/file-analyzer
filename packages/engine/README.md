# file-analyzer-engine

The **analyzer fleet** for the **file-analyzer** platform.

Install this wherever analysis actually runs. It turns a source tree into a
queryable SQLite/PostgreSQL database of code, schemas, data, archives, binaries
and documents -- **without executing the code** -- and adds a live background
repository monitor, an MCP agent-enrichment tier, and a document-intelligence
engine (Parts A/B/C).

```python
from file_analyzer.engine import analyze, RepositoryAnalyzer, AnalysisEngine

result = analyze("/path/to/repo")          # one-shot; returns an AnalysisResult
print(result.file_count, result.database)
with result.open() as db:                  # read-only handle (from the client wheel)
    print(db.query("SELECT * FROM v_file_inventory"))
```

Or from the command line (these entrypoints run **only inside a container or VM**
-- see `docs/runtime-containment.md`):

```bash
file-analyzer /path/to/repo --out ./artifacts --quiet
file-analyzer-monitor /path/to/repo --interval 2
file-analyzer-mcp                          # MCP server over stdio (needs [agent])
```

## The public import surface

The fleet's public API is `file_analyzer.engine` (the analyzers, `AnalysisEngine`,
and the SDK classes `FileAnalyzerClient` / `FileAnalyzerAgent` /
`FileAnalyzerMonitor` / `FileAnalyzerMCPServer`). The read-only
`FileAnalyzerDatabase` and `open_database` come from the client wheel and are
re-exported here so both installs hand out the same handle type.

`FileAnalyzerClient.server()` returns the database-**hosting** server, which ships
separately in `file-analyzer-server`; it is imported lazily and raises a helpful
error if that wheel is not installed.

## Dependencies

- Requires `file-analyzer-client` (pure stdlib foundation + read-only DB access).
- The pure-stdlib fleet needs nothing else. Optional extras deepen individual
  formats and enable the MCP server:
  - `pip install "file-analyzer-engine[agent]"` -- the MCP server / agent connectors
  - `pip install "file-analyzer-engine[document]"` -- the full document engine
    (`parse` + `ocr` + `pii` + `eval`)
  - `pip install "file-analyzer-engine[monitor-postgres]"` / `[monitor-mysql]` --
    point the monitor's durable dumps at a remote database

## Related wheels

| Wheel                    | Install where            | Contains                                   |
| ------------------------ | ------------------------ | ------------------------------------------ |
| `file-analyzer-client`   | anywhere                 | client + read-only DB access (stdlib only) |
| `file-analyzer-server`   | the hosting server       | the database-hosting server                |
| `file-analyzer-engine`   | wherever analysis runs   | the analyzer fleet that builds databases (this wheel) |
