# file-analyzer-client

The tiny, dependency-free client for the **file-analyzer** platform.

This wheel is pure Python standard library. Install it on any machine that needs
to talk to the platform without pulling in the analyzer fleet:

- **Connect to a hosted server and run queries** — `connect()` / `ServerClient`
- **Read / query a local `.db` offline** — `open_database()` / `FileAnalyzerDatabase`
- **Optionally run an analysis locally** — `analyze()`, available only when the
  separate `file-analyzer-engine` wheel is also installed

```python
from file_analyzer.client import open_database, connect, has_engine

# Read a database a previous analysis run produced -- offline, no engine needed.
db = open_database("repository.db")
print(db.tables())
for row in db.query_dicts("SELECT path FROM files LIMIT 5"):
    print(row["path"])

# Talk to a hosted server.
client = connect("http://localhost:8765", token="…")
print(client.health())

# Local analysis is opt-in; it needs the engine wheel.
if has_engine():
    from file_analyzer.client import analyze
    result = analyze(".")
    print(result.database)
```

## Related wheels

The platform ships as three wheels that share the `file_analyzer` namespace:

| Wheel                    | Install where            | Contains                                   |
| ------------------------ | ------------------------ | ------------------------------------------ |
| `file-analyzer-client`   | anywhere (this wheel)    | client + read-only DB access (stdlib only) |
| `file-analyzer-server`   | the hosting server       | the database-hosting server                |
| `file-analyzer-engine`   | wherever analysis runs   | the analyzer fleet that builds databases   |

Installing only the client keeps the footprint minimal; add the others when a
machine actually needs to host databases or run analyses.
