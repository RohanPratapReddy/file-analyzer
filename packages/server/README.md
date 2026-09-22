# file-analyzer-server

The database-**hosting** server for the **file-analyzer** platform.

Install this on the machine that should host analysis databases and serve them to
clients. It stands up a real, detachable, multi-instance server that:

- resolves (or reuses) a **session token** per repository and stores every
  database under `PROJECT_ROOT-{token}-{db_name}` in SQLite or Postgres/MySQL,
- coordinates parallel instances through a shared session catalog (token reuse, no
  duplicate copies),
- runs periodic **chunked rotating backups**,
- serves a **token-authenticated HTTP control plane** that
  [`file-analyzer-client`](https://pypi.org/project/file-analyzer-client/)'s
  `ServerClient` connects to.

```python
from file_analyzer.server import FileAnalyzerServer

srv = FileAnalyzerServer("/repo", backend="sqlite")
info = srv.start(detach=True)          # background; returns {url, token, pid}
srv.host_database("repository.db", "repository")
client = srv.connect()                 # a ServerClient bound to url + token
print(client.query(srv.storage_key_for("repository"),
                   "SELECT * FROM v_file_inventory"))
srv.stop()
```

Or from the command line:

```bash
file-analyzer-server run /path/to/repo --backend sqlite
```

## Dependencies

- Requires `file-analyzer-client` (pure stdlib foundation + `ServerClient`).
- SQLite hosting needs nothing extra. For remote backends install an extra:
  `pip install "file-analyzer-server[postgres]"` or `[mysql]`.

## Related wheels

| Wheel                    | Install where            | Contains                                   |
| ------------------------ | ------------------------ | ------------------------------------------ |
| `file-analyzer-client`   | anywhere                 | client + read-only DB access (stdlib only) |
| `file-analyzer-server`   | the hosting server       | the database-hosting server (this wheel)   |
| `file-analyzer-engine`   | wherever analysis runs   | the analyzer fleet that builds databases   |
