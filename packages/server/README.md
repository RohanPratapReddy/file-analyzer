# file-analyzer-server

The database-**hosting** server for the **file-analyzer** platform.

Install this on the machine that should host analysis databases and serve them to
clients. It stands up a real, detachable, multi-instance server that:

- resolves (or reuses) a **session token** per repository and stores every
  database under `PROJECT_ROOT-{token}-{db_name}` in SQLite or Postgres/MySQL,
- coordinates parallel instances through a shared session catalog (token reuse, no
  duplicate copies),
- runs periodic **rotating backups**. These are plain chunked parts by default, or **Reed-Solomon erasure-coded shards** spread across several directories, with scheduled scrubbing and repair,
- enforces **time- and space-based retention**,
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

## Retention: keeping disk usage bounded

A retention pass runs periodically (`--retention-interval`) and can also be run on demand. It enforces three limits:

- **Idle databases.** A database that hasn't been re-hosted or read for `--retention-days` days (default 30) is removed, together with its backups.
- **Old backups.** Backup sets older than `--backup-retention-days` days (default 7) are pruned. Each database always keeps its newest set.
- **Space budget.** `--max-total-size` (for example `20G`) is a size budget covering hosted databases and their backups. To get back under it, old backups are removed first, then the least-recently-used databases.

```bash
file-analyzer-server retention /path/to/repo --max-total-size 20G --dry-run
```

## Reed-Solomon erasure-coded, sharded backups

By default each backup set is a list of gzip parts (`"format": "chunked"`). These parts give no protection if one of them is lost or damaged. Pass `--rs-data-shards K` to switch to erasure-coded backups (`"format": "reed-solomon"`):

- **Encoding.** The gzipped snapshot is cut into stripes of `K` blocks each. Every stripe gets `M` parity blocks (`--rs-parity-shards`, default 2).
  - The code is a systematic Reed-Solomon code over GF(2^8), built on a Cauchy matrix, so it is MDS.
  - Any `K` of the `K+M` shards rebuild the backup.
  - Storage overhead is `(K+M)/K`.
- **Checksums.** Each block of each shard has its own SHA-256 checksum. Damage is therefore tolerated per stripe: up to `M` bad blocks in every stripe, even when more than `M` shards are affected in total. The whole payload and the raw database also have their own checksums.
- **Placement.** Shards are spread round-robin across `--shard-dir` directories (repeat the flag, ideally once per physical disk or mount). The layout is `<shard-dir>/fa-<namespace>/<key>/<timestamp>/shard-NNN.rs`.
  - Every shard directory holds a copy of the manifest, so the set can still be found if the primary backup directory is lost.
  - The status output reports how many whole directories can be lost, based on the current layout.
  - Without `--shard-dir`, all shards stay in the backup directory, which protects against bit rot but not against losing that disk.
- **Scrubbing.** A background scrub runs every `--scrub-interval` seconds (default 86400). It verifies every block and repairs damaged or missing shards in place. If a shard's directory is gone, the rebuilt shard goes to the least-loaded surviving directory and every manifest copy is updated.
- **Atomic writes.** Shards are written to temp files, fsynced, then renamed into place. The primary manifest is written last and marks the set as complete. Restore rebuilds the file into a temp file and checks the SHA-256 before moving it into place.

```bash
file-analyzer-server start /repo --detach \
    --rs-data-shards 4 --rs-parity-shards 2 --rs-block-size 1M \
    --shard-dir /mnt/disk1/fa --shard-dir /mnt/disk2/fa --shard-dir /mnt/disk3/fa

file-analyzer-server backup-verify  /repo <same flags>   # exit 1 if not all healthy
file-analyzer-server backup-repair  /repo <same flags>   # rebuild damaged/missing shards
file-analyzer-server restore        /repo <same flags> --storage-key KEY --dest out.db
```

The same operations are available in Python:

- **SDK:** `FileAnalyzerServer.backup_status()`, `verify_backups()`, `repair_backups()` and `restore()`.
- **HTTP:** `GET /backups/status`, `POST /backups/verify` and `POST /backups/repair`. The POST routes take an optional body `{storage_key, timestamp}`.
- **Client:** `ServerClient.backup_status()`, `verify_backups()` and `repair_backups()`.

## Autopilot: self-healing maintenance

A serving server runs an **autopilot** tick every `--autopilot-interval` seconds (default 300; `0` disables it). The first tick runs after `--autopilot-startup-delay`. Each task runs on its own schedule. Ticks hold a shared lock, so parallel servers on the same repository never run maintenance at the same time. State (per-database health, lineage, pending work, events) lives in `autopilot.json` and survives restarts. A torn state file is reset, and the reset is logged as an event.

| Task | What it does |
|---|---|
| `catalog` | Checks the session catalog and snapshots it regularly. If the catalog is damaged or deleted, it is rebuilt from the newest good snapshot, or recreated empty if no snapshot exists; the damaged copy is quarantined. |
| `check` | For every hosted database: checks the SQLite header (magic, page size, page count vs. file size), compares the SHA-256 with the catalog and runs `quick_check`. A full `integrity_check` runs every `--deep-check-interval`. Remote (Postgres/MySQL) records are checked chunk by chunk. Each database is marked healthy, missing, corrupt or drifted. |
| `heal` | Restores **missing/corrupt** databases from the newest backup that passes verification. Backups that fail verification are skipped. The damaged copy is quarantined with a `reason.json`, and while a key is damaged it can never be backed up over its good sets. If no backup of the exact content exists, it rolls back to an older backup (disable with `--no-rollback`). A **drifted** database (sound, but its checksum changed) is restored, adopted or only reported, per `--drift-action`. A database lost with no backup at all is removed from the catalog after a grace period. |
| `scrub` | Verifies every backup set and repairs Reed-Solomon shards. A set that cannot be recovered is dropped after a grace period, and the database is backed up again. |
| `backup` | Backs up any database that has no backups, no backup of its current content, a stale backup, or a pending request (disable with `--no-auto-backup`). |
| `retention` | Runs the time- and space-based retention pass. |
| `sweep` | Removes old debris: interrupted restores and backups, temp files, partial catalog snapshots, endpoint/PID files of dead servers, old logs and expired quarantine. Orphaned database files are re-registered in the catalog if sound, or quarantined if damaged; files that don't belong to this session are left alone. |

**Concurrent workers (Go pool).** The expensive per-database work runs on a worker pool, with one job per storage key, so jobs never compete for a lock. That work is hashing plus `quick_check`/`integrity_check`, verifying and repairing backup sets, and restoring plus verifying heal candidates.
- `check` first runs a cheap pass in-process: stat and header, or chunk accounting for remote backends. Only the databases that pass leaves undecided go to the pool.
- `heal` takes the key lock of every damaged database. It then deep re-checks them all concurrently and restores each one's backup candidates into its own staging file concurrently. The installs (quarantine, re-host, lineage) run one at a time because they write to the catalog.
- `scrub`, `backup-verify` and `backup-repair` verify each key's sets concurrently.

When the Go toolchain is on `PATH`, the pool is the server's Go binary (`go/backup.go`, run with `-module file_analyzer.server.autopilot_worker`). A fixed set of goroutines runs one `python -m file_analyzer.server.autopilot_worker --kind inspect|verify|stage` subprocess per batch. A worker that crashes on a badly damaged file only takes down its own process.

Without Go, the same jobs run on an in-process thread pool (`hashlib` and `sqlite3` release the GIL). A single job runs inline.

A job the pool could not run never escalates a heal to adopt or drop; it is reported as `failed` and retried on the next tick.

Tuning flags:
- `--autopilot-workers N` sets the number of workers. The default is sized to the work, from 4 to 32; `1` runs everything inline.
- `--no-go-workers` forces the thread pool.

Reports include the engine used: `check.engine`, `heal.engines`, `scrub.engine`, and `last_pool` in `autopilot_status()`.

```bash
file-analyzer-server check     /repo                    # exit 1 if anything is unhealthy
file-analyzer-server check     /repo --autopilot-workers 8 --no-go-workers
file-analyzer-server maintain  /repo --dry-run          # show what would be healed/removed
file-analyzer-server maintain  /repo --task check --task heal
file-analyzer-server autopilot /repo                    # policy, schedule, health, events
file-analyzer-server start     /repo --detach --drift-action adopt --check-interval 600
```

**SDK:**
- `FileAnalyzerServer.check()` checks everything and repairs nothing.
- `heal(dry_run=False)` runs the catalog, scrub, check, heal and backup tasks.
- `maintain(tasks=...)` runs a full tick, or only the named tasks.
- `autopilot_status()` returns the autopilot's policy, schedule, per-database health and recent events.
- `health_report()` returns autopilot, backup, retention and supervisor state in one call.
- `start_autopilot()` / `stop_autopilot()` run the loop in an embedded process.

**HTTP:** `GET /autopilot`, `POST /autopilot/run` (body: `{dry_run, tasks, force}`; an unknown task gets a 400), and a summary in `GET /health`.

**Client:** `ServerClient.check()`, `run_autopilot()` and `autopilot_status()`.

**Process supervision.** `FileAnalyzerServer.start(detach=True, supervise=True)` (or `supervise()`) starts a `ServerSupervisor` watchdog in the calling process:
- It polls the detached server's PID and `/health`, and reaps zombies.
- After `failure_threshold` failed checks in a row (the process died, or it stopped answering, for example because it was frozen), it stops the old process, escalating to SIGKILL if needed.
- It restarts the server with the same session token, with exponential backoff.
- It gives up after `max_restarts` restarts within `restart_window`.
- `stop()` stops the watchdog first, so an intentional shutdown is never "healed".

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
