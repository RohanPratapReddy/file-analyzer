# The database-hosting server (`file-analyzer-server`)

`file-analyzer-server` hosts the databases the analysis engine produces and serves
them to clients. It is a separate wheel (`pip install file-analyzer-server`, or
`pip install "file-analyzer[server]"`) that installs the
`file_analyzer.server` package and the `file-analyzer-server` command. It depends
only on `file-analyzer-client`. Everything it needs for SQLite hosting is
standard library.

What one server gives you:

| Area | What it does |
|---|---|
| Sessions | One **session token** per repository, shared by every server on that repository through a lock-protected catalog. Databases are stored as `PROJECT_ROOT-{token}-{db_name}`, and there are never duplicate copies. |
| Storage | Live SQLite files (default), or a chunked content store on Postgres or MySQL (`--backend postgresql://...` / `mysql://...`). |
| Lifecycle | Foreground `run`, or `start --detach` (a background process with a PID file that outlives the shell), `stop`, and `status`. |
| Control plane | A token-authenticated HTTP JSON API, used by [`ServerClient`](#python-client-serverclient). |
| Backups | Periodic rotating backups. They are plain gzip parts, or **Reed-Solomon erasure-coded shards** spread across several disks with a scheduled scrub and repair. |
| Retention | Time- and space-based limits, so disk usage stays bounded. |
| Autopilot | Self-healing maintenance: catalog repair, health checks, restoring from verified backups, backup scrub, automatic backups, retention and a debris sweep. |
| Concurrency | The expensive per-database work runs on a **Go worker pool** (one Go driver binary, with Python worker processes), with a thread-pool fallback. |
| Supervision | An optional watchdog that restarts a detached server if it dies or hangs. |

> **Acceptable use.** The server hosts databases the engine built. Those
> databases hold metadata and statistics, never raw file payloads (see
> [`../ACCEPTABLE_USE.md`](../ACCEPTABLE_USE.md)). Host only repositories you are
> authorized to analyze.

> **Containment.** `run` / `start` enforce the same guard as the engine: they
> serve only inside a container or VM (exit code `3` on bare metal). Pass
> `--no-contain` (or `serve(contained=False)`) only when the caller provides its
> own isolation. Admin subcommands (`status`, `check`, `backup-verify`, ...) don't
> serve anything and are not gated. See [runtime-containment.md](runtime-containment.md).

---

## Quick start

```bash
pip install file-analyzer-server

# foreground (Ctrl-C / SIGTERM stops it cleanly)
file-analyzer-server run /path/to/repo --port 8765

# or detached: prints {server_id, pid, url, token, ...} and returns
file-analyzer-server start /path/to/repo --detach

file-analyzer-server host   /path/to/repo --db-name repository --source ./artifacts/repository.db
file-analyzer-server status /path/to/repo      # servers, databases, token, backups, autopilot
file-analyzer-server stop   /path/to/repo --all
```

The same thing from Python:

```python
from file_analyzer.server import FileAnalyzerServer

srv = FileAnalyzerServer("/repo", backend="sqlite")
info = srv.start(detach=True)            # {server_id, pid, url, token, ...}
srv.host_database("artifacts/repository.db", "repository")
client = srv.connect()                   # ServerClient bound to url + token
print(client.query(srv.storage_key_for("repository"), "SELECT * FROM v_file_inventory"))
srv.stop()
```

`python -m file_analyzer.server ...` is the same as the `file-analyzer-server`
command. With no subcommand, `file-analyzer-server /repo` means `start /repo`.

---

## Where things live

Everything is under `FILE_ANALYZER_SERVER_HOME` (default `~/.file-analyzer`).
`--catalog-dir` moves the catalog and per-repository directories.
`--catalog-target` puts the catalog itself on a remote SQL server, so servers on
several hosts can coordinate.

```
$FILE_ANALYZER_SERVER_HOME/servers/          <- the catalog dir
  catalog.db  catalog.lock                   session / database / server registry
  snapshots/                                 rolling online backups of the catalog (autopilot)
  <fingerprint>/                             one per repository (sha256 of its path)
    data/        hosted SQLite databases     PROJECT_ROOT-{token}-{db}.db
    backups/     backup sets + manifests     (RS manifests are also copied to every shard dir)
    quarantine/  damaged copies moved aside by a heal, each with reason.json
    run/         autopilot.json (state), endpoint-*.json, server-*.pid, logs
<shard-dir>/fa-<namespace>/<key>/<timestamp>/shard-NNN.rs   <- Reed-Solomon shards
```

---

## Backups

A serving server backs up every hosted database every `--backup-interval`
seconds (default 900; `0` disables periodic backups). Each database keeps its
newest `--backup-keep` sets (default 5). A backup is a consistent SQLite online
backup (`sqlite3.backup`), gzipped. Remote-backend databases are exported from
their chunk store.

### Plain chunked sets (default)

With `"format": "chunked"`, each set is a list of gzip parts plus a manifest
that records SHA-256 checksums. Verification detects damage, but it can't be
repaired: the autopilot falls back to an older set.

### Reed-Solomon erasure-coded, sharded sets

`--rs-data-shards K` switches the server to `"format": "reed-solomon"`:

- **Code.** A systematic Reed-Solomon code over GF(2^8), built on a Cauchy
  matrix, so it is MDS. It is pure Python (`erasure.py`) with no third-party
  codec.
  - The gzipped snapshot is cut into stripes of `K` data blocks, each at most
    `--rs-block-size` (default `1M`).
  - Every stripe gets `M = --rs-parity-shards` parity blocks (default 2).
  - **Any `K` of the `K + M` shards rebuild the backup.** Storage overhead is
    `(K + M) / K`.
- **Checksums at three levels.** Each block of each shard has its own SHA-256,
  and so do the whole payload and the raw database. Because damage is judged
  stripe by stripe, a set survives up to `M` bad blocks *in every stripe*, even
  when more than `M` shards are damaged in total.
- **Placement.** Shards go round-robin across the `--shard-dir` directories
  (repeat the flag, one per physical disk or mount).
  - Every shard directory also holds a copy of the manifest, so a set can still
    be found and restored after the primary backup directory is lost.
  - `backup_status()` reports, for the current layout, how many whole
    directories can be lost.
  - Without `--shard-dir`, all shards stay in the backup directory. That
    protects against bit rot but not against losing that disk.
- **Atomic writes.** Shards are written to temp files, fsynced, then renamed
  into place. The primary manifest is written last and marks the set as
  complete. A restore rebuilds the file into a temp file and checks its
  SHA-256 before moving it into place.
- **Scrub.** A background scrub runs every `--scrub-interval` seconds (default
  86400).
  - It verifies every block of every set and rewrites damaged or missing shards
    in place.
  - If a shard's whole directory is gone, the rebuilt shard goes to the
    least-loaded surviving directory, and every manifest copy is updated.
  - When the autopilot is on, it runs the scrub as one of its tasks.

Layout example: with `K=4, M=2` and three shard directories, each directory holds
two of the six shards, so **any one directory** can be lost:

```bash
file-analyzer-server start /repo --detach \
    --rs-data-shards 4 --rs-parity-shards 2 --rs-block-size 1M \
    --shard-dir /mnt/disk1/fa --shard-dir /mnt/disk2/fa --shard-dir /mnt/disk3/fa
```

### Backup operations

Pass the same `--rs-*` / `--shard-dir` flags the server runs with:

```bash
file-analyzer-server backup        /repo [--storage-key K]             # back up now
file-analyzer-server backup-verify /repo [--storage-key K] [--timestamp T]
file-analyzer-server backup-repair /repo [--storage-key K] [--timestamp T]
file-analyzer-server restore       /repo --storage-key K [--timestamp T] --dest out.db
```

- **`backup-verify`** is read-only. Each set comes back `healthy`, `degraded`
  (damaged but recoverable), `unrecoverable`, `incomplete` or `error`. The exit
  code is `1` unless every set is `healthy`.
- **`backup-repair`** rebuilds the damaged or missing shards. Its exit code is
  `1` only for sets that can't be recovered.
- Both verify each key's sets concurrently on the
  [worker pool](#concurrency-the-go-worker-pool).

---

## Retention

A retention pass runs every `--retention-interval` seconds (default 3600) and can
also be run on demand. It enforces three independent limits; `0` disables any of
them:

| Flag | Default | Effect |
|---|---|---|
| `--retention-days` | 30 | A hosted database that hasn't been re-hosted or read for this many days is evicted, together with its backups. |
| `--backup-retention-days` | 7 | Backup sets older than this are pruned. Every database always keeps its newest set. |
| `--max-total-size` | off | A size budget (for example `20G` or `512MB`) covering hosted databases and their backups. Old backups go first, then the least-recently-used databases, until usage is under the budget. |

```bash
file-analyzer-server retention /repo --max-total-size 20G --dry-run   # preview
file-analyzer-server retention /repo --max-total-size 20G             # enforce
```

---

## Autopilot: self-healing maintenance

A serving server runs an **autopilot tick** every `--autopilot-interval`
seconds.

- **Schedule.** The default interval is 300; `0` disables the autopilot, and
  retention and scrub then run on their own timers. The first tick comes after
  `--autopilot-startup-delay` (default 30).
- **Per-task timing.** Each task inside a tick keeps its own schedule.
- **One tick at a time.** Ticks take a shared lock, so parallel servers on one
  repository never run maintenance at the same time.
- **Persistent state.** Per-database health, content lineage, pending work and
  recent events are kept in `run/autopilot.json` and survive restarts. A torn
  state file is reset, and the reset is logged as an event.

| Task | What it does |
|---|---|
| `catalog` | Checks the session catalog and keeps rolling snapshots of it. A damaged or deleted catalog is rebuilt from the newest good snapshot (or recreated empty), and the damaged copy is quarantined. |
| `check` | Checks every hosted database. SQLite: the header (magic, page size, page count vs. file size), the SHA-256 vs. the catalog, and `quick_check`; a full `integrity_check` every `--deep-check-interval` (default 86400). Remote: chunk-by-chunk accounting. Each database is marked **healthy / missing / corrupt / drifted**. |
| `heal` | Restores **missing/corrupt** databases from the newest backup that passes verification (see below). |
| `scrub` | Verifies every backup set and repairs Reed-Solomon shards. A set that can't be recovered is dropped after a grace period, and the database is backed up again. |
| `backup` | Backs up any database with no backups, no backup of its current content, a stale newest backup (older than twice `--backup-interval`) or a pending request. Disable with `--no-auto-backup`. |
| `retention` | Runs the retention pass above. |
| `sweep` | Removes debris: interrupted restores and backups, temp files, partial catalog snapshots, endpoint/PID files of dead servers, old logs and expired quarantine. Orphaned database files are re-registered if sound or quarantined if damaged; files that aren't this session's are left alone. |

**How `heal` works:**

- **Restore.** It skips backups that fail verification and quarantines the
  damaged copy with a `reason.json`. While a key is damaged, it is never backed
  up over its good sets.
- **Rollback.** If no backup of the exact current content exists, it rolls back
  to an older backup. `--no-rollback` turns this off.
- **Drift.** A drifted database (sound, but its checksum changed) is restored,
  adopted or only reported, per `--drift-action` (`restore` by default).
- **Lost databases.** A database lost with no backup at all is removed from the
  catalog after a grace period.
- **Detect only.** `--no-auto-heal` detects and reports damage but changes
  nothing.

```bash
file-analyzer-server check     /repo                        # exit 1 if anything is unhealthy
file-analyzer-server maintain  /repo --dry-run              # what would be healed/removed
file-analyzer-server maintain  /repo --task check --task heal
file-analyzer-server autopilot /repo                        # policy, schedule, health, events
file-analyzer-server start     /repo --detach --drift-action adopt --check-interval 600
```

`check` and `maintain` exit `1` if anything is unhealthy, or if a tick was
skipped because another process holds the maintenance lock.

### Concurrency: the Go worker pool

The expensive per-database work runs on a worker pool, with **one job per
storage key**, so jobs never compete for a lock. That work is hashing plus
`quick_check`/`integrity_check`, verifying and repairing backup sets, and
restoring plus verifying heal candidates.

- **`check`** first runs a cheap pass in-process: stat and header, or chunk
  accounting for remote backends. Only the databases that pass leaves undecided
  go to the pool (`inspect` jobs).
- **`heal`** takes the key lock of every damaged database (sorted order; a busy
  key is skipped this tick). It then:
  1. deep re-checks them all concurrently, so a heal never acts on a stale
     verdict;
  2. restores and `integrity_check`s each database's backup candidates, each
     into its own staging file `.{key}.db.healing` (`stage` jobs);
  3. installs the staged copies one at a time (quarantine, re-host, lineage),
     because installs write to the catalog.
- **`scrub`**, **`backup-verify`** and **`backup-repair`** verify each key's sets
  concurrently (`verify` jobs).

**Engines.**

- **`go`.** When `go` is on `PATH`, the pool is the server's Go driver
  (`file_analyzer/server/go/backup.go`, built once on demand as `backup-pool`).
  - A fixed set of goroutines runs one
    `python -m file_analyzer.server.autopilot_worker --kind inspect|verify|stage`
    subprocess per batch.
  - A worker that crashes on a badly damaged file only takes down its own
    process.
  - The same binary also drives the periodic backup workers
    (`-module file_analyzer.server.backup_worker`).
- **`python`.** Without Go, the same jobs run on an in-process thread pool.
  `hashlib` and `sqlite3` release the GIL, so this is real parallelism for the
  heavy parts.
- **`inline`.** A single job, or `--autopilot-workers 1`, runs in-process.

A job the pool couldn't run never escalates a heal to adopt or drop. It is
reported as `failed` and retried on the next tick.

**Tuning.**

- `--autopilot-workers N` sets the number of workers. The default is sized to
  the work, from 4 to 32; `1` runs everything inline.
- `--no-go-workers` forces the Python pool.
- Both apply to `run`, `start`, `check` and `maintain`. A detached `start`
  forwards them to the background process.

Reports record which engine ran: `check.engine`, `heal.engines`
(`{check, stage}`), `scrub.engine`, and `last_pool` in `autopilot_status()`.

### Process supervision

`FileAnalyzerServer.start(detach=True, supervise=True)`, or `supervise()` on an
already detached server, starts a `ServerSupervisor` watchdog in the calling
process:

- It polls the server's PID and `/health` every `interval` seconds (default 5)
  and reaps zombies.
- After `failure_threshold` failed checks in a row (default 3), it stops the old
  process, escalating to SIGKILL if needed. A failed check means the process
  died, or it stopped answering, for example because it was frozen.
- It restarts the server **with the same session token**. Backoff grows
  exponentially from `backoff` (default 1 s) up to `max_backoff` (default 60 s).
- It gives up after `max_restarts` restarts (default 5) within `restart_window`
  seconds (default 3600).
- `stop()` stops the watchdog first, so an intentional shutdown is never
  "healed".
- `supervisor_status()` reports its state, and `unsupervise()` detaches it.

In Docker, the container's restart policy plays the same role (see below).

---

## HTTP control plane

Every route except `GET /health` requires `Authorization: Bearer <session token>`,
and the token is compared in constant time. Every response is JSON. The
transport is plain HTTP, so bind to `127.0.0.1` (the default `--host`) or put
TLS in front of it.

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | Liveness, with an autopilot summary. It doesn't depend on the catalog, so a damaged catalog is never a restart reason. |
| GET | `/session` | Token, project root, fingerprint, backend. |
| GET | `/databases` | Hosted databases. |
| GET | `/databases/{key}/download` | Download one SQLite database. |
| GET | `/servers` | Servers running for this repository. |
| GET | `/backups?storage_key=K` | Backup sets. |
| GET | `/backups/status` | Backup health and layout, including how many shard directories can be lost. |
| GET | `/retention` | Retention policy and usage. |
| GET | `/autopilot` | Policy, schedule, per-database health, `last_pool`, recent events. |
| GET | `/pglogs` | Backend Postgres logs. |
| POST | `/databases` | Host a database from a server-side path. |
| POST | `/databases/upload` | Host an uploaded database file. |
| POST | `/query` | Run a read-only `SELECT`/`WITH` against a hosted database. |
| POST | `/backup` | Back up now. |
| POST | `/backups/verify`, `/backups/repair` | Body `{storage_key?, timestamp?}`. |
| POST | `/retention` | Body `{dry_run?}`. |
| POST | `/autopilot/run` | Body `{dry_run?, tasks?, force?}`. An unknown task gets a 400. |

---

## Python API

### `FileAnalyzerServer` (server wheel)

`FileAnalyzerServer(path=".", **kwargs)` takes every `DatabaseServer` keyword:

| Group | Keywords |
|---|---|
| Storage | `backend`, `catalog_dir`, `catalog_target`, `data_dir` |
| Serving | `host`, `port`, `token`, `server_id`, `chunk_bytes` |
| Backups | `backup_interval`, `backup_keep`, `backup_part_bytes` |
| Retention | `retention_interval`, `retention_max_age`, `backup_max_age`, `retention_max_bytes` (ages are in seconds, sizes in bytes) |
| Reed-Solomon | `rs_data_shards`, `rs_parity_shards`, `rs_block_bytes`, `shard_dirs`, `scrub_interval` |
| Autopilot | `autopilot_interval`, `autopilot_startup_delay`, `check_interval`, `deep_check_interval`, `auto_heal`, `allow_rollback`, `auto_backup`, `drift_action`, `autopilot_workers`, `autopilot_use_go`, `autopilot_policy` |

| Method | Purpose |
|---|---|
| `start(detach=True, contained=True, supervise=False, **supervisor_options)` / `serve()` / `stop(all_for_repo=False)` | Lifecycle. |
| `token`, `url`, `storage_key_for(db)`, `status()`, `servers()`, `is_running()`, `wait_ready()` | Identity and state. |
| `host_database(path, db)`, `databases()` | Hosting. |
| `backup(key=None)`, `backup_status()`, `verify_backups(key, ts)`, `repair_backups(key, ts)`, `restore(key, dest, ts)` | Backups. |
| `retention()`, `enforce_retention(dry_run=False)` | Retention. |
| `check()`, `heal(dry_run=False)`, `maintain(tasks=None, dry_run=False)`, `autopilot_status()`, `health_report()` | Autopilot. `heal` runs catalog, scrub, check, heal and backup. `health_report` returns autopilot, backup, retention and supervisor state in one call. |
| `start_autopilot()` / `stop_autopilot()` | Run the autopilot loop inside an embedding process. |
| `supervise(**options)` / `unsupervise()` / `supervisor_status()` | The watchdog. |
| `connect()` / `FileAnalyzerServer.client(url, token)` | A `ServerClient`. |

### Python client: `ServerClient`

`ServerClient` ships in the client wheel and is pure standard library:

```python
from file_analyzer.client import ServerClient

c = ServerClient("http://127.0.0.1:8765", token="...")
c.health(); c.session(); c.databases(); c.servers()
c.host_path("/srv/repository.db", "repository"); c.upload("local.db", "copy")
c.query(key, "SELECT * FROM v_symbols_by_kind", limit=50); c.download(key, "out.db")
c.backup(); c.backups(); c.backup_status(); c.verify_backups(); c.repair_backups()
c.retention(); c.enforce_retention(dry_run=True)
c.check(); c.run_autopilot(tasks=["check", "heal"]); c.autopilot_status()
```

---

## Running it in Docker

The `server` target of the root [`Dockerfile`](../Dockerfile) installs the
client and server wheels built from `packages/`. It also copies in the Go
toolchain, with the `backup-pool` driver **pre-built** so the Go pool is live
from the first tick, and it adds `tini`.

- **Process.** It runs as the unprivileged `fa` user (uid 10001), with
  `FILE_ANALYZER_SERVER_HOME=/data`.
- **Command.** It serves `file-analyzer-server run /workspace --host 0.0.0.0
  --port 8765`.
- **Health.** The image declares a `HEALTHCHECK` against `/health`.
- **Remote drivers.** Build with `--build-arg SERVER_EXTRAS=postgres` (or
  `mysql`) to add a remote-backend driver.

The compose `server` profile wires it up:

```bash
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  docker compose --profile server up -d --build server

docker compose exec server file-analyzer-server status /workspace     # includes the token
docker compose exec server file-analyzer-server host /workspace \
    --db-name repository --source /artifacts/repository.db
curl -s http://127.0.0.1:8765/health
```

- **Default arguments.** Reed-Solomon backups with `K=4, M=2` over three named
  shard volumes (`fa-shards-1..3`, mounted at `/shards/disk1..3`, so any one
  volume can be lost), plus 30-day / 7-day retention and a 20 GB budget.
- **Volumes.** Catalog, databases, backups, quarantine and autopilot state live
  in the `fa-server-data` volume, so the session token and hosted databases
  survive `docker compose down` and restarts. `down -v` deletes them. In
  production, put each shard volume on its own disk. For bind mounts, `chown
  10001` the host directories first.
- **Ports.** The port is published on `127.0.0.1` only. `SERVER_BIND=0.0.0.0`
  exposes it, and `SERVER_PORT` changes the host port.
- **Arguments.** `SERVER_ARGS` replaces the whole argument list, for example:

  ```bash
  SERVER_ARGS="run /workspace --host 0.0.0.0 --port 8765 --max-total-size 10G \
      --autopilot-workers 8" docker compose --profile server up -d server
  ```

- **Remote content store.** With the compose Postgres as the content store:

  ```bash
  SERVER_EXTRAS=postgres SERVER_ARGS="run /workspace --host 0.0.0.0 --port 8765 \
      --backend postgresql://sentinel:sentinel@postgres:5432/repository" \
    docker compose --profile server up -d --build postgres server
  ```

- **Operations.** Use `docker compose exec server file-analyzer-server <cmd>
  /workspace ...` for `backup-verify`, `backup-repair`, `restore`, `retention`,
  `check`, `maintain` and `autopilot`. Pass the same `--rs-*` and `--shard-dir`
  flags as the service.
- **Shutdown and restarts.** `docker stop` sends SIGTERM, and the server shuts
  down cleanly within the 60 s `stop_grace_period`. `init: true` plus the
  image's `tini` (with `TINI_SUBREAPER=1`) reap the pool's worker processes.
  `restart: unless-stopped` covers crashes; the in-process `ServerSupervisor` is
  for detached servers outside a container.

---

## CLI reference

```
file-analyzer-server {start,run,stop,status,host,databases,backup,retention,restore,
                      backup-verify,backup-repair,logs,check,maintain,autopilot} [root] ...
```

- **Every subcommand:** `--backend`, `--catalog-dir`, `--catalog-target`,
  `--rs-data-shards`, `--rs-parity-shards`, `--rs-block-size`, `--shard-dir`
  (repeatable).
- **Serving (`start`, `run`):**
  - Network and identity: `--host`, `--port`, `--token`, `--server-id`,
    `--chunk-bytes`.
  - Backups: `--backup-interval`, `--backup-keep`, `--scrub-interval`.
  - Retention: `--retention-interval`, `--retention-days`,
    `--backup-retention-days`, `--max-total-size`.
  - Autopilot schedule: `--autopilot-interval`, `--autopilot-startup-delay`,
    `--check-interval`, `--deep-check-interval`.
  - Autopilot behaviour: `--no-auto-heal`, `--no-rollback`, `--no-auto-backup`,
    `--drift-action`.
  - Workers: `--autopilot-workers`, `--no-go-workers`.
  - `--no-contain`; `start` also takes `--detach`.
- **`check`:** the autopilot flags (`--check-interval` to `--no-go-workers`).
- **`maintain`:** the autopilot flags plus the retention limits,
  `--backup-interval`, `--task` (repeatable; `catalog`, `check`, `heal`,
  `scrub`, `backup`, `retention`, `sweep`) and `--dry-run`.
- **`retention`:** the retention limits plus `--dry-run`.
- **`--version`** prints the platform version.

All commands print JSON to stdout.
