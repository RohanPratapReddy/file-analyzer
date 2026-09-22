# Background monitor — `python -m file_analyzer monitor`

Beyond the one-shot pipeline, `file-analyzer` ships a **long-running background
monitor** that watches a repository, records recent changes, and re-analyzes
changed files incrementally as agents / users / tools touch them.

```bash
python -m file_analyzer monitor <repo> [flags]        # module form (from the repo root)
file-analyzer-monitor <repo> [flags]         # after `pip install .`
python -m file_analyzer <repo>                          # 'monitor' is the default subcommand
```

> **⚠️ Container / VM only.** Like the main CLI, the monitor **refuses to run on
> bare-metal host hardware** (exit code `3`) — it starts only inside a container or
> a VM. `--help` is exempt. Override on an already-isolated box with
> `FILE_ANALYZER_ALLOW_BARE_METAL=1`. See [runtime-containment.md](runtime-containment.md).

## What it does

- Watches `<repo>` on a fixed cadence (`--interval`, default 2s).
- Keeps the last **16** changes in a **FIFO diff database** (`--capacity`), and —
  unless disabled — a **durable append-only change log** that never deletes evicted
  events (the superset of the FIFO ring).
- **Re-analyzes** each changed file: inline when few files changed, or fanned out
  across a **Go / Python worker pool** for larger change sets
  (`--inline-threshold`, `--min-workers`, `--max-workers`, `--no-go`).
- Optionally runs the **soft MCP agent tier** on every re-analyzed file (off by
  default; a no-op unless an MCP provider is actually reachable).
- Installs SIGINT/SIGTERM handlers and a PID file, and shuts down cleanly (no
  orphaned threads or child processes).

State (diff DB, durable log, per-file analysis) is written under
`<repo>/.file-analyzer` by default, or `--out`.

## Flags

### Cadence & buffer

| flag | default | meaning |
|------|---------|---------|
| `--interval SECONDS` | `2.0` | seconds between scan cycles |
| `--capacity N` | `16` | FIFO depth — consecutive changes retained in the diff DB |
| `--once` | off | run a single scan cycle, print a JSON summary, and exit |
| `--no-reanalyze` | off | only record changes; do not re-run analyzers |
| `--no-offline` | off | do not record changes that happened while the monitor was down |

### Output & PID

| flag | default | meaning |
|------|---------|---------|
| `--out PATH` | `<repo>/.file-analyzer` | artifact directory |
| `--diff-db PATH` | under `--out` | FIFO diff database path |
| `--pid-file PATH` | — | PID file path |

### Durable change log

The durable log is **on by default** and writes a local SQLite file under
`<out>/monitor/`. Point it at a remote SQL server with a connection URL.

| flag | default | meaning |
|------|---------|---------|
| `--change-log` / `--no-change-log` | on | enable/disable the durable append-only change log (FIFO-ring-only with `--no-change-log`) |
| `--change-log-url URL` | — | remote store: `postgresql://…` / `mysql://…`, or a SQLite path |
| `--change-log-path PATH` | local SQLite | local SQLite path (ignored if a URL is given) |

Remote backends need an optional driver: `pip install ".[monitor-postgres]"` or
`".[monitor-mysql]"`. Both are imported lazily, so the core stays stdlib-only
without them.

### Worker pool

| flag | default | meaning |
|------|---------|---------|
| `--inline-threshold N` | `8` | re-analyze inline when ≤ N files changed, else fan out |
| `--min-workers N` | `16` | worker-pool floor for large change sets |
| `--max-workers N` | `128` | worker-pool ceiling for large change sets |
| `--no-go` | off | skip the Go worker pool and use the Python fallback |

### Agent tier (soft MCP enrichment)

Off by default. When enabled, each re-analyzed file is additionally handed to the
same soft MCP agent layer a full run uses (summary, quality / security findings,
symbol docs). Strictly additive and soft: no reachable provider → no-op, and the
deterministic re-analysis is untouched.

| flag | default | meaning |
|------|---------|---------|
| `--agents` / `--no-agents` | off | enable/disable the soft MCP agent tier on re-analyzed files |
| `--agents-include NAMES` | — | comma/space-separated allow-list of provider names (case-insensitive) |
| `--agents-exclude NAMES` | — | comma/space-separated deny-list (applied after include) |
| `--discover-agents` / `--no-discover-agents` | on | resolve providers from the desktop/CLI-configured MCP servers |
| `--agent-roster NAME` | — | preferred provider name (else the first available) |
| `--max-agent-files N` | `40` | cap on files handed to the agent tier per re-analysis |

## Examples

```bash
python -m file_analyzer monitor .                          # watch the cwd, 2s cadence
python -m file_analyzer monitor /repo --interval 1         # faster cadence
python -m file_analyzer monitor /repo --once               # one scan cycle, then exit (JSON)
python -m file_analyzer monitor /repo --max-workers 200 --min-workers 20
python -m file_analyzer monitor /repo --no-go              # force the Python fallback pool
python -m file_analyzer monitor /repo --no-change-log      # FIFO ring only (no durable log)
python -m file_analyzer monitor /repo --agents             # enrich each change via MCP agents
python -m file_analyzer monitor /repo --agents --agents-include claude,gpt --agent-roster claude
```

## In Docker (compose `monitor` profile)

The always-on monitor has its own compose service (Dockerfile `monitor` stage).
Running it in a container also satisfies the containment guard automatically:

```bash
# watch ./workspace, artifacts + state under ./artifacts
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  docker compose --profile monitor up --build monitor

# tune via MONITOR_ARGS (shell-split, replaces the default command):
MONITOR_ARGS="/workspace --out /artifacts --interval 1 --max-workers 200 --min-workers 20" \
  docker compose --profile monitor up --build monitor
```

The service runs `init: true` (tini as PID 1, reaps orphans) with a
`stop_grace_period` that lets the SIGTERM handler drain workers before SIGKILL.

## Over MCP

The MCP server exposes the monitor as tools — `start_monitor`, `stop_monitor`,
`monitor_status` — with the same knobs, including `change_log`, `enable_agents`,
`agents_include` / `agents_exclude`, `discover_agents`, and `agent_roster`. See
[USAGE.md — Part 4](USAGE.md#part-4--ai-agents-mcp) for the MCP server setup.

## Related

- [`runtime-containment.md`](runtime-containment.md) — the container/VM guard the
  monitor enforces.
- [`USAGE.md`](USAGE.md) — the one-shot pipeline CLI.
- [`../README.md`](../README.md) — project overview and Docker workflow.
