# syntax=docker/dockerfile:1
# =============================================================================
# file-analyzer images (one multi-stage Dockerfile, one target per service)
# =============================================================================
#   loader   pgloader/psql job: ingests AnalysisEngine artifacts into Postgres
#   reader   static Go VIEW reader over a mounted .db / .sql artifact
#   engine   `python -m file_analyzer.main` -- produces the artifacts
#   monitor  `python -m file_analyzer monitor` -- background re-analysis daemon
#   mcp      `python -m mcp_server` -- the MCP server for AI agents (stdio)
#   server   `file-analyzer-server` -- the database-hosting server (backups,
#            Reed-Solomon shards, retention, self-healing autopilot)
# Build one with `docker build --target <name> .`, or through the compose
# profiles in docker-compose.yml. The Python stages install the wheels built
# from packages/ (the same three wheels published to PyPI), never a source
# checkout on PYTHONPATH.
#
# Build args:
#   GO_VERSION      Go toolchain for the reader + every Go worker pool (1.26)
#   PYTHON_VERSION  Python for the engine/monitor/mcp/server images (3.12)
#   SERVER_EXTRAS   server-only: "postgres" / "mysql" installs a remote driver
ARG GO_VERSION=1.26
ARG PYTHON_VERSION=3.12

# =============================================================================
# loader -- artifact loader image
# =============================================================================
# AnalysisEngine emits SQLite artifacts:
#     repository.db            SQLite binary database  (the reliable artifact)
#     repository_schema.sql    SQL dump (sqlite dialect by default; postgresql
#                              dialect if run with sql_dialect="postgresql")
#     <archive>.db / ...       nested per-archive sub-databases beside the main db
#
# This image ingests those artifacts into the Postgres backend:
#     *.db   -> pgloader   (type-safe SQLite -> Postgres conversion:
#                           creates tables + indexes, resets sequences)
#     *.sql  -> psql       (best effort; only a POSTGRESQL-dialect dump loads
#                           cleanly -- a sqlite-dialect dump errors on PRAGMA)
#
# Each artifact lands in its OWN Postgres database (named after the file stem)
# so the main repository db and the nested per-archive sub-databases never
# collide on table names. The image is self-contained: it installs pgloader +
# the psql client and carries its own load script (no build context needed).
# =============================================================================

FROM debian:bookworm-slim AS loader

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pgloader \
        postgresql-client \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /loader

# --- inlined load script (keeps the build context empty; see .dockerignore) ---
COPY <<'EOF' /loader/load.sh
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob globstar

ARTIFACTS_DIR="${ARTIFACTS_DIR:-/artifacts}"
PGHOST="${PGHOST:-postgres}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-sentinel}"
export PGPASSWORD="${PGPASSWORD:-sentinel}"
# Postgres CREATE-VIEW DDL for the analysis views (file_analyzer/views/catalog.py), emitted
# by `python -m file_analyzer.views artifacts` and bind-mounted in by compose. pgloader
# copies TABLES only, so we (re)create the views on the Postgres side after each
# .db load. It carries ALL views; those whose base tables are absent in a given
# database simply fail and are skipped (ON_ERROR_STOP is off for this step).
VIEWS_SQL="${VIEWS_SQL:-/loader/views.pgsql.sql}"

echo "[loader] waiting for postgres at ${PGHOST}:${PGPORT} ..."
until pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" >/dev/null 2>&1; do
  sleep 2
done
echo "[loader] postgres is ready."

# lowercase, non-alnum -> '_', ensure it does not start with a digit
sanitize() {
  local n
  n="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_]/_/g')"
  case "$n" in [a-z_]*) : ;; *) n="db_${n}" ;; esac
  printf '%s' "$n"
}

createdb_if_absent() {
  local db="$1"
  if ! psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAc \
        "SELECT 1 FROM pg_database WHERE datname='${db}'" | grep -q 1; then
    echo "[loader] creating database ${db}"
    psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
         -c "CREATE DATABASE \"${db}\""
  fi
}

# (Re)create the analysis views in a loaded database. Runs WITHOUT ON_ERROR_STOP
# so views over base tables that this database lacks are skipped, not fatal --
# the same "present tables only" contract the SQLite/readers side enforces.
apply_views() {
  local db="$1"
  [ -f "$VIEWS_SQL" ] || return 0
  echo "[loader] applying analysis views -> ${db}"
  psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$db" -q -f "$VIEWS_SQL" \
    >/dev/null 2>&1 || true
}

found=0

# 1. SQLite .db artifacts -> pgloader (recursive, includes nested sub-DBs)
for f in "$ARTIFACTS_DIR"/**/*.db; do
  [ -f "$f" ] || continue
  found=1
  db="$(sanitize "$(basename "$f" .db)")"
  createdb_if_absent "$db"
  echo "[loader] pgloader ${f} -> ${db}"
  pgloader "$f" "postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${db}"
  apply_views "$db"
done

# 2. .sql dumps -> psql (only a postgresql-dialect dump loads cleanly)
for f in "$ARTIFACTS_DIR"/**/*.sql; do
  [ -f "$f" ] || continue
  found=1
  db="$(sanitize "$(basename "$f" .sql)")"
  createdb_if_absent "$db"
  echo "[loader] psql < ${f} -> ${db}"
  if psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$db" \
          -v ON_ERROR_STOP=1 -f "$f"; then
    # A postgresql-dialect dump already carries the appended views; re-applying
    # is idempotent (CREATE OR REPLACE VIEW) and covers older dumps.
    apply_views "$db"
  else
    echo "[loader] WARN: ${f} did not load cleanly."
    echo "[loader]       Re-run AnalysisEngine with sql_dialect=\"postgresql\""
    echo "[loader]       for a psql-loadable dump, or just use the .db artifact."
  fi
done

if [ "$found" -eq 0 ]; then
  echo "[loader] no *.db or *.sql artifacts found under ${ARTIFACTS_DIR}"
  echo "[loader] mount your AnalysisEngine output dir to /artifacts (see compose)."
fi
echo "[loader] done."
EOF

RUN chmod +x /loader/load.sh

ENTRYPOINT ["/loader/load.sh"]

# =============================================================================
# Shared build stages for everything below
# =============================================================================
# `go-toolchain` exists so the Python runtime stages can COPY the Go toolchain
# (COPY --from cannot expand a build ARG itself). GO_VERSION must satisfy the
# newest `go` directive among the shipped go.mod files (router/go needs 1.26).
FROM golang:${GO_VERSION}-bookworm AS go-toolchain

# `wheels`: build the three platform wheels exactly as CI does -- one
# `python -m build --wheel` per packages/<name>. They merge into one PEP 420
# `file_analyzer` namespace when installed side by side, so each runtime stage
# picks just the wheels it needs:
#     engine / monitor / mcp : file-analyzer-client + file-analyzer-engine
#     server                 : file-analyzer-client + file-analyzer-server
FROM python:${PYTHON_VERSION}-slim-bookworm AS wheels
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install "setuptools>=77" wheel build
WORKDIR /build
COPY packages/ ./packages/
RUN set -eu; \
    for p in client server engine; do \
        python -m build --no-isolation --wheel -o /dist "packages/$p"; \
    done; \
    ls -l /dist

# `runtime-base`: slim Python + the Go toolchain + git + tini. Every Go worker
# pool in the platform (engine analysis plane, SQLite injector, view readers,
# monitor pool, server backup/autopilot pool) only runs when `go` is on PATH --
# without it each one falls back to its pure-Python pool -- so the toolchain
# stays in the runtime image. The pool binaries themselves are PRE-BUILT at image
# build time (see the stages below), so no container ever compiles at runtime.
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime-base
COPY --from=go-toolchain /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOCACHE=/tmp/gocache \
    GOPATH=/tmp/gopath \
    GOFLAGS=-mod=mod \
    GOTOOLCHAIN=local \
    TINI_SUBREAPER=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Optional: containerized Go reader (the read-only VIEW worker).
# =============================================================================
# Builds the engine's views/go into a static binary and runs it against a mounted
# .db / .sql artifact. It discovers the installed analysis views from the
# database catalog and reads them concurrently -- the same views the loader
# materializes on the Postgres side. Gated behind the compose `reader` profile so
# a plain `docker compose up` never builds Go.
FROM golang:${GO_VERSION}-bookworm AS go-build
WORKDIR /src
COPY packages/engine/file_analyzer/views/go/go.mod packages/engine/file_analyzer/views/go/go.sum ./
RUN go mod download
COPY packages/engine/file_analyzer/views/go/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /repo-reader .

FROM gcr.io/distroless/static-debian12 AS reader
COPY --from=go-build /repo-reader /repo-reader
# Default: read the main repository.db mounted at /artifacts. Override the args
# in compose (or on the CLI) to point at another artifact or tune -workers.
ENTRYPOINT ["/repo-reader"]
CMD ["-source", "/artifacts/repository.db"]

# =============================================================================
# `engine-base`: the analysis profile (client + engine wheels) with every engine
# Go pool pre-built inside site-packages.
# =============================================================================
# Each pool rebuilds its binary only when a Go source is newer than it, so
# building here -- right after install -- leaves them all "fresh" for good.
FROM runtime-base AS engine-base
COPY --from=wheels /dist /dist
RUN set -eu; \
    pip install /dist/file_analyzer_client-*.whl /dist/file_analyzer_engine-*.whl; \
    rm -rf /dist; \
    fa="$(python -c 'import file_analyzer.client as m, os; print(os.path.dirname(os.path.dirname(m.__file__)))')"; \
    for spec in client/go:client-reader views/go:repo-reader core/go:repo-injector \
                router/go:analysis-plane monitor/go:monitor-pool; do \
        dir="${spec%%:*}"; bin="${spec##*:}"; \
        (cd "$fa/$dir" && go build -o "$bin" .); \
    done; \
    rm -rf /tmp/gocache /tmp/gopath; \
    python -m file_analyzer.main --version

# =============================================================================
# Optional: the analysis ENGINE (producer of the artifacts everything else loads)
# =============================================================================
# Runs `python -m file_analyzer.main` over a source repo mounted at /workspace
# and writes repository.db + repository_schema.sql (with the v_* analysis views
# already installed) into /artifacts. The loader/reader stages above then
# consume those artifacts. `git` is needed because the census walks git-tracked
# files; the Go toolchain lets the analysis plane and the SQLite injector fan out
# across their Go worker pools. The engine refuses bare metal -- a container
# satisfies its containment guard. Gated behind the compose `engine` profile.
FROM engine-base AS engine
WORKDIR /app
# Analyze the repo mounted at /workspace; emit artifacts to /artifacts. Override
# the args in compose (or on the CLI), e.g. add `--dialect postgresql`.
ENTRYPOINT ["python", "-m", "file_analyzer.main"]
CMD ["/workspace", "--out", "/artifacts"]

# =============================================================================
# Optional: the always-on background MONITOR (incremental re-analysis daemon)
# =============================================================================
# Runs `python -m file_analyzer monitor /workspace` as a long-lived process: it
# watches the repo mounted at /workspace, records the last 16 changes into the
# FIFO diff database and re-analyzes changed files across the Go worker pool as
# they appear.
#
# Zombie prevention is layered:
#   * `tini` is PID 1 and reaps any orphaned grandchildren (the compose service
#     also sets `init: true` as a second line of defense);
#   * the monitor installs SIGINT/SIGTERM handlers, writes a PID file and stops
#     its daemon threads + waits on every worker child on shutdown (SIGTERM from
#     `docker stop` therefore drains cleanly within stop_grace_period).
# Gated behind the compose `monitor` profile.
FROM engine-base AS monitor
WORKDIR /app
# tini (PID 1) forwards signals and reaps zombies; the monitor itself handles
# SIGTERM/SIGINT for a clean drain. Watch /workspace; keep state under /artifacts.
ENTRYPOINT ["tini", "--", "python", "-m", "file_analyzer", "monitor"]
CMD ["/workspace", "--out", "/artifacts", "--interval", "2"]

# =============================================================================
# Optional: the MCP server (AI-agent integration over stdio)
# =============================================================================
# `python -m mcp_server` with the engine's `agent` extra (mcp 1.x). It speaks
# MCP over stdin/stdout, so run it attached with -i, e.g. register it as
#     claude mcp add file-analyzer -- docker run -i --rm \
#         -v "$PWD:/workspace" -w /workspace <image>
# The analyzer fleet is imported at build time (--precompile), so the first tool
# call runs at full speed. Gated behind the compose `mcp` profile.
FROM engine-base AS mcp
RUN pip install "mcp[cli]>=1.2,<2" \
 && python -m mcp_server --precompile
WORKDIR /workspace
ENTRYPOINT ["tini", "--", "python", "-m", "mcp_server"]

# =============================================================================
# Optional: the DATABASE-HOSTING SERVER (file-analyzer-server)
# =============================================================================
# `file-analyzer-server run /workspace` hosts a repository session's databases
# and serves them over the token-authenticated HTTP control plane that
# ServerClient speaks. Everything it owns lives under FILE_ANALYZER_SERVER_HOME
# (/data): the session catalog, the hosted databases, backup sets, quarantine,
# autopilot state and logs. Reed-Solomon shards go to the /shards/disk* dirs --
# mount each on its own disk/volume so losing one never loses a backup.
#
# Inside, the server runs its maintenance on timers:
#   * periodic rotating backups (plain chunked, or RS erasure-coded shards),
#   * the time/space retention pass,
#   * the backup scrub (verify every shard block, repair damage),
#   * the self-healing autopilot (catalog/check/heal/scrub/backup/retention/
#     sweep), whose per-database work fans out on the Go worker pool.
# The Go pool binary (go/backup-pool, which drives both the backup workers and
# the autopilot inspect/verify/stage workers) is pre-built below.
#
# Runs as the unprivileged `fa` user (uid 10001); /data and /shards/* are owned
# by it, so fresh named volumes inherit that ownership. For a bind mount, chown
# the host directory to 10001 first. tini is PID 1 (reaps worker children and
# forwards SIGTERM, which the server handles with a clean shutdown).
#
# Remote backends: build with SERVER_EXTRAS=postgres (or mysql) to install the
# driver, then pass `--backend postgresql://...` in the server args.
FROM runtime-base AS server
ARG SERVER_EXTRAS=""
COPY --from=wheels /dist /dist
RUN set -eu; \
    srv="$(ls /dist/file_analyzer_server-*.whl)"; \
    if [ -n "$SERVER_EXTRAS" ]; then srv="${srv}[${SERVER_EXTRAS}]"; fi; \
    pip install /dist/file_analyzer_client-*.whl "$srv"; \
    rm -rf /dist; \
    fa="$(python -c 'import file_analyzer.client as m, os; print(os.path.dirname(os.path.dirname(m.__file__)))')"; \
    (cd "$fa/server/go" && go build -o backup-pool .); \
    (cd "$fa/client/go" && go build -o client-reader .); \
    rm -rf /tmp/gocache /tmp/gopath; \
    python -c "from file_analyzer.server.backup_pool import _go_binary; log = []; exe = _go_binary(log); assert exe is not None, log; print('server pool:', exe)"; \
    file-analyzer-server --version; \
    useradd --uid 10001 --user-group --no-create-home --home-dir /data --shell /usr/sbin/nologin fa; \
    mkdir -p /data /shards/disk1 /shards/disk2 /shards/disk3 /workspace /artifacts; \
    chown -R fa:fa /data /shards
ENV FILE_ANALYZER_SERVER_HOME=/data \
    FA_SERVER_PORT=8765
USER fa
WORKDIR /data
EXPOSE 8765
# /health is unauthenticated and independent of the catalog (a damaged catalog is
# the autopilot's job to repair, not a reason to restart the container).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('FA_SERVER_PORT', '8765'), timeout=4).read()"]
ENTRYPOINT ["tini", "--", "file-analyzer-server"]
# Serve /workspace on all interfaces (publish the port only where it should be
# reachable). Override the args in compose (SERVER_ARGS) or on the CLI.
CMD ["run", "/workspace", "--host", "0.0.0.0", "--port", "8765"]
