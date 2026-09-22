# syntax=docker/dockerfile:1
# =============================================================================
# tabgen "readers" — artifact loader image
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
# Optional: containerized Go reader (the read-only VIEW worker).
# =============================================================================
# Builds file_analyzer/views/go into a static binary and runs it against a mounted .db /
# .sql artifact. It discovers the installed analysis views from the database
# catalog and reads them concurrently -- the same views the loader materializes
# on the Postgres side. Gated behind the compose `reader` profile so a plain
# `docker compose up` never builds Go. Requires file_analyzer/views/go + file_analyzer/views/sql to be
# in the build context (see .dockerignore).
FROM golang:1.22-bookworm AS go-build
WORKDIR /src
COPY file_analyzer/views/go/go.mod file_analyzer/views/go/go.sum ./
RUN go mod download
COPY file_analyzer/views/go/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /repo-reader .

FROM gcr.io/distroless/static-debian12 AS reader
COPY --from=go-build /repo-reader /repo-reader
# Default: read the main repository.db mounted at /artifacts. Override the args
# in compose (or on the CLI) to point at another artifact or tune -workers.
ENTRYPOINT ["/repo-reader"]
CMD ["-source", "/artifacts/repository.db"]

# =============================================================================
# Optional: the analysis ENGINE (producer of the artifacts everything else loads)
# =============================================================================
# Runs `python -m file_analyzer.main` (the file_analyzer package entry point) over a source repo
# mounted at /workspace and writes repository.db + repository_schema.sql (with
# the v_* analysis views already installed) into /artifacts. The loader/reader
# stages above then consume those artifacts. Pure-stdlib core, so a slim Python
# image suffices; `git` is needed because the census walks git-tracked files.
# Gated behind the compose `engine` profile. Requires the whole file_analyzer/ package in
# the build context (see .dockerignore).
FROM python:3.12-slim-bookworm AS engine
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY file_analyzer/ ./file_analyzer/
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Analyze the repo mounted at /workspace; emit artifacts to /artifacts. Override
# the args in compose (or on the CLI), e.g. add `--dialect postgresql`.
ENTRYPOINT ["python", "-m", "file_analyzer.main"]
CMD ["/workspace", "--out", "/artifacts"]

# =============================================================================
# Optional: the always-on background MONITOR (incremental re-analysis daemon)
# =============================================================================
# Runs `python -m file_analyzer monitor /workspace` as a long-lived process: it watches the
# repo mounted at /workspace, records the last 16 changes into the FIFO diff
# database and re-analyzes changed files across the Go worker pool as they appear.
#
# Zombie prevention is layered:
#   * `tini` is PID 1 and reaps any orphaned grandchildren (the compose service
#     also sets `init: true` as a second line of defense);
#   * the monitor installs SIGINT/SIGTERM handlers, writes a PID file and stops
#     its daemon threads + waits on every worker child on shutdown (SIGTERM from
#     `docker stop` therefore drains cleanly within stop_grace_period).
#
# The Go worker pool is real here: the Go 1.22 toolchain is copied in so the pool
# builds `file_analyzer/monitor/go` on first use (GOCACHE/GOPATH point at writable /tmp).
# Without Go it would transparently fall back to the concurrent.futures pool.
# Gated behind the compose `monitor` profile. Requires the whole file_analyzer/ package in
# the build context (see .dockerignore).
FROM python:3.12-slim-bookworm AS monitor
COPY --from=golang:1.22-bookworm /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOCACHE=/tmp/gocache \
    GOPATH=/tmp/gopath \
    GOFLAGS=-mod=mod
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY file_analyzer/ ./file_analyzer/
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# tini (PID 1) forwards signals and reaps zombies; the monitor itself handles
# SIGTERM/SIGINT for a clean drain. Watch /workspace; keep state under /artifacts.
ENTRYPOINT ["tini", "--", "python", "-m", "file_analyzer", "monitor"]
CMD ["/workspace", "--out", "/artifacts", "--interval", "2"]
