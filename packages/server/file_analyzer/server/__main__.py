"""
``python -m file_analyzer.server`` -- run and control the database-hosting server.

Subcommands::

    start   [root] [--detach] [options]   # start a server (detached persists by PID)
    run     [root] [options]              # foreground runner (what --detach launches)
    stop    [root] [--all] [--server-id]  # stop this repo's server(s) by PID
    status  [root]                        # running servers + hosted databases
    host    [root] --db-name N --source P # host a database file under the session
    databases [root]                      # list hosted databases (JSON)
    backup  [root] [--storage-key K]      # run a backup now
    retention [root] [--dry-run]          # run a retention pass now (or preview it)
    restore [root] --storage-key K --dest P [--timestamp T]  # restore a backup set
    backup-verify [root] [--storage-key K] [--timestamp T]   # check backups block by block
    backup-repair [root] [--storage-key K] [--timestamp T]   # rebuild lost/corrupt shards
    logs    [root] [--lines N]            # tail the backend Postgres logs
    check   [root]                        # health-check catalog + every database (exit 1 on problems)
    maintain [root] [--dry-run] [--task T ...]  # run an autopilot tick now: check, heal, ...
    autopilot [root]                      # autopilot schedule, health and recent events

A serving server runs the **autopilot** every ``--autopilot-interval`` seconds
(0 disables it): it checks the catalog and every hosted database (structure,
checksum, ``quick_check``; a full ``integrity_check`` every
``--deep-check-interval``), restores damaged/missing/drifted databases from
verified backups (quarantining the damaged copy), scrubs and repairs backup
sets, keeps backups fresh, enforces retention and sweeps debris and orphans.

Backups are plain chunked sets by default. ``--rs-data-shards K`` (with
``--rs-parity-shards M`` and one ``--shard-dir`` per disk/mount) switches them to
Reed-Solomon erasure-coded sets: any ``K`` of the ``K + M`` shards restore a
backup, and a periodic scrub (``--scrub-interval``) verifies and repairs them.

``start --detach`` launches a background process that outlives this shell and
writes a PID file; ``stop`` terminates it by that PID. Multiple ``start`` calls on
the same repository share one session token (no duplicate database copies).

The subcommand is optional: ``python -m file_analyzer.server /repo`` is treated as
``python -m file_analyzer.server start /repo``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .._version import __version__


def _retention_flags(p: argparse.ArgumentParser, *, periodic: bool) -> None:
    """Time/space retention policy flags (0 disables any limit)."""
    if periodic:
        p.add_argument(
            "--retention-interval",
            type=float,
            default=3600.0,
            help="seconds between retention passes (0 disables; default 3600)",
        )
    p.add_argument(
        "--retention-days",
        type=float,
        default=30.0,
        help="evict a hosted database idle (not re-hosted or read) this many "
        "days, with its backups (0 disables; default 30)",
    )
    p.add_argument(
        "--backup-retention-days",
        type=float,
        default=7.0,
        help="prune backup sets older than this many days; each hosted database "
        "keeps its newest set (0 disables; default 7)",
    )
    p.add_argument(
        "--max-total-size",
        default="0",
        help="size budget for hosted databases + backups, e.g. 20G or 512MB; "
        "old backups then least-recently-used databases are removed to fit "
        "(0 disables; default)",
    )


def _erasure_flags(p: argparse.ArgumentParser, *, serving: bool) -> None:
    """Reed-Solomon backup flags (shared by every subcommand touching backups)."""
    from .retention import parse_size

    p.add_argument(
        "--rs-data-shards",
        type=int,
        default=0,
        help="erasure code backups into this many data shards (0 = plain "
        "chunked backups, the default; e.g. 4)",
    )
    p.add_argument(
        "--rs-parity-shards",
        type=int,
        default=2,
        help="parity shards per backup: this many shards (or the shard dirs "
        "holding them) can be lost without losing the backup (default 2)",
    )
    p.add_argument(
        "--rs-block-size",
        type=parse_size,
        default=1024 * 1024,
        help="largest block per shard per stripe, e.g. 1M or 256K (default 1M)",
    )
    p.add_argument(
        "--shard-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="a directory (ideally its own disk/mount) to spread shards over; "
        "repeat for several (default: the server's backup directory)",
    )
    if serving:
        p.add_argument(
            "--scrub-interval",
            type=float,
            default=86400.0,
            help="seconds between integrity scrubs that verify every shard "
            "block and repair damage (0 disables; default 86400)",
        )


def _autopilot_flags(p: argparse.ArgumentParser, *, serving: bool) -> None:
    """Self-healing maintenance flags."""
    if serving:
        p.add_argument(
            "--autopilot-interval",
            type=float,
            default=300.0,
            help="seconds between autopilot maintenance ticks (0 disables the "
            "autopilot; retention/scrub then run on their own timers; default 300)",
        )
        p.add_argument(
            "--autopilot-startup-delay",
            type=float,
            default=30.0,
            help="seconds before the first autopilot tick (default 30)",
        )
    p.add_argument(
        "--check-interval",
        type=float,
        default=900.0,
        help="seconds between health checks of the catalog + hosted databases "
        "(default 900)",
    )
    p.add_argument(
        "--deep-check-interval",
        type=float,
        default=86400.0,
        help="seconds between full PRAGMA integrity_check passes (0 disables; "
        "default 86400)",
    )
    p.add_argument(
        "--no-auto-heal",
        action="store_true",
        help="detect and report damage, but do not restore from backups",
    )
    p.add_argument(
        "--no-rollback",
        action="store_true",
        help="heal only from backups of the exact hosted content, never an older one",
    )
    p.add_argument(
        "--no-auto-backup",
        action="store_true",
        help="do not back up databases that lack a recent exact backup",
    )
    p.add_argument(
        "--drift-action",
        choices=("restore", "adopt", "report"),
        default="restore",
        help="for a sound database whose checksum changed: restore the hosted "
        "version from backup (default), adopt the new content, or only report",
    )
    p.add_argument(
        "--autopilot-workers",
        type=int,
        default=None,
        metavar="N",
        help="concurrent workers for health checks, backup verification and "
        "heal restores (default: sized to the work, 4..32; 1 runs inline)",
    )
    p.add_argument(
        "--no-go-workers",
        action="store_true",
        help="never use the Go worker pool; fan out on a Python thread pool",
    )


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python -m file_analyzer.server",
        description="Host a repo-session's databases; serve them to clients.",
    )
    ap.add_argument(
        "--version",
        action="version",
        version=f"file-analyzer {__version__}",
        help="print the file-analyzer version and exit.",
    )
    sub = ap.add_subparsers(dest="command")

    def _common(p: argparse.ArgumentParser, *, serving: bool) -> None:
        p.add_argument("root", nargs="?", default=".", help="repository to host")
        p.add_argument(
            "--backend",
            default="sqlite",
            help="'sqlite' (live files, default) or a SQL URL "
            "(postgresql://... / mysql://...) for the chunked content store.",
        )
        p.add_argument("--catalog-dir", default=None, help="shared catalog directory")
        p.add_argument("--catalog-target", default=None, help="catalog SQL URL/path")
        _erasure_flags(p, serving=serving)
        if serving:
            p.add_argument("--host", default="127.0.0.1", help="bind host")
            p.add_argument("--port", type=int, default=0, help="bind port (0=auto)")
            p.add_argument("--token", default=None, help="explicit session token")
            p.add_argument("--server-id", default=None, help="explicit server id")
            p.add_argument(
                "--chunk-bytes",
                type=int,
                default=8 * 1024 * 1024,
                help="per-chunk size for the remote content store (default 8 MiB)",
            )
            p.add_argument(
                "--backup-interval",
                type=float,
                default=900.0,
                help="seconds between periodic backups (0 disables; default 900)",
            )
            p.add_argument(
                "--backup-keep",
                type=int,
                default=5,
                help="backup sets to keep per database before rotating (default 5)",
            )
            _retention_flags(p, periodic=True)
            _autopilot_flags(p, serving=True)
            p.add_argument(
                "--no-contain",
                action="store_true",
                help="skip the bare-metal containment guard (caller owns isolation)",
            )

    start = sub.add_parser("start", help="start a server (optionally detached)")
    _common(start, serving=True)
    start.add_argument(
        "--detach",
        action="store_true",
        help="run in the background, detached with a PID, and return its endpoint",
    )

    run = sub.add_parser("run", help="foreground runner (used by --detach)")
    _common(run, serving=True)

    stop = sub.add_parser("stop", help="stop server(s) hosting a repository")
    _common(stop, serving=False)
    stop.add_argument("--all", action="store_true", help="stop all servers for repo")
    stop.add_argument("--server-id", default=None, help="stop one server by id")

    status = sub.add_parser("status", help="show running servers + hosted databases")
    _common(status, serving=False)

    host = sub.add_parser("host", help="host a database file under the session")
    _common(host, serving=False)
    host.add_argument("--db-name", required=True, help="logical database name")
    host.add_argument("--source", required=True, help="path to the SQLite database")

    dbs = sub.add_parser("databases", help="list hosted databases")
    _common(dbs, serving=False)

    backup = sub.add_parser("backup", help="run a backup now")
    _common(backup, serving=False)
    backup.add_argument("--storage-key", default=None, help="one database, else all")

    retention = sub.add_parser(
        "retention", help="run a retention pass now (evict idle dbs / old backups)"
    )
    _common(retention, serving=False)
    _retention_flags(retention, periodic=False)
    retention.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be removed without removing anything",
    )

    restore = sub.add_parser("restore", help="restore a backup set to a file")
    _common(restore, serving=False)
    restore.add_argument("--storage-key", required=True, help="database to restore")
    restore.add_argument(
        "--timestamp", default=None, help="backup set to restore (default: newest)"
    )
    restore.add_argument("--dest", required=True, help="file to write")

    for name, text in (
        ("backup-verify", "verify backup sets block by block (read-only)"),
        ("backup-repair", "rebuild lost/corrupt shards of erasure-coded backups"),
    ):
        cmd = sub.add_parser(name, help=text)
        _common(cmd, serving=False)
        cmd.add_argument("--storage-key", default=None, help="one database, else all")
        cmd.add_argument("--timestamp", default=None, help="one set, else all")

    logs = sub.add_parser("logs", help="tail the backend Postgres logs")
    _common(logs, serving=False)
    logs.add_argument("--lines", type=int, default=100, help="lines to show")

    check = sub.add_parser(
        "check", help="health-check the catalog + every hosted database now"
    )
    _common(check, serving=False)
    _autopilot_flags(check, serving=False)

    from .autopilot import TASKS

    maintain = sub.add_parser(
        "maintain",
        help="run an autopilot maintenance tick now (check, heal, backup, ...)",
    )
    _common(maintain, serving=False)
    _retention_flags(maintain, periodic=False)
    _autopilot_flags(maintain, serving=False)
    maintain.add_argument(
        "--task",
        action="append",
        choices=TASKS,
        default=[],
        help="run only this task (repeatable; default: all of them)",
    )
    maintain.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be healed/removed without changing anything",
    )
    maintain.add_argument(
        "--backup-interval",
        type=float,
        default=900.0,
        help="the serving backup interval; a database whose newest exact "
        "backup is older than twice this is backed up (default 900)",
    )

    autopilot = sub.add_parser(
        "autopilot", help="show the autopilot schedule, health and events"
    )
    _common(autopilot, serving=False)

    return ap


def _build_server(args: argparse.Namespace):
    from .retention import parse_size
    from .server import DatabaseServer

    kwargs = dict(
        root=args.root,
        backend=args.backend,
        catalog_dir=args.catalog_dir,
        catalog_target=args.catalog_target,
    )
    for attr in (
        "host",
        "port",
        "token",
        "server_id",
        "chunk_bytes",
        "backup_interval",
        "backup_keep",
        "retention_interval",
        "rs_data_shards",
        "rs_parity_shards",
        "rs_block_size",
        "scrub_interval",
    ):
        if hasattr(args, attr) and getattr(args, attr) is not None:
            kwargs[attr] = getattr(args, attr)
    if "rs_block_size" in kwargs:
        kwargs["rs_block_bytes"] = kwargs.pop("rs_block_size")
    if getattr(args, "shard_dir", None):
        kwargs["shard_dirs"] = list(args.shard_dir)
    if hasattr(args, "retention_days"):
        kwargs["retention_max_age"] = args.retention_days * 86400.0
        kwargs["backup_max_age"] = args.backup_retention_days * 86400.0
        kwargs["retention_max_bytes"] = parse_size(args.max_total_size)
    for attr in (
        "autopilot_interval",
        "autopilot_startup_delay",
        "check_interval",
        "deep_check_interval",
        "drift_action",
    ):
        if getattr(args, attr, None) is not None:
            kwargs[attr] = getattr(args, attr)
    if hasattr(args, "no_auto_heal"):
        kwargs["auto_heal"] = not args.no_auto_heal
        kwargs["allow_rollback"] = not args.no_rollback
        kwargs["auto_backup"] = not args.no_auto_backup
    if getattr(args, "autopilot_workers", None) is not None:
        if args.autopilot_workers < 0:
            raise SystemExit("--autopilot-workers must be >= 0")
        kwargs["autopilot_workers"] = args.autopilot_workers
    if getattr(args, "no_go_workers", False):
        kwargs["autopilot_use_go"] = False
    return DatabaseServer(**kwargs)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    known = {
        "start",
        "run",
        "stop",
        "status",
        "host",
        "databases",
        "backup",
        "retention",
        "restore",
        "backup-verify",
        "backup-repair",
        "logs",
        "check",
        "maintain",
        "autopilot",
    }
    if argv and argv[0] not in known and argv[0] not in ("-h", "--help", "--version"):
        argv = ["start", *argv]

    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help()
        return 2

    if args.command in ("start", "run"):
        server = _build_server(args)
        if args.command == "start" and getattr(args, "detach", False):
            info = server.start_detached()
            print(json.dumps(info, indent=2, default=str))
            return 0
        # Foreground run.
        return server.serve(contained=not getattr(args, "no_contain", False))

    if args.command == "stop":
        server = _build_server(args)
        result = server.stop(all_for_repo=args.all)
        print(json.dumps(result, indent=2, default=str))
        return 0

    if args.command == "status":
        server = _build_server(args)
        print(json.dumps(server.status(), indent=2, default=str))
        return 0

    if args.command == "host":
        server = _build_server(args)
        rec = server.host_database(args.source, args.db_name)
        print(json.dumps(rec, indent=2, default=str))
        return 0

    if args.command == "databases":
        server = _build_server(args)
        print(json.dumps(server.databases(), indent=2, default=str))
        return 0

    if args.command == "backup":
        server = _build_server(args)
        if args.storage_key:
            out = server.backups.backup_database(args.storage_key)
        else:
            out = server.backups.backup_all()
        print(json.dumps(out, indent=2, default=str))
        return 0

    if args.command == "retention":
        server = _build_server(args)
        report = server.enforce_retention(dry_run=args.dry_run)
        print(json.dumps(report, indent=2, default=str))
        return 0

    if args.command == "restore":
        server = _build_server(args)
        dest = server.restore_backup(args.storage_key, args.dest, args.timestamp)
        print(json.dumps({"restored": str(dest)}, indent=2))
        return 0

    if args.command in ("backup-verify", "backup-repair"):
        server = _build_server(args)
        action = (
            server.verify_backups
            if args.command == "backup-verify"
            else server.repair_backups
        )
        report = action(args.storage_key, args.timestamp)
        print(json.dumps(report, indent=2, default=str))
        bad = {"unrecoverable", "incomplete", "error"}
        if args.command == "backup-verify":
            bad.add("degraded")
        return 1 if any(s["status"] in bad for s in report["sets"]) else 0

    if args.command == "logs":
        server = _build_server(args)
        print(json.dumps(server.postgres_logs(args.lines), indent=2, default=str))
        return 0

    if args.command in ("check", "maintain"):
        server = _build_server(args)
        if args.command == "check":
            report = server.check_health()
        else:
            report = server.run_maintenance(
                dry_run=args.dry_run, tasks=args.task or None
            )
        print(json.dumps(report, indent=2, default=str))
        if report.get("skipped"):
            return 1
        return 0 if report.get("healthy") else 1

    if args.command == "autopilot":
        server = _build_server(args)
        print(json.dumps(server.autopilot_status(), indent=2, default=str))
        return 0

    build_parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
