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
    logs    [root] [--lines N]            # tail the backend Postgres logs

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

    logs = sub.add_parser("logs", help="tail the backend Postgres logs")
    _common(logs, serving=False)
    logs.add_argument("--lines", type=int, default=100, help="lines to show")

    return ap


def _build_server(args: argparse.Namespace):
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
    ):
        if hasattr(args, attr) and getattr(args, attr) is not None:
            kwargs[attr] = getattr(args, attr)
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
        "logs",
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

    if args.command == "logs":
        server = _build_server(args)
        print(json.dumps(server.postgres_logs(args.lines), indent=2, default=str))
        return 0

    build_parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
