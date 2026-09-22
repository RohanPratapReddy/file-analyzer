"""
``python -m file_analyzer`` entrypoint -- run the repository monitoring layer as a process.

This makes the background monitor *persistable*: instead of only living inside an
agent session (as a daemon thread), it can be launched as its own long-running
process that watches a repository, records the last 16 changes into the FIFO diff
database and re-analyzes changed files as they appear -- across the Go / Python
worker pool. It installs SIGINT/SIGTERM handlers and writes a PID file, and shuts
down cleanly (no orphaned threads or child processes).

Examples::

    python -m file_analyzer monitor .                     # watch the cwd, 2s cadence
    python -m file_analyzer monitor /repo --interval 1    # faster cadence
    python -m file_analyzer monitor /repo --once          # one scan cycle, then exit
    python -m file_analyzer monitor /repo --max-workers 200 --min-workers 20
    python -m file_analyzer monitor /repo --no-go         # force the Python fallback pool
    python -m file_analyzer monitor /repo --no-change-log # FIFO ring only (no durable log)
    python -m file_analyzer monitor /repo --agents        # enrich each change via MCP agents
    python -m file_analyzer monitor /repo --agents --agents-include claude,gpt --agent-roster claude

The subcommand is optional -- ``python -m file_analyzer /repo`` is treated as
``python -m file_analyzer monitor /repo``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import List, Optional


def _split_names(value: Optional[str]) -> Optional[List[str]]:
    """Parse a comma/whitespace-separated provider list into a clean list.

    Returns ``None`` for an empty/unset value so it passes straight through to
    the monitor's ``agents_include`` / ``agents_exclude`` (which treat ``None``
    as "no filter"). Mirrors ``file_analyzer.main._split_names``.
    """
    if not value:
        return None
    names = [n.strip() for n in re.split(r"[,\s]+", value) if n.strip()]
    return names or None


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python -m file_analyzer",
        description="Background repository monitor + incremental re-analysis.",
    )
    from ._version import __version__

    # Prints and exits during parsing (like --help) -- before the containment guard.
    ap.add_argument(
        "--version",
        action="version",
        version=f"file-analyzer {__version__}",
        help="print the file-analyzer version and exit.",
    )
    sub = ap.add_subparsers(dest="command")

    mon = sub.add_parser(
        "monitor", help="watch a repository and record/re-analyze changes"
    )
    mon.add_argument("path", help="repository directory to watch")
    mon.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="seconds between scan cycles (default: 2.0)",
    )
    mon.add_argument(
        "--capacity",
        type=int,
        default=16,
        help="FIFO buffer depth: consecutive changes retained (default: 16)",
    )
    mon.add_argument(
        "--out", default=None, help="artifact dir (default: <path>/.file-analyzer)"
    )
    mon.add_argument("--diff-db", default=None, help="diff database path")
    mon.add_argument("--pid-file", default=None, help="PID file path")
    mon.add_argument(
        "--change-log-url",
        default=None,
        help=(
            "durable change-log store: a remote SQL URL "
            "(postgresql://... / mysql://...) or a SQLite path; default is a local "
            "SQLite file under <out>/monitor/changes_log.db"
        ),
    )
    mon.add_argument(
        "--change-log-path",
        default=None,
        help="local SQLite path for the durable change log (ignored if URL given)",
    )
    mon.add_argument(
        "--change-log",
        dest="change_log",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "enable/disable the durable append-only change log (the superset of "
            "the FIFO ring that never deletes evicted events). On by default; "
            "use --no-change-log for FIFO-ring-only."
        ),
    )
    mon.add_argument(
        "--min-workers",
        type=int,
        default=16,
        help="worker-pool floor for large change sets (default: 16)",
    )
    mon.add_argument(
        "--max-workers",
        type=int,
        default=128,
        help="worker-pool ceiling for large change sets (default: 128)",
    )
    mon.add_argument(
        "--inline-threshold",
        type=int,
        default=8,
        help="re-analyze inline when <= N files changed, else fan out (default: 8)",
    )
    mon.add_argument(
        "--no-go",
        action="store_true",
        help="skip the Go worker pool and use the Python fallback",
    )
    mon.add_argument(
        "--agents",
        dest="agents",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "enable/disable the soft MCP agent tier on every re-analyzed file "
            "(the same agent layer a full run uses: summary, quality/security "
            "findings, symbol docs). Off by default; a no-op unless an MCP "
            "provider is actually reachable."
        ),
    )
    mon.add_argument(
        "--agents-include",
        default=None,
        metavar="NAMES",
        help="comma/space-separated allow-list of agent/provider names to use "
        "(case-insensitive; unknown names ignored). When set, only these "
        "providers are eligible.",
    )
    mon.add_argument(
        "--agents-exclude",
        default=None,
        metavar="NAMES",
        help="comma/space-separated deny-list of agent/provider names to drop "
        "(applied after --agents-include).",
    )
    mon.add_argument(
        "--discover-agents",
        dest="discover_agents",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="resolve providers from the desktop/CLI-configured MCP servers so "
        "the include/exclude filter has providers to act on (on by default).",
    )
    mon.add_argument(
        "--agent-roster",
        default=None,
        metavar="NAME",
        help="preferred provider name for the agent tier (used when reachable, "
        "else the first available provider).",
    )
    mon.add_argument(
        "--max-agent-files",
        type=int,
        default=40,
        help="cap on files handed to the agent tier per re-analysis (default: 40)",
    )
    mon.add_argument(
        "--no-reanalyze",
        action="store_true",
        help="only record changes; do not re-run analyzers",
    )
    mon.add_argument(
        "--no-offline",
        action="store_true",
        help="do not record changes that happened while the monitor was down",
    )
    mon.add_argument(
        "--once",
        action="store_true",
        help="run a single scan cycle and exit (prints a JSON summary)",
    )
    return ap


def _make_monitor(args: argparse.Namespace):
    from .monitor import RepositoryMonitor

    return RepositoryMonitor(
        root=args.path,
        out_dir=args.out,
        diff_db_path=args.diff_db,
        interval=args.interval,
        capacity=args.capacity,
        min_workers=args.min_workers,
        max_workers=args.max_workers,
        inline_threshold=args.inline_threshold,
        use_go=not args.no_go,
        record_offline_changes=not args.no_offline,
        reanalyze=not args.no_reanalyze,
        enable_change_log=args.change_log,
        change_log_url=args.change_log_url,
        change_log_path=args.change_log_path,
        enable_agents=args.agents,
        agents_include=_split_names(args.agents_include),
        agents_exclude=_split_names(args.agents_exclude),
        discover_agents=args.discover_agents,
        agent_roster=args.agent_roster,
        max_agent_files=args.max_agent_files,
    )


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Allow the subcommand to be omitted: "python -m file_analyzer /repo" == "... monitor /repo".
    # Top-level flags (--version/--help) must reach the top-level parser, so they
    # are NOT rewritten into the monitor subcommand.
    if argv and argv[0] not in ("monitor", "-h", "--help", "--version"):
        argv = ["monitor", *argv]

    args = build_parser().parse_args(argv)
    if args.command != "monitor":
        build_parser().print_help()
        return 2

    # Containment guard: only run inside a container or VM, never on bare-metal
    # host hardware. Refuses (exit code 3) unless a container/VM is detected or
    # FILE_ANALYZER_ALLOW_BARE_METAL is set. Placed after the help/no-command
    # path so ``--help`` still works anywhere.
    from .runtime_guard import require_virtualized

    require_virtualized(context="python -m file_analyzer")

    monitor = _make_monitor(args)
    if args.once:
        monitor.initialize()
        summary = monitor.scan_once()
        monitor.close()
        print(json.dumps(summary, indent=2, default=str))
        return 0
    return monitor.run_forever(pid_file=args.pid_file)


if __name__ == "__main__":
    raise SystemExit(main())
