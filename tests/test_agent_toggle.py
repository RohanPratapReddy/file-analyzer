"""
Tests for the monitor's on/off toggles wired through ``python -m src``:

* ``--change-log`` / ``--no-change-log`` -- the durable append-only change log;
* ``--agents`` / ``--no-agents`` (+ include/exclude/roster/discover) -- the soft
  MCP agent tier that enriches every re-analyzed file.

The agent tier is *soft*: with no MCP provider reachable (as in CI) it must run,
report ``invoked: False`` and leave the deterministic result intact -- proving the
toggle is a real code path, not a no-op stub. When disabled it must not appear at
all. Everything here runs on the CI runner (no provider, no network).
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.__main__ import _split_names, build_parser  # noqa: E402
from src.monitor.incremental import IncrementalUpdateEngine  # noqa: E402
from src.monitor.monitor import RepositoryMonitor  # noqa: E402


# --------------------------------------------------------------------------- #
# CLI parsing: both toggles, both directions
# --------------------------------------------------------------------------- #
def test_cli_defaults():
    args = build_parser().parse_args(["monitor", "/repo"])
    assert args.change_log is True  # durable log on by default
    assert args.agents is False  # agent tier off by default
    assert args.discover_agents is True
    assert args.max_agent_files == 40


def test_cli_toggles_off_and_on():
    args = build_parser().parse_args(
        [
            "monitor",
            "/repo",
            "--no-change-log",
            "--agents",
            "--agents-include",
            "claude, gpt",
            "--agents-exclude",
            "flaky",
            "--no-discover-agents",
            "--agent-roster",
            "claude",
            "--max-agent-files",
            "5",
        ]
    )
    assert args.change_log is False
    assert args.agents is True
    assert args.discover_agents is False
    assert args.agent_roster == "claude"
    assert args.max_agent_files == 5
    assert _split_names(args.agents_include) == ["claude", "gpt"]
    assert _split_names(args.agents_exclude) == ["flaky"]


def test_split_names_empty_is_none():
    assert _split_names(None) is None
    assert _split_names("") is None
    assert _split_names("  ") is None


# --------------------------------------------------------------------------- #
# Incremental engine: the agent tier is a real, additive code path
# --------------------------------------------------------------------------- #
def test_agent_tier_soft_noop_when_no_provider(tmp_path):
    """An impossible include-list leaves zero eligible providers, so the tier
    deterministically degrades to a no-op regardless of the environment."""
    f = tmp_path / "m.py"
    f.write_text("def foo():\n    return 1\n", encoding="utf-8")
    eng = IncrementalUpdateEngine(
        readers_root=str(_ROOT),
        enable_agents=True,
        discover_agents=False,
        agents_include=["__no_such_provider__"],  # filters every provider out
        project_dir=str(tmp_path),
    )
    res = eng.analyze_file(str(f))
    assert res["status"] == "reanalyzed"
    agent = res["summary"]["agent"]
    assert agent["requested"] is True
    assert agent["invoked"] is False  # nothing eligible -> soft no-op
    assert agent["agent_calls"] == 0


def test_no_agent_key_when_disabled(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("x = 1\n", encoding="utf-8")
    eng = IncrementalUpdateEngine(readers_root=str(_ROOT), enable_agents=False)
    res = eng.analyze_file(str(f))
    assert res["status"] == "reanalyzed"
    assert "agent" not in res["summary"]


# --------------------------------------------------------------------------- #
# Monitor: the flag is threaded through and reaches the durable log
# --------------------------------------------------------------------------- #
def test_monitor_threads_agent_flag_into_reanalysis(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("a = 0\n", encoding="utf-8")

    mon = RepositoryMonitor(
        repo,
        out_dir=tmp_path / "artifacts",
        interval=0.2,
        use_go=False,
        inline_threshold=16,  # keep it inline so the agent tier runs in-thread
        enable_agents=True,
        discover_agents=False,
        agents_include=["__no_such_provider__"],  # hermetic: no live LLM call
    )
    mon.initialize()
    try:
        assert mon.updater.enable_agents is True
        assert mon.enable_agents is True

        (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
        summary = mon.scan_once()
        assert summary["changes"] == 1

        history = mon.change_history(limit=5)
        assert history, "durable change log kept the event"
        # update_summary is stored as JSON text; the agent sub-dict is present
        # because the toggle really threaded into the re-analysis.
        assert '"agent"' in history[0]["update_summary"]
    finally:
        mon.close()


def test_monitor_no_agent_by_default(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("a = 0\n", encoding="utf-8")

    mon = RepositoryMonitor(
        repo,
        out_dir=tmp_path / "artifacts",
        interval=0.2,
        use_go=False,
        inline_threshold=16,
    )
    mon.initialize()
    try:
        assert mon.enable_agents is False
        assert mon.updater.enable_agents is False

        (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
        mon.scan_once()
        history = mon.change_history(limit=5)
        assert history
        assert '"agent"' not in history[0]["update_summary"]
    finally:
        mon.close()
