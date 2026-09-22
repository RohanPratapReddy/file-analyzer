"""
Tests for the bare-metal containment guard (``file_analyzer/runtime_guard.py``).

The CLI entrypoints must run only inside a container or a VM. These tests pin the
*enforcement contract* independently of the machine the suite happens to run on
(bare-metal Windows dev box, or inside CI's Docker container) by monkeypatching
the two detectors -- so the refuse / allow / override behaviour is verified
deterministically everywhere. The real detection path itself is exercised for
real by the CI smoke commands, which run under Docker.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from file_analyzer import runtime_guard as rg  # noqa: E402


def _bare_metal(monkeypatch):
    monkeypatch.delenv(rg.OVERRIDE_ENV, raising=False)
    monkeypatch.setattr(rg, "detect_container", lambda: (None, []))
    monkeypatch.setattr(rg, "detect_virtual_machine", lambda: (None, []))


def test_inspect_environment_shape():
    info = rg.inspect_environment()
    for key in (
        "platform",
        "system",
        "container",
        "virtual_machine",
        "virtualized",
        "override",
        "signals",
    ):
        assert key in info
    assert isinstance(info["signals"], list)
    assert isinstance(info["virtualized"], bool)


def test_refuses_on_bare_metal(monkeypatch):
    _bare_metal(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        rg.require_virtualized(context="test")
    assert excinfo.value.code == rg.BARE_METAL_EXIT_CODE


def test_override_bypasses_bare_metal(monkeypatch):
    _bare_metal(monkeypatch)
    monkeypatch.setenv(rg.OVERRIDE_ENV, "1")
    info = rg.require_virtualized(context="test")  # must NOT raise
    assert info["override"] is True


def test_override_accepts_word_values(monkeypatch):
    _bare_metal(monkeypatch)
    for val in ("true", "YES", "On"):
        monkeypatch.setenv(rg.OVERRIDE_ENV, val)
        assert rg.require_virtualized(context="test")["override"] is True


def test_allows_in_container(monkeypatch):
    monkeypatch.delenv(rg.OVERRIDE_ENV, raising=False)
    monkeypatch.setattr(
        rg, "detect_container", lambda: ("docker", ["/.dockerenv present"])
    )
    monkeypatch.setattr(rg, "detect_virtual_machine", lambda: (None, []))
    info = rg.require_virtualized(context="test")  # must NOT raise
    assert info["virtualized"] is True
    assert info["container"] == "docker"


def test_allows_in_vm(monkeypatch):
    monkeypatch.delenv(rg.OVERRIDE_ENV, raising=False)
    monkeypatch.setattr(rg, "detect_container", lambda: (None, []))
    monkeypatch.setattr(
        rg, "detect_virtual_machine", lambda: ("kvm", ["hypervisor flag"])
    )
    info = rg.require_virtualized(context="test")  # must NOT raise
    assert info["virtualized"] is True
    assert info["virtual_machine"] == "kvm"


def test_cli_run_refuses_on_bare_metal(monkeypatch, capsys):
    """The main.py entrypoint itself refuses before doing any work."""
    _bare_metal(monkeypatch)
    from file_analyzer.main import run

    with pytest.raises(SystemExit) as excinfo:
        run(["--list-components"])
    assert excinfo.value.code == rg.BARE_METAL_EXIT_CODE
    assert "BARE-METAL" in capsys.readouterr().err


def test_cli_run_allowed_when_virtualized(monkeypatch):
    """When a container/VM is detected, main.py proceeds (here: --list-components)."""
    monkeypatch.delenv(rg.OVERRIDE_ENV, raising=False)
    monkeypatch.setattr(rg, "detect_container", lambda: ("docker", ["x"]))
    monkeypatch.setattr(rg, "detect_virtual_machine", lambda: (None, []))
    from file_analyzer.main import run

    assert run(["--list-components"]) == 0


# ---------------------------------------------------------------------------
# Boundary: the runnable surfaces (CLI + MCP) are guarded; the SDK import is not.
# ---------------------------------------------------------------------------
def test_sdk_import_is_unguarded_on_bare_metal(monkeypatch):
    """Using the SDK as a library never trips the containment guard."""
    _bare_metal(monkeypatch)
    import file_analyzer.engine as fae  # importing / using the SDK must not SystemExit

    assert isinstance(fae.__version__, str)
    from file_analyzer.engine import scrub

    assert scrub("plain text") == "plain text"


def test_mcp_server_refuses_on_bare_metal(monkeypatch):
    """Serving the MCP tools refuses on bare metal, before the server starts."""
    mcp_server = pytest.importorskip("mcp_server")

    _bare_metal(monkeypatch)
    # Belt and braces: even if the guard were bypassed, never actually serve.
    monkeypatch.setattr(mcp_server, "_start_warm_cache", lambda: None)
    called = {"run": False}
    monkeypatch.setattr(
        mcp_server.mcp, "run", lambda *a, **k: called.__setitem__("run", True)
    )
    monkeypatch.setattr(sys, "argv", ["mcp_server"])

    with pytest.raises(SystemExit) as excinfo:
        mcp_server.main()
    assert excinfo.value.code == rg.BARE_METAL_EXIT_CODE
    assert called["run"] is False  # the guard fired before mcp.run()


def test_mcp_server_allowed_when_virtualized(monkeypatch):
    """When a container/VM is detected, the MCP server proceeds to serve."""
    mcp_server = pytest.importorskip("mcp_server")

    monkeypatch.delenv(rg.OVERRIDE_ENV, raising=False)
    monkeypatch.setattr(rg, "detect_container", lambda: ("docker", ["x"]))
    monkeypatch.setattr(rg, "detect_virtual_machine", lambda: (None, []))
    monkeypatch.setattr(mcp_server, "_start_warm_cache", lambda: None)
    called = {"run": False}
    monkeypatch.setattr(
        mcp_server.mcp, "run", lambda *a, **k: called.__setitem__("run", True)
    )
    monkeypatch.setattr(sys, "argv", ["mcp_server"])

    mcp_server.main()  # must not raise
    assert called["run"] is True


def test_mcp_version_bypasses_guard_on_bare_metal(monkeypatch, capsys):
    """`--version` prints and exits before the guard, so it works anywhere."""
    mcp_server = pytest.importorskip("mcp_server")

    _bare_metal(monkeypatch)
    called = {"run": False}
    monkeypatch.setattr(
        mcp_server.mcp, "run", lambda *a, **k: called.__setitem__("run", True)
    )
    monkeypatch.setattr(sys, "argv", ["mcp_server", "--version"])

    mcp_server.main()  # must return, not SystemExit(3)
    assert "file-analyzer" in capsys.readouterr().out
    assert called["run"] is False
