"""
Tests for the bare-metal containment guard (``file_analyzer/core/runtime_guard.py``).

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

from file_analyzer.core import runtime_guard as rg  # noqa: E402


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
