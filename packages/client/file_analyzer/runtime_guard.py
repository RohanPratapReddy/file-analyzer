"""
Runtime containment guard: refuse to run on bare-metal OS hardware.

The CLI entrypoints (``file_analyzer/main.py`` and ``file_analyzer/__main__.py``) must only run
*inside a container (Docker / Podman / containerd / LXC / Kubernetes) or a
virtual machine* -- never directly on the host's physical hardware. This module
does the real detection and enforces it.

Detection is stdlib-only (so importing it never breaks the bare-interpreter CI
import gate) and evidence-based -- every positive decision records the concrete
signal that produced it, and those signals are shown to the operator on refusal.

* **Containers** -- ``/.dockerenv`` (Docker), ``/run/.containerenv`` (Podman),
  the ``docker``/``kubepods``/``containerd``/``lxc``/``podman``/``crio`` tokens
  in ``/proc/*/cgroup``, the ``container=`` marker in the environment or in
  ``/proc/1/environ``, and ``KUBERNETES_SERVICE_HOST``.
* **Virtual machines** -- the ``hypervisor`` CPU flag in ``/proc/cpuinfo`` (set
  under any hypervisor), the DMI vendor/product strings under
  ``/sys/class/dmi/id`` (VMware / VirtualBox / KVM / QEMU / Xen / Hyper-V / EC2 /
  GCE / OpenStack / Parallels), and ``/proc/xen``. On Windows and macOS -- where
  ``/proc`` and ``/sys`` do not exist -- a short, timeout-bounded WMI / sysctl
  probe is used, and anything inconclusive is treated as *bare metal* (refused),
  so the default is fail-closed.

Escape hatch: set ``FILE_ANALYZER_ALLOW_BARE_METAL=1`` (or ``true``/``yes``/
``on``) to deliberately bypass the guard. This is an explicit, logged operator
opt-out for the rare case of an already-isolated bare-metal box; the default
posture without it is to refuse.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

#: Deliberate operator opt-out. Accepts 1/true/yes/on (case-insensitive).
OVERRIDE_ENV = "FILE_ANALYZER_ALLOW_BARE_METAL"

#: Exit code used when the guard refuses to run on bare metal.
BARE_METAL_EXIT_CODE = 3

_TRUE = {"1", "true", "yes", "on"}

# DMI / vendor substrings -> a friendly hypervisor name.
_VM_VENDOR_MARKERS: Tuple[Tuple[str, str], ...] = (
    ("vmware", "vmware"),
    ("virtualbox", "virtualbox"),
    ("innotek", "virtualbox"),
    ("kvm", "kvm"),
    ("qemu", "qemu"),
    ("bochs", "qemu"),
    ("xen", "xen"),
    # NB: match the Hyper-V *guest* signature (Model == "Virtual Machine"), never
    # the "Microsoft Corporation" manufacturer alone -- that is also a physical
    # Surface device, which is bare metal.
    ("hyper-v", "hyper-v"),
    ("virtual machine", "hyper-v"),
    ("amazon ec2", "aws"),
    ("google", "gce"),
    ("googlecomputeengine", "gce"),
    ("openstack", "openstack"),
    ("parallels", "parallels"),
    ("bhyve", "bhyve"),
    ("apple virtualization", "apple-vz"),
)

# cgroup tokens -> container runtime name.
_CGROUP_MARKERS: Tuple[Tuple[str, str], ...] = (
    ("docker", "docker"),
    ("kubepods", "kubernetes"),
    ("containerd", "containerd"),
    ("libpod", "podman"),
    ("podman", "podman"),
    ("crio", "cri-o"),
    ("lxc", "lxc"),
    ("garden", "garden"),
    ("ecs", "ecs"),
)


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def _override_active() -> bool:
    return os.environ.get(OVERRIDE_ENV, "").strip().lower() in _TRUE


# ---------------------------------------------------------------------------
# Container detection
# ---------------------------------------------------------------------------
def detect_container() -> Tuple[Optional[str], List[str]]:
    """Return ``(runtime_name_or_None, [evidence, ...])``."""
    signals: List[str] = []
    kind: Optional[str] = None

    if Path("/.dockerenv").exists():
        signals.append("/.dockerenv present")
        kind = kind or "docker"
    if Path("/run/.containerenv").exists():
        signals.append("/run/.containerenv present")
        kind = kind or "podman"

    for cg in ("/proc/1/cgroup", "/proc/self/cgroup"):
        data = _read_text(cg).lower()
        if not data:
            continue
        for token, name in _CGROUP_MARKERS:
            if token in data:
                signals.append(f"{cg} mentions '{token}'")
                kind = kind or name

    cenv = os.environ.get("container", "").strip()
    if cenv:
        signals.append(f"environment container={cenv}")
        kind = kind or (cenv if cenv.isalpha() else "container")

    if "container=" in _read_text("/proc/1/environ"):
        signals.append("/proc/1/environ sets container=")
        kind = kind or "container"

    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        signals.append("KUBERNETES_SERVICE_HOST set")
        kind = kind or "kubernetes"

    return kind, signals


# ---------------------------------------------------------------------------
# Virtual-machine detection
# ---------------------------------------------------------------------------
def _detect_vm_linux() -> Tuple[Optional[str], List[str]]:
    signals: List[str] = []
    kind: Optional[str] = None

    cpuinfo = _read_text("/proc/cpuinfo")
    if re.search(r"^flags\s*:.*\bhypervisor\b", cpuinfo, re.MULTILINE):
        signals.append("/proc/cpuinfo has the 'hypervisor' CPU flag")
        kind = "hypervisor"

    for field in ("product_name", "sys_vendor", "bios_vendor", "product_version"):
        val = _read_text(f"/sys/class/dmi/id/{field}").strip()
        if not val:
            continue
        low = val.lower()
        for needle, name in _VM_VENDOR_MARKERS:
            if needle in low:
                signals.append(f"DMI {field}={val!r}")
                kind = kind or name

    if Path("/proc/xen").exists():
        signals.append("/proc/xen present")
        kind = kind or "xen"

    # systemd's own detector, when present, is authoritative.
    virt = _run(["systemd-detect-virt", "--vm", "--quiet"])
    if virt is not None and virt.returncode == 0:
        name = _run(["systemd-detect-virt", "--vm"])
        detected = (name.stdout.strip() if name else "") or "vm"
        signals.append(f"systemd-detect-virt: {detected}")
        kind = kind or detected

    return kind, signals


def _detect_vm_windows() -> Tuple[Optional[str], List[str]]:
    signals: List[str] = []
    kind: Optional[str] = None
    # Query the computer-system manufacturer/model via CIM (WMI). wmic is gone on
    # Windows 11, so use PowerShell. Fail-closed: any error -> treat as bare metal.
    ps = _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$c = Get-CimInstance Win32_ComputerSystem;"
            " Write-Output ($c.Manufacturer + '|' + $c.Model)",
        ]
    )
    if ps is not None and ps.returncode == 0 and ps.stdout.strip():
        raw = ps.stdout.strip()
        low = raw.lower()
        for needle, name in _VM_VENDOR_MARKERS:
            if needle in low:
                signals.append(f"Win32_ComputerSystem={raw!r}")
                kind = kind or name
    return kind, signals


def _detect_vm_darwin() -> Tuple[Optional[str], List[str]]:
    signals: List[str] = []
    kind: Optional[str] = None
    # macOS: kern.hv_vmm_present == 1 inside a guest (Apple Hypervisor / VMware /
    # Parallels). Fail-closed on any error.
    res = _run(["sysctl", "-n", "kern.hv_vmm_present"])
    if res is not None and res.returncode == 0 and res.stdout.strip() == "1":
        signals.append("sysctl kern.hv_vmm_present=1")
        kind = "hypervisor"
    return kind, signals


def detect_virtual_machine() -> Tuple[Optional[str], List[str]]:
    """Return ``(vm_name_or_None, [evidence, ...])`` for the current OS."""
    system = platform.system()
    if system == "Linux":
        return _detect_vm_linux()
    if system == "Windows":
        return _detect_vm_windows()
    if system == "Darwin":
        return _detect_vm_darwin()
    return None, []


def _run(
    cmd: List[str], timeout: float = 5.0
) -> Optional["subprocess.CompletedProcess"]:
    """Best-effort subprocess call; ``None`` if the tool is missing or times out."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def inspect_environment() -> Dict[str, Any]:
    """Full detection result: what we are running inside, with the evidence."""
    container, c_signals = detect_container()
    vm, v_signals = detect_virtual_machine()
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "container": container,
        "virtual_machine": vm,
        "virtualized": bool(container or vm),
        "override": _override_active(),
        "signals": c_signals + v_signals,
    }


def _refusal_message(info: Dict[str, Any]) -> str:
    lines = [
        "",
        "=" * 72,
        " REFUSING TO RUN ON BARE-METAL HARDWARE",
        "=" * 72,
        " This tool is only permitted inside a container (Docker / Podman /",
        " containerd / LXC / Kubernetes) or a virtual machine -- not directly on",
        " the host operating system's physical hardware.",
        "",
        f" Detected platform : {info['platform']}",
        " No container or VM signal was found on this host.",
        "",
        " Run it in one of these instead, for example:",
        "   docker compose run --rm analyzer <args>",
        '   docker run --rm -v "$PWD:/work" -w /work <image> python -m file_analyzer.main ...',
        "",
        f" Deliberate override (already-isolated bare-metal box only): set"
        f" {OVERRIDE_ENV}=1",
        "=" * 72,
        "",
    ]
    return "\n".join(lines)


def require_virtualized(context: str = "", stream=None) -> Dict[str, Any]:
    """Enforce the guard. Return the detection info, or exit the process.

    If an explicit override is set, it is honoured (and noted on ``stream``).
    Otherwise, when neither a container nor a VM is detected, a detailed refusal
    is written to ``stream`` (default: stderr) and the process exits with
    :data:`BARE_METAL_EXIT_CODE`. On success the detection info is returned so a
    caller can log where it is running.
    """
    stream = stream if stream is not None else sys.stderr
    if _override_active():
        info = inspect_environment()
        stream.write(
            f"[runtime-guard] {OVERRIDE_ENV} set -- bypassing the bare-metal "
            f"guard ({context or 'entrypoint'}).\n"
        )
        return info

    info = inspect_environment()
    if info["virtualized"]:
        return info

    stream.write(_refusal_message(info))
    raise SystemExit(BARE_METAL_EXIT_CODE)
