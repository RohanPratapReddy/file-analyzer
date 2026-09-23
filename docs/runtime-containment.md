# Runtime containment — container / VM only

Every **runnable** `file-analyzer` entrypoint — the CLI, the background monitor,
and the **MCP server** — **refuses to run directly on bare-metal host hardware**.
They start only inside a **container** (Docker / Podman / containerd / LXC /
Kubernetes) or a **virtual machine**. When neither is detected, the process writes
a refusal banner to stderr and exits with code **`3`**.

**The one exception is the SDK.** Importing the engine facade and using its classes
and functions as a library (`import file_analyzer.engine`, `AnalysisEngine(...)`,
`scrub(...)`, …) does **not** trigger the guard — an embedding application owns its
own isolation. Only the surfaces that *run the tool for you* (CLI / monitor / MCP)
are contained.

This is a real, evidence-based, stdlib-only check — no stubs. It lives in
[`file_analyzer/runtime_guard.py`](../packages/client/file_analyzer/runtime_guard.py) and is enforced at the
start of each runnable entrypoint.

## Why

The engine walks arbitrary repositories and shells out to optional toolchains
(the Go builder, OCR, document parsers). Pinning execution to a container or VM
keeps that work inside a disposable, isolated boundary instead of the operator's
own OS — a defense-in-depth default. The engine already never executes analyzed
code and never stores raw payloads; the containment guard adds an isolation floor
on top of that.

## What is guarded

| Entrypoint | Command forms | Guarded |
|------------|---------------|:-------:|
| Full pipeline | `python -m file_analyzer.main …`, `file-analyzer …` | ✅ |
| Background monitor | `python -m file_analyzer …`, `file-analyzer-monitor …` | ✅ |
| MCP server | `python -m mcp_server`, `file-analyzer-mcp` | ✅ |
| Database-hosting server | `file-analyzer-server run/start …`, `python -m file_analyzer.server …`, `FileAnalyzerServer.serve()` / `start()` | ✅ (serving only; `--no-contain` / `contained=False` when the caller owns isolation) |
| SDK (library import) | `import file_analyzer.engine`, `AnalysisEngine(...)`, `scrub(...)` | ❌ (by design — caller owns isolation) |

`--help` and `--version` are **always exempt**: they print and exit before the
guard runs, so you can inspect the flag surface and read the version on any host.
For the full pipeline, everything past `--help` — including `--list-components` and
component mode — is behind the guard. For the MCP server, `--version` and
`--precompile` are exempt (the latter is a build-time warm-up meant for a
`Dockerfile` / CI, where `/.dockerenv` is not yet present during `docker build`);
actually **serving** the tools is guarded.

## How detection works

`inspect_environment()` returns a dict — `{platform, system, container,
virtual_machine, virtualized, override, signals}` — and every positive decision
records the concrete **signal** that produced it. Those signals are printed on
refusal so the decision is auditable.

### Container detection (`detect_container()`)

- `/.dockerenv` (Docker) and `/run/.containerenv` (Podman) marker files.
- Runtime tokens in `/proc/1/cgroup` and `/proc/self/cgroup`:
  `docker`, `kubepods`, `containerd`, `libpod`/`podman`, `crio`, `lxc`, `garden`, `ecs`.
- The `container=` variable in the environment and in `/proc/1/environ`.
- `KUBERNETES_SERVICE_HOST` (in-cluster pods).

### Virtual-machine detection (`detect_virtual_machine()`)

- **Linux** — the `hypervisor` CPU flag in `/proc/cpuinfo` (set under any
  hypervisor; primary signal), DMI vendor/product strings under
  `/sys/class/dmi/id/*` (VMware, VirtualBox, KVM, QEMU, Xen, Hyper-V, Amazon EC2,
  GCE, OpenStack, Parallels, bhyve, Apple Virtualization), `/proc/xen`, and
  `systemd-detect-virt` when present.
- **Windows** — a short, timeout-bounded PowerShell CIM query of
  `Win32_ComputerSystem` (Manufacturer + Model). *Fail-closed*: any error or an
  inconclusive result is treated as bare metal. Note it deliberately matches the
  Hyper-V **guest** signature (`Model == "Virtual Machine"`), never the
  `Microsoft Corporation` manufacturer alone — that is also a physical Surface
  device, which is bare metal.
- **macOS** — `sysctl -n kern.hv_vmm_present` (`1` inside a guest). Fail-closed on
  any error.

The default posture is **fail-closed**: if nothing proves a container or VM, the
guard refuses.

## The override

For the rare case of an already-isolated bare-metal box, set the environment
variable to bypass the guard:

```bash
export FILE_ANALYZER_ALLOW_BARE_METAL=1     # also accepts true / yes / on (any case)
python -m file_analyzer.main . --out ./artifacts
```

The bypass is **explicit and logged** — a one-line notice goes to stderr:

```
[runtime-guard] FILE_ANALYZER_ALLOW_BARE_METAL set -- bypassing the bare-metal guard (file_analyzer.main).
```

## What refusal looks like

On bare metal without the override, stderr shows:

```
========================================================================
 REFUSING TO RUN ON BARE-METAL HARDWARE
========================================================================
 This tool is only permitted inside a container (Docker / Podman /
 containerd / LXC / Kubernetes) or a virtual machine -- not directly on
 the host operating system's physical hardware.

 Detected platform : <your platform string>
 No container or VM signal was found on this host.

 Run it in one of these instead, for example:
   docker compose run --rm analyzer <args>
   docker run --rm -v "$PWD:/work" -w /work <image> python -m file_analyzer.main ...

 Deliberate override (already-isolated bare-metal box only): set
 FILE_ANALYZER_ALLOW_BARE_METAL=1
========================================================================
```

…and the process exits with code **`3`** (`BARE_METAL_EXIT_CODE`).

## Satisfying the guard

The recommended path is the containerized **`engine`** service — it runs inside
Docker, so the guard is satisfied automatically:

```bash
# full pipeline in a container (see USAGE.md Part 3 and the README Docker section)
SOURCE_DIR=/path/to/repo ARTIFACTS_DIR=./artifacts \
  docker compose --profile engine run --build engine \
    /workspace --out /artifacts --quiet

# or a plain docker run
docker run --rm -v "$PWD:/work" -w /work file-analyzer \
  python -m file_analyzer.main /work --out /work/artifacts --quiet
```

The database-hosting server has its own image (Dockerfile `server` target, compose
profile `server`). It serves as the unprivileged `fa` user (uid 10001) under
`tini`, so the guard passes and the process holds no root inside the container
either; see [server.md](server.md#running-it-in-docker). Its admin subcommands
(`status`, `check`, `backup-verify`, `maintain`, …) serve nothing and are not
gated.

Any VM (VMware, VirtualBox, KVM/QEMU, Hyper-V guest, a cloud instance such as EC2 /
GCE, WSL2, …) also satisfies the guard with no extra flags.

## Programmatic use

Importing the `file_analyzer` package as a library does **not** trigger the guard — only the
runnable entrypoints (`file_analyzer.main:run`, `file_analyzer.__main__:main`, and
`mcp_server:main`) enforce it. Library callers that want the same policy can call it
explicitly:

```python
from file_analyzer.runtime_guard import require_virtualized, inspect_environment

info = inspect_environment()          # inspect without enforcing
require_virtualized(context="my-app") # enforce: returns info, or SystemExit(3)
```

## Verifying

The enforcement contract is pinned by
[`tests/test_runtime_guard.py`](../tests/test_runtime_guard.py) (the detectors are
monkeypatched so refuse / allow / override behaviour is deterministic on any host),
and the real detection path is exercised for real by the CI smoke commands, which
run under Docker (where `virtualized` is `true`, so the commands proceed).

## Related

- [`USAGE.md`](USAGE.md) — the full CLI reference and exit-code table (code `3` is
  the containment refusal).
- [`../README.md`](../README.md) — project overview and the Docker workflow that
  satisfies the guard.
- [`server.md`](server.md) — the database-hosting server and its Docker profile.
