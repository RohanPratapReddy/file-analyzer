"""
file_analyzer.sdk -- a high-level, object-oriented SDK surface over the platform.

Everything here is a *thin but real* facade over machinery that already exists in
the package; nothing is stubbed, mocked, or faked. Each class delegates to the
concrete implementation it names:

    FileAnalyzerClient    -> file_analyzer.core.analysis_engine.AnalysisEngine
                             (+ file_analyzer.main.list_components / run_component)
    AnalysisResult        -> the dict AnalysisEngine.run() returns, plus a live
                             FileAnalyzerDatabase handle on the produced .db
    FileAnalyzerDatabase  -> read-only sqlite query + view readers, defined in the
                             client wheel (file_analyzer.client) and re-exported
                             here so the engine SDK exposes the same handle type
    FileAnalyzerMCPServer -> the MCP server module (mcp_server) -- serve / warm /
                             precompile / call a tool in-process (agent API +
                             MCP transport that BUILDS databases)
    FileAnalyzerAgent     -> file_analyzer.document.agent_mcp AgentRegistry /
                             AgentConnector (LLM + MCP transports)
    FileAnalyzerMonitor   -> file_analyzer.monitor background repository watcher

The database-**hosting** server (``FileAnalyzerServer``) lives in a separate wheel,
``file-analyzer-server`` (``file_analyzer.server``); :meth:`FileAnalyzerClient.server`
lazily imports it and raises a helpful error when that wheel is not installed. This
keeps the engine wheel free of the hosting server's surface and vice versa.

Design rules that keep this file honest:

* **No re-implementation.** The classes call the same functions the CLI and MCP
  server call, so behaviour cannot drift from the rest of the platform.
* **Cheap import.** Every heavy dependency is imported lazily inside the method
  that needs it. Importing this module (and therefore ``import file_analyzer.engine``)
  never pulls in the analyzer fleet, the ``mcp`` package, or a network client.
* **Containment stays a library caller's choice.** Using the SDK never trips the
  bare-metal guard by default (an embedding app owns its own isolation); pass
  ``require_containment=True`` to opt a client into the same policy the CLI and
  MCP server enforce.
"""

from __future__ import annotations

import io
import json
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from ._version import __version__

# FileAnalyzerDatabase + the read-only opener live in the client wheel (pure
# stdlib foundation). Re-export them so the engine SDK hands out the same handle
# type a client-only install would, with a single source of truth.
from .client import FileAnalyzerDatabase, open_database

__all__ = [
    "FileAnalyzerClient",
    "FileAnalyzerMCPServer",
    "FileAnalyzerAgent",
    "FileAnalyzerMonitor",
    "FileAnalyzerDatabase",
    "AnalysisResult",
    "analyze",
    "open_database",
]

PathLike = Union[str, Path]


# ======================================================================
# AnalysisResult -- the run summary plus a live database handle
# ======================================================================
class AnalysisResult:
    """The result of one :meth:`FileAnalyzerClient.analyze` run.

    Wraps the summary dict ``AnalysisEngine.run()`` returns and exposes the
    salient fields as attributes, while still behaving like the underlying dict
    (``result["file_count"]``, ``result.get(...)``, ``dict(result)``).
    """

    def __init__(self, summary: Dict[str, Any]):
        self._summary = dict(summary)

    # -- attribute access over the well-known keys --------------------
    @property
    def summary(self) -> Dict[str, Any]:
        """The raw summary dict, copied."""
        return dict(self._summary)

    @property
    def database(self) -> str:
        return self._summary["database"]

    @property
    def sql_dump(self) -> str:
        return self._summary.get("sql_dump", "")

    @property
    def repository_root(self) -> str:
        return self._summary.get("repository_root", "")

    @property
    def file_count(self) -> int:
        return int(self._summary.get("file_count", 0))

    @property
    def views(self) -> List[str]:
        return list(self._summary.get("views_installed", []))

    @property
    def database_path(self) -> Path:
        """The produced database path as a :class:`~pathlib.Path`."""
        return Path(self.database)

    def open(self) -> FileAnalyzerDatabase:
        """Open the produced database read-only for querying."""
        return FileAnalyzerDatabase(self.database)

    def save(self, path: PathLike) -> Path:
        """Write the run summary to ``path`` as pretty JSON; return the path."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self._summary, indent=2, default=str), encoding="utf-8")
        return p

    # -- dict passthrough --------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return dict(self._summary)

    def __getitem__(self, key: str) -> Any:
        return self._summary[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._summary.get(key, default)

    def keys(self):  # enables dict(result)
        return self._summary.keys()

    def __iter__(self):
        return iter(self._summary)

    def __contains__(self, key: object) -> bool:
        return key in self._summary

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"AnalysisResult(database={self.database!r}, "
            f"file_count={self.file_count}, views={len(self.views)})"
        )


# ======================================================================
# FileAnalyzerClient -- the primary entry point
# ======================================================================
class FileAnalyzerClient:
    """The main object-oriented entry point to the analysis pipeline.

    A client carries default concurrency knobs and an optional containment
    policy, then produces :class:`AnalysisResult` objects from repositories and
    hands out the other SDK facades (:meth:`database`, :meth:`agent`,
    :meth:`monitor`, :meth:`server`).

    ``require_containment=True`` makes :meth:`analyze` and :meth:`run_component`
    enforce the same bare-metal guard the CLI/MCP server use (refusing outside a
    container or VM). It is off by default: using the SDK as a library never
    trips the guard, because an embedding application owns its own isolation.
    """

    def __init__(
        self,
        *,
        require_containment: bool = False,
        workers: Optional[int] = None,
        plane_workers: Optional[int] = None,
        injection_workers: Optional[int] = None,
    ):
        self.require_containment = bool(require_containment)
        self.workers = workers
        self.plane_workers = plane_workers
        self.injection_workers = injection_workers

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"FileAnalyzerClient(require_containment={self.require_containment}, "
            f"version={__version__!r})"
        )

    @property
    def version(self) -> str:
        return __version__

    def _guard(self, context: str) -> None:
        if self.require_containment:
            from .runtime_guard import require_virtualized

            require_virtualized(context=context)

    # -- the pipeline -------------------------------------------------
    def analyze(
        self,
        path: PathLike = ".",
        *,
        out_dir: Optional[PathLike] = None,
        db_path: Optional[PathLike] = None,
        sql_path: Optional[PathLike] = None,
        dialect: str = "sqlite",
        no_git: bool = False,
        git_tracked: Optional[bool] = None,
        temp_dir: Optional[PathLike] = None,
        keep_temp: bool = False,
        **engine_kwargs: Any,
    ) -> AnalysisResult:
        """Analyze ``path`` and return an :class:`AnalysisResult`.

        ``out_dir`` (when given) is where the ``.db`` / ``.sql`` land; otherwise
        they default to ``repository.db`` / ``repository_schema.sql`` in the
        current directory (the engine's own defaults). ``db_path`` / ``sql_path``
        override those names (resolved under ``out_dir`` when relative). Any extra
        keyword is forwarded verbatim to :class:`AnalysisEngine` -- e.g.
        ``enable_mcp_enrichment=True``, ``enable_dynamic_database=True``,
        ``agents_include=[...]``.
        """
        from .core.analysis_engine import AnalysisEngine

        self._guard("file_analyzer.sdk.analyze")

        src = Path(path).resolve()
        out = Path(out_dir).resolve() if out_dir is not None else None
        if out is not None:
            out.mkdir(parents=True, exist_ok=True)

        def _resolve(explicit: Optional[PathLike], default_name: str) -> Path:
            if explicit is not None:
                p = Path(explicit)
                if not p.is_absolute() and out is not None:
                    p = out / p
                return p
            base = out if out is not None else Path.cwd()
            return base / default_name

        db = _resolve(db_path, "repository.db")
        sql = _resolve(sql_path, "repository_schema.sql")

        if git_tracked is None:
            git_tracked = not no_git

        engine = AnalysisEngine(
            dir_path=src,
            db_path=db,
            sql_path=sql,
            temp_dir=temp_dir,
            sql_dialect=dialect,
            git_tracked=git_tracked,
            workers=self.workers,
            plane_workers=self.plane_workers,
            injection_workers=self.injection_workers,
            keep_temp_on_success=keep_temp,
            **engine_kwargs,
        )
        return AnalysisResult(engine.run())

    def analyze_many(
        self,
        paths: Iterable[PathLike],
        *,
        out_dir: Optional[PathLike] = None,
        **engine_kwargs: Any,
    ) -> List[AnalysisResult]:
        """Analyze several repositories and return one result per path.

        Each repository gets its own subdirectory under ``out_dir`` (named after
        the repo's basename, de-duplicated) so their ``.db`` / ``.sql`` artifacts
        never collide. Without ``out_dir`` the engine's per-run defaults apply.
        Extra keywords are forwarded to :meth:`analyze` for every repository.
        """
        base = Path(out_dir).resolve() if out_dir is not None else None
        results: List[AnalysisResult] = []
        seen: Dict[str, int] = {}
        for path in paths:
            sub: Optional[Path] = None
            if base is not None:
                stem = Path(path).resolve().name or "repo"
                n = seen.get(stem, 0)
                seen[stem] = n + 1
                sub = base / (stem if n == 0 else f"{stem}-{n}")
            results.append(self.analyze(path, out_dir=sub, **engine_kwargs))
        return results

    # -- open an existing database -----------------------------------
    def open(self, db_path: PathLike) -> FileAnalyzerDatabase:
        """Open a previously produced database read-only."""
        return FileAnalyzerDatabase(db_path)

    # alias -- reads more naturally in some call sites
    database = open

    # -- environment / policy introspection --------------------------
    def environment(self) -> Dict[str, Any]:
        """Probe the runtime: container/VM detection, platform, override state.

        Returns :func:`file_analyzer.runtime_guard.inspect_environment`'s dict.
        This never enforces the guard -- it only reports what the guard *would*
        see -- so it is safe to call from anywhere, bare metal included.
        """
        from .runtime_guard import inspect_environment

        return inspect_environment()

    def acceptable_use(self) -> str:
        """Return the acceptable-use banner (the platform's IP-safety notice)."""
        from .core.guardrails import acceptable_use_banner

        return acceptable_use_banner()

    # -- component mode ----------------------------------------------
    def list_components(self) -> Dict[str, Any]:
        """Enumerate every valid :meth:`run_component` name, grouped by kind."""
        from .main import list_components

        return list_components()

    def run_component(
        self,
        component: str,
        path: PathLike = ".",
        *,
        out_dir: Optional[PathLike] = None,
        no_git: bool = False,
        mapping: bool = False,
        tables_json: Optional[PathLike] = None,
        build_db: bool = False,
    ) -> Dict[str, Any]:
        """Run a single analyzer block and return its tables as structured data.

        This drives the very same code path as
        ``python -m file_analyzer.main --component <name>`` (see
        :meth:`list_components`): a plane, a language ``{Lang}Analyzer``,
        ``census``, ``linkage`` or ``dbgen``. Returns
        ``{"summary": {...}, "tables": {...}, "emit_path": "..."}`` -- the block's
        run summary plus the emitted tables loaded back as JSON. ``linkage`` and
        ``dbgen`` require ``tables_json``.
        """
        from . import main as _main

        self._guard("file_analyzer.sdk.run_component")

        # A scratch output dir so the component's emitted JSON has somewhere to
        # land when the caller does not care to keep it.
        cleanup_dir: Optional[tempfile.TemporaryDirectory] = None
        if out_dir is not None:
            out = Path(out_dir).resolve()
            out.mkdir(parents=True, exist_ok=True)
        else:
            cleanup_dir = tempfile.TemporaryDirectory(prefix="fa-component-")
            out = Path(cleanup_dir.name)

        emit = out / f"{component}_analysis.json"
        argv: List[str] = [
            str(Path(path).resolve()),
            "--component",
            component,
            "--out",
            str(out),
            "--emit",
            str(emit),
            "--quiet",
        ]
        if no_git:
            argv.append("--no-git")
        if mapping:
            argv.append("--mapping")
        if build_db:
            argv.append("--build-db")
        if tables_json is not None:
            argv += ["--tables-json", str(Path(tables_json).resolve())]

        args = _main.build_parser().parse_args(argv)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = _main.run_component(args)
            if rc != 0:
                raise RuntimeError(
                    f"component {component!r} failed with exit code {rc}"
                )
            try:
                summary = json.loads(buf.getvalue() or "{}")
            except json.JSONDecodeError:
                summary = {"stdout": buf.getvalue()}
            tables: Any = None
            emit_from_summary = (
                summary.get("emit_path") if isinstance(summary, dict) else None
            )
            emit_path = Path(emit_from_summary) if emit_from_summary else emit
            if emit_path.is_file():
                tables = json.loads(emit_path.read_text(encoding="utf-8"))
            return {
                "summary": summary,
                "tables": tables,
                "emit_path": str(emit_path),
            }
        finally:
            if cleanup_dir is not None:
                cleanup_dir.cleanup()

    # -- facades over the other layers -------------------------------
    def agent(self, **kwargs: Any) -> "FileAnalyzerAgent":
        """Construct a :class:`FileAnalyzerAgent` (LLM + MCP transports)."""
        return FileAnalyzerAgent(**kwargs)

    def monitor(self, path: PathLike, **kwargs: Any) -> "FileAnalyzerMonitor":
        """Construct a :class:`FileAnalyzerMonitor` for ``path`` (not started)."""
        return FileAnalyzerMonitor(path, **kwargs)

    def mcp_server(self) -> "FileAnalyzerMCPServer":
        """Construct a :class:`FileAnalyzerMCPServer` around the MCP server module."""
        return FileAnalyzerMCPServer()

    def server(self, path: Optional[PathLike] = None, **kwargs: Any) -> Any:
        """Construct a database-hosting ``FileAnalyzerServer`` for a repo.

        The hosting server ships in a separate wheel, ``file-analyzer-server``;
        it is imported lazily here so the engine wheel never depends on it. When
        that wheel is not installed this raises a ``RuntimeError`` naming the
        install command. Defaults to the client's analysis target (``.`` unless
        overridden); see ``file_analyzer.server.FileAnalyzerServer`` for options.
        """
        try:
            from .server import FileAnalyzerServer
        except ImportError as exc:
            raise RuntimeError(
                "the database-hosting server requires the 'file-analyzer-server' "
                "wheel; install it with: pip install file-analyzer-server"
            ) from exc
        return FileAnalyzerServer(path if path is not None else ".", **kwargs)


# ======================================================================
# FileAnalyzerMCPServer -- object facade over the MCP server module
# ======================================================================
class FileAnalyzerMCPServer:
    """Object-oriented control of the file-analyzer MCP server.

    Wraps the ``mcp_server`` module (which needs the optional ``mcp`` package).
    You can :meth:`serve` the tools over stdio, :meth:`warm` the analyzer fleet
    in the background, :meth:`precompile` it synchronously (build-time warm-up),
    or :meth:`call` any tool in-process without standing up a server at all.
    """

    #: The tools the server exposes (module-level callables on ``mcp_server``).
    TOOL_NAMES: Tuple[str, ...] = (
        "server_info",
        "analyze_repository",
        "query",
        "list_views",
        "read_views",
        "describe_schema",
        "run_component",
        "list_components",
        "start_monitor",
        "stop_monitor",
        "monitor_status",
        "recent_changes",
        "scan_now",
        "change_history",
        "log_session",
        "assess_last_session",
        "recent_sessions",
    )

    def __init__(self) -> None:
        self._module: Any = None

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"FileAnalyzerMCPServer(version={__version__!r})"

    def _mod(self) -> Any:
        """Import and cache the ``mcp_server`` module (needs ``mcp`` installed)."""
        if self._module is None:
            try:
                import mcp_server  # noqa: F401  (repo-root module)
            except ImportError as exc:  # pragma: no cover - env-dependent
                raise RuntimeError(
                    "the MCP server requires the optional 'mcp' package; "
                    'install it with: pip install "mcp[cli]>=1.2,<2"'
                ) from exc
            self._module = mcp_server
        return self._module

    @property
    def version(self) -> str:
        return __version__

    def tools(self) -> List[str]:
        """The names of the tools the server exposes."""
        return list(self.TOOL_NAMES)

    def precompile(self) -> None:
        """Warm the analyzer fleet synchronously and return (build-time warm-up)."""
        self._mod().warm_cache()

    def warm(self):
        """Warm the analyzer fleet in a background thread; returns the thread."""
        return self._mod()._start_warm_cache()

    def call(self, name: str, /, **kwargs: Any) -> Any:
        """Invoke one MCP tool in-process by name (no server needed).

        Runs the exact function the served tool would run -- e.g.
        ``server.call("query", sql="SELECT * FROM v_file_inventory",
        db_path="repository.db")``.
        """
        if name not in self.TOOL_NAMES:
            raise ValueError(
                f"unknown tool {name!r}; valid tools: {', '.join(self.TOOL_NAMES)}"
            )
        fn = getattr(self._mod(), name)
        return fn(**kwargs)

    def serve(self, *, warm: bool = True, contained: bool = True) -> None:
        """Serve the MCP tools over stdio. Blocks until the server stops.

        With ``contained=True`` (the default) the bare-metal containment guard is
        enforced first -- serving runs the analysis engine, so it is only allowed
        inside a container or VM, exactly like ``python -m mcp_server``. Set
        ``contained=False`` only when the caller already owns its isolation.
        """
        mod = self._mod()
        if contained:
            from .runtime_guard import require_virtualized

            require_virtualized(context="mcp_server")
        if warm:
            mod._start_warm_cache()
        mod.mcp.run()


# ======================================================================
# FileAnalyzerAgent -- LLM + MCP provider facade
# ======================================================================
class FileAnalyzerAgent:
    """A uniform ``chat`` / ``call_tool`` client over configured agent providers.

    Wraps :class:`~file_analyzer.document.agent_mcp.AgentRegistry` and its
    :class:`AgentConnector`. Providers come from the built-in specs (env-driven
    HTTP LLMs) and, with ``discover=True``, from desktop/CLI-configured MCP
    servers. ``include`` / ``exclude`` narrow the set (soft, case-insensitive);
    ``roster`` is an ordered preference string used to pick a default provider.
    """

    def __init__(
        self,
        *,
        specs: Optional[List[Any]] = None,
        timeout: float = 60.0,
        discover: bool = False,
        project_dir: Optional[str] = None,
        include: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
        roster: Optional[str] = None,
    ):
        self._specs = specs
        self.timeout = timeout
        self.discover = discover
        self.project_dir = project_dir
        self.include = list(include) if include else None
        self.exclude = list(exclude) if exclude else None
        self.roster = (
            [r.strip() for r in roster.split(",") if r.strip()] if roster else None
        )
        self._registry: Any = None
        self._connectors: Dict[str, Any] = {}

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"FileAnalyzerAgent(providers={self.providers()})"

    def _registry_obj(self) -> Any:
        if self._registry is None:
            from .document.agent_mcp import AgentRegistry

            reg = AgentRegistry(
                specs=self._specs,
                timeout=self.timeout,
                discover=self.discover,
                project_dir=self.project_dir,
            )
            if self.include or self.exclude:
                reg = reg.select(include=self.include, exclude=self.exclude)
            self._registry = reg
        return self._registry

    @property
    def registry(self) -> Any:
        """The underlying (filtered) :class:`AgentRegistry`."""
        return self._registry_obj()

    def providers(self) -> List[str]:
        """All configured provider names (after include/exclude)."""
        return self._registry_obj().names()

    def discovered(self) -> List[str]:
        """Names that came from a desktop/CLI MCP config file."""
        return self._registry_obj().discovered()

    def available(self) -> List[str]:
        """Names of providers reachable in this environment right now."""
        return self._registry_obj().available()

    def probe(self) -> List[Dict[str, Any]]:
        """Honest reachability probe for every configured provider."""
        return self._registry_obj().probe_all()

    def connector(self, name: str) -> Any:
        """Return (and cache) the :class:`AgentConnector` for ``name``."""
        if name not in self._connectors:
            self._connectors[name] = self._registry_obj().connector(name)
        return self._connectors[name]

    def _pick(self, provider: Optional[str] = None) -> str:
        """Choose a provider: the explicit one, else the first reachable one.

        When choosing automatically, ``roster`` order is honoured first, then the
        registry's own order. Raises ``ProviderUnavailable`` if none is reachable.
        """
        from .document.agent_mcp import ProviderUnavailable

        if provider:
            return provider
        available = set(self._registry_obj().available())
        if not available:
            raise ProviderUnavailable(
                "no configured agent provider is reachable in this environment"
            )
        order = list(self.roster or []) + [
            n for n in self._registry_obj().names() if n not in (self.roster or [])
        ]
        for name in order:
            if name in available:
                return name
        # Fallback: any reachable name.
        return sorted(available)[0]

    def chat(
        self,
        messages: Union[str, List[Dict[str, str]]],
        *,
        provider: Optional[str] = None,
        system: str = "",
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> Any:
        """One assistant turn. ``messages`` may be a string or a message list.

        Returns the provider's
        :class:`~file_analyzer.document.agent_mcp.ChatResult`.
        """
        if isinstance(messages, str):
            messages = [{"role": "user", "content": messages}]
        name = self._pick(provider)
        return self.connector(name).chat(
            messages,
            system=system,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    def list_tools(self, provider: str) -> List[Dict[str, Any]]:
        """List the MCP tools an MCP-transport provider exposes."""
        return self.connector(provider).list_tools()

    def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        provider: str,
    ) -> Any:
        """Call one MCP tool on ``provider`` -> ``ToolResult``."""
        return self.connector(provider).call_tool(name, arguments)

    def close(self) -> None:
        """Close every connector this agent opened."""
        for conn in self._connectors.values():
            try:
                conn.close()
            except Exception:  # pragma: no cover - best-effort teardown
                pass
        self._connectors.clear()

    def __enter__(self) -> "FileAnalyzerAgent":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


# ======================================================================
# FileAnalyzerMonitor -- background repository watcher facade
# ======================================================================
class FileAnalyzerMonitor:
    """Object control of the background repository monitor for one repo.

    Wraps the process-wide monitor registry in
    :mod:`file_analyzer.monitor.control`. Construction records the root and the
    :class:`RepositoryMonitor` keyword arguments; nothing runs until
    :meth:`start`. Read helpers (:meth:`status`, :meth:`recent_changes`,
    :meth:`change_history`, sessions) work whether or not this process owns the
    monitor, because they read the on-disk diff/log databases directly.
    """

    def __init__(self, path: PathLike, **kwargs: Any):
        self.root = Path(path).resolve()
        self.kwargs = kwargs

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"FileAnalyzerMonitor({str(self.root)!r}, running={self.running})"

    # -- lifecycle ----------------------------------------------------
    def start(self) -> "FileAnalyzerMonitor":
        """Start (or return the already-running) monitor for this repo."""
        from .monitor.control import start_monitor

        start_monitor(self.root, **self.kwargs)
        return self

    def stop(self, timeout: float = 10.0) -> bool:
        """Stop and deregister the monitor. True if one was running."""
        from .monitor.control import stop_monitor

        return stop_monitor(self.root, timeout=timeout)

    @property
    def running(self) -> bool:
        from .monitor.control import get_monitor

        return get_monitor(self.root) is not None

    def scan_now(self) -> Dict[str, Any]:
        """Force one immediate scan cycle. Requires the monitor to be running."""
        from .monitor.control import get_monitor

        mon = get_monitor(self.root)
        if mon is None:
            raise RuntimeError(
                f"no monitor is running for {self.root}; call start() first"
            )
        return mon.scan_once()

    # -- reads (own or observe) --------------------------------------
    def status(self) -> Dict[str, Any]:
        """Live status from the on-disk diff database."""
        from .monitor.control import read_status

        return read_status(root=self.root)

    def recent_changes(self, limit: int = 16) -> Dict[str, Any]:
        """The FIFO ring of the most recent change events."""
        from .monitor.control import read_recent_changes

        return read_recent_changes(root=self.root, limit=limit)

    def change_history(
        self,
        limit: int = 50,
        rel_path: Optional[str] = None,
        url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """The durable, continuous change log (superset of the FIFO ring)."""
        from .monitor.control import read_change_log

        return read_change_log(self.root, url=url, limit=limit, rel_path=rel_path)

    # -- session summaries -------------------------------------------
    def record_session(
        self,
        task_given: str,
        work_done: str,
        files_changed: Optional[Sequence[str]] = None,
        improvements: str = "",
        url: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Record one session summary for this repo. Returns the stored row."""
        from .monitor.control import record_session

        return record_session(
            self.root,
            task_given=task_given,
            work_done=work_done,
            files_changed=files_changed,
            improvements=improvements,
            url=url,
            **kwargs,
        )

    def assess_last_session(
        self,
        next_prompt: str,
        url: Optional[str] = None,
        user_sentiment: Optional[str] = None,
        improvements: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Classify ``next_prompt`` against the most recent pending session."""
        from .monitor.control import assess_last_session

        return assess_last_session(
            self.root,
            next_prompt,
            url=url,
            user_sentiment=user_sentiment,
            improvements=improvements,
        )

    def recent_sessions(
        self, limit: int = 20, url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Read recent session summaries for this repo."""
        from .monitor.control import read_sessions

        return read_sessions(self.root, url=url, limit=limit)

    # -- context manager (stop on exit) ------------------------------
    def __enter__(self) -> "FileAnalyzerMonitor":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


# ======================================================================
# Module-level convenience
# ======================================================================
def analyze(path: PathLike = ".", **kwargs: Any) -> AnalysisResult:
    """One-shot analysis with a default client.

    ``analyze("/repo", enable_mcp_enrichment=True)`` is shorthand for
    ``FileAnalyzerClient().analyze("/repo", enable_mcp_enrichment=True)``.
    """
    return FileAnalyzerClient().analyze(path, **kwargs)
