"""
Multi-provider agent / MCP connector layer for the DocumentParser dynamic plane.

This is the transport that lets the **dynamic layer** (Part B of
``DUMP/document-analysis-engine-metrics.md``) talk to external coding agents and
LLM/VLM backends "back to back": an agent proposes, code validates, errors are
fed back, the agent repairs. It provides two *real* transports, both built on
the standard library alone (so the module imports cleanly on a bare
interpreter, which the CI import gate checks):

* :class:`HttpLLMClient` -- a real HTTP client (``urllib``) speaking the two
  dominant chat schemas: the Anthropic **Messages** API and the **OpenAI
  chat-completions** schema that Grok (xAI), DeepSeek, Moonshot/Kimi and
  Gemini's OpenAI-compatible endpoint all implement.
* :class:`McpStdioClient` -- a real **Model Context Protocol** client speaking
  JSON-RPC 2.0 over a subprocess's stdio (newline-delimited framing, the MCP
  stdio transport): ``initialize`` handshake, ``notifications/initialized``,
  ``tools/list`` and ``tools/call``. This is how CLI agents such as Claude
  Code, the Gemini CLI, OpenCode, Antigravity and a Kimi agent are driven.
* :class:`McpHttpClient` -- the same MCP JSON-RPC 2.0 protocol over the
  **Streamable HTTP** transport (a single POST endpoint that answers with
  either ``application/json`` or an ``text/event-stream`` SSE body, honouring
  the ``Mcp-Session-Id`` header and ``MCP-Protocol-Version`` negotiation).
  This is how *remote* MCP servers and the ones already wired into the Claude
  **desktop** app / ``claude`` CLI are reached -- no separate API key needed,
  because those servers carry their own auth in the config.

Because the desktop app and the ``claude`` CLI already register MCP servers,
:func:`discover_mcp_servers` reads their configuration files
(``claude_desktop_config.json``, ``~/.claude.json``, a project ``.mcp.json``)
and turns each configured server -- stdio *or* http/sse -- into a
:class:`ProviderSpec`, so the dynamic layer can talk to exactly the tools and
agents the user has already connected in the desktop, over MCP, without any new
credentials.

:class:`AgentRegistry` enumerates the named providers with their documented
endpoints / CLI commands (optionally merging the discovered desktop servers)
and **probes reachability honestly**: an HTTP-LLM provider is reachable when its
API key environment variable is set; an MCP-stdio provider is reachable when its
CLI binary is on ``PATH``; an MCP-http provider is reachable when a URL is
configured. Nothing is faked -- an unconfigured provider reports
``reachable = False`` and calling it raises :class:`ProviderUnavailable` rather
than inventing a response. Every base URL, model id, endpoint URL and CLI
command can be overridden by environment variable so the registry maps onto
whatever the operator actually has installed.

Security note: this connector only ever sends the operator's *own* document
context to the operator's *own* configured agents. The "prompt injection" the
dynamic engine performs is internal context injection (folding static-layer
findings and prior-agent outputs into the next prompt), not an attack on a
third party.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ======================================================================
# Errors
# ======================================================================
class AgentError(RuntimeError):
    """Base class for connector failures."""


class ProviderUnavailable(AgentError):
    """Raised when a provider is not configured/reachable in this environment."""


class TransportError(AgentError):
    """Raised when a reachable provider fails mid-exchange (HTTP / RPC error)."""


# ======================================================================
# Result envelopes
# ======================================================================
@dataclass
class ChatResult:
    """One assistant turn plus the bookkeeping the audit tables want."""

    text: str
    provider: str
    model: str
    transport: str
    role: str = "assistant"
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    status: str = "ok"
    error: str = ""
    raw: Optional[Dict[str, Any]] = None


@dataclass
class ToolResult:
    """Result of an MCP ``tools/call``."""

    name: str
    content: str
    provider: str
    is_error: bool = False
    latency_ms: float = 0.0
    status: str = "ok"
    error: str = ""
    raw: Optional[Dict[str, Any]] = None


# ======================================================================
# Provider registry (declarative, env-overridable)
# ======================================================================
@dataclass
class ProviderSpec:
    """Declarative description of one agent/LLM backend.

    ``kind`` selects the transport and wire schema:

    * ``"anthropic"``     -- HTTP, Anthropic Messages schema.
    * ``"openai_compat"`` -- HTTP, OpenAI chat-completions schema.
    * ``"mcp_stdio"``     -- MCP JSON-RPC 2.0 over a subprocess's stdio.
    * ``"mcp_http"``      -- MCP JSON-RPC 2.0 over Streamable HTTP (remote /
      desktop-configured servers).
    """

    name: str
    kind: str
    description: str = ""
    # HTTP-LLM providers
    base_url: str = ""
    api_key_envs: Tuple[str, ...] = ()
    default_model: str = ""
    # env vars that override base_url / model at runtime
    base_url_env: str = ""
    model_env: str = ""
    extra_headers: Dict[str, str] = field(default_factory=dict)
    # MCP-stdio providers
    command: Tuple[str, ...] = ()
    command_env: str = ""  # env var holding a shlex-free space-joined override
    mcp_env: Dict[str, str] = field(default_factory=dict)  # child-process env
    # MCP-http providers (Streamable HTTP)
    url: str = ""
    url_env: str = ""
    headers_env: str = ""  # env var holding a JSON object of extra headers
    # default chat-shaped tool exposed by an MCP server, if any
    mcp_chat_tool: str = ""
    # provenance: "builtin" | "claude_code" | "claude_desktop" | "mcp_json" ...
    source: str = "builtin"
    config_path: str = ""

    # -- resolution against the live environment ----------------------
    def resolved_api_key(self) -> Optional[str]:
        for env in self.api_key_envs:
            val = os.environ.get(env)
            if val:
                return val
        return None

    def resolved_base_url(self) -> str:
        if self.base_url_env and os.environ.get(self.base_url_env):
            return os.environ[self.base_url_env].rstrip("/")
        return self.base_url.rstrip("/")

    def resolved_model(self) -> str:
        if self.model_env and os.environ.get(self.model_env):
            return os.environ[self.model_env]
        return self.default_model

    def resolved_command(self) -> Tuple[str, ...]:
        if self.command_env and os.environ.get(self.command_env):
            return tuple(os.environ[self.command_env].split())
        return self.command

    def resolved_url(self) -> str:
        """Endpoint for an ``mcp_http`` provider (no trailing-slash mangling)."""
        if self.url_env and os.environ.get(self.url_env):
            return os.environ[self.url_env]
        return self.url

    def resolved_headers(self) -> Dict[str, str]:
        """Static headers plus an optional ``headers_env`` JSON override."""
        hdrs = dict(self.extra_headers)
        if self.headers_env and os.environ.get(self.headers_env):
            try:
                extra = json.loads(os.environ[self.headers_env])
                if isinstance(extra, dict):
                    hdrs.update({str(k): str(v) for k, v in extra.items()})
            except ValueError:
                pass
        return hdrs

    def probe(self) -> Dict[str, Any]:
        """Return an honest reachability report for this provider."""
        if self.kind in ("anthropic", "openai_compat"):
            key = self.resolved_api_key()
            reachable = bool(key) and bool(self.resolved_base_url())
            reason = (
                "ok"
                if reachable
                else (
                    "no base url"
                    if not self.resolved_base_url()
                    else "missing api key (" + "/".join(self.api_key_envs) + ")"
                )
            )
            return {
                "name": self.name,
                "kind": self.kind,
                "transport": "http",
                "reachable": reachable,
                "reason": reason,
                "base_url": self.resolved_base_url(),
                "model": self.resolved_model(),
                "binary": None,
            }
        if self.kind == "mcp_stdio":
            cmd = self.resolved_command()
            binary = cmd[0] if cmd else ""
            found = shutil.which(binary) if binary else None
            return {
                "name": self.name,
                "kind": self.kind,
                "transport": "mcp_stdio",
                "reachable": bool(found),
                "reason": "ok" if found else f"binary {binary!r} not on PATH",
                "base_url": None,
                "model": self.resolved_model(),
                "binary": found or binary,
                "command": list(cmd),
                "source": self.source,
            }
        if self.kind == "mcp_http":
            url = self.resolved_url()
            reachable = bool(url)
            return {
                "name": self.name,
                "kind": self.kind,
                "transport": "mcp_http",
                "reachable": reachable,
                "reason": "ok (configured)" if reachable else "no url configured",
                "base_url": url,
                "model": self.resolved_model(),
                "binary": None,
                "source": self.source,
            }
        return {
            "name": self.name,
            "kind": self.kind,
            "transport": "unknown",
            "reachable": False,
            "reason": f"unknown kind {self.kind!r}",
        }


def default_provider_specs() -> List[ProviderSpec]:
    """The named backends the request calls out, with documented defaults.

    Every field is overridable by environment variable so the registry maps
    onto the operator's actual install. HTTP providers all speak either the
    Anthropic or the OpenAI wire schema; CLI agents are driven over MCP stdio.
    """
    return [
        # --- Anthropic / Claude -------------------------------------
        ProviderSpec(
            name="claude",
            kind="anthropic",
            description="Anthropic Claude via the Messages API",
            base_url="https://api.anthropic.com",
            api_key_envs=("ANTHROPIC_API_KEY", "CLAUDE_API_KEY"),
            default_model="claude-sonnet-5",
            base_url_env="ANTHROPIC_BASE_URL",
            model_env="CLAUDE_MODEL",
        ),
        ProviderSpec(
            name="claude_code",
            kind="mcp_stdio",
            description="Claude Code CLI as an MCP server",
            command=("claude", "mcp", "serve"),
            command_env="CLAUDE_CODE_MCP_CMD",
            default_model="claude-code",
            model_env="CLAUDE_CODE_MODEL",
        ),
        # --- Google / Gemini ----------------------------------------
        ProviderSpec(
            name="gemini",
            kind="openai_compat",
            description="Google Gemini via its OpenAI-compatible endpoint",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai",
            api_key_envs=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
            default_model="gemini-2.5-pro",
            base_url_env="GEMINI_BASE_URL",
            model_env="GEMINI_MODEL",
        ),
        ProviderSpec(
            name="gemini_code",
            kind="mcp_stdio",
            description="Gemini CLI in MCP mode",
            command=("gemini", "mcp"),
            command_env="GEMINI_CODE_MCP_CMD",
            default_model="gemini-cli",
            model_env="GEMINI_CODE_MODEL",
        ),
        # --- Antigravity (Google agentic IDE) -----------------------
        ProviderSpec(
            name="antigravity",
            kind="mcp_stdio",
            description="Antigravity desktop agent over MCP",
            command=("antigravity", "mcp"),
            command_env="ANTIGRAVITY_MCP_CMD",
            default_model="antigravity",
            model_env="ANTIGRAVITY_MODEL",
        ),
        # --- xAI / Grok ---------------------------------------------
        ProviderSpec(
            name="grok",
            kind="openai_compat",
            description="xAI Grok (OpenAI-compatible)",
            base_url="https://api.x.ai/v1",
            api_key_envs=("XAI_API_KEY", "GROK_API_KEY"),
            default_model="grok-4",
            base_url_env="XAI_BASE_URL",
            model_env="GROK_MODEL",
        ),
        # --- OpenCode -----------------------------------------------
        ProviderSpec(
            name="opencode",
            kind="mcp_stdio",
            description="OpenCode agent over MCP",
            command=("opencode", "mcp"),
            command_env="OPENCODE_MCP_CMD",
            default_model="opencode",
            model_env="OPENCODE_MODEL",
        ),
        # --- DeepSeek -----------------------------------------------
        ProviderSpec(
            name="deepseek",
            kind="openai_compat",
            description="DeepSeek chat (OpenAI-compatible)",
            base_url="https://api.deepseek.com",
            api_key_envs=("DEEPSEEK_API_KEY",),
            default_model="deepseek-chat",
            base_url_env="DEEPSEEK_BASE_URL",
            model_env="DEEPSEEK_MODEL",
        ),
        # --- Moonshot / Kimi ----------------------------------------
        ProviderSpec(
            name="moonshot",
            kind="openai_compat",
            description="Moonshot Kimi (OpenAI-compatible)",
            base_url="https://api.moonshot.cn/v1",
            api_key_envs=("MOONSHOT_API_KEY", "KIMI_API_KEY"),
            default_model="kimi-k2-0905-preview",
            base_url_env="MOONSHOT_BASE_URL",
            model_env="MOONSHOT_MODEL",
        ),
        ProviderSpec(
            name="kimi_agent",
            kind="mcp_stdio",
            description="Kimi agent CLI over MCP",
            command=("kimi", "mcp"),
            command_env="KIMI_AGENT_MCP_CMD",
            default_model="kimi-agent",
            model_env="KIMI_AGENT_MODEL",
        ),
        # --- OpenClaw ------------------------------------------------
        ProviderSpec(
            name="openclaw",
            kind="mcp_stdio",
            description="OpenClaw agent over MCP",
            command=("openclaw", "mcp"),
            command_env="OPENCLAW_MCP_CMD",
            default_model="openclaw",
            model_env="OPENCLAW_MODEL",
        ),
        # --- Generic OpenAI-compatible escape hatch -----------------
        ProviderSpec(
            name="openai_compat",
            kind="openai_compat",
            description="Generic OpenAI-compatible endpoint (self-hosted / other)",
            base_url="",
            api_key_envs=("OPENAI_API_KEY", "OPENAI_COMPAT_API_KEY"),
            default_model="",
            base_url_env="OPENAI_COMPAT_BASE_URL",
            model_env="OPENAI_COMPAT_MODEL",
        ),
        # --- Generic remote MCP server (Streamable HTTP) escape hatch -
        ProviderSpec(
            name="mcp_http",
            kind="mcp_http",
            description="Generic remote MCP server over Streamable HTTP",
            url="",
            url_env="MCP_HTTP_URL",
            headers_env="MCP_HTTP_HEADERS",
            default_model="mcp-http",
            model_env="MCP_HTTP_MODEL",
        ),
    ]


# ======================================================================
# HTTP transport (Anthropic + OpenAI-compatible)
# ======================================================================
class HttpLLMClient:
    """Real HTTP client for the Anthropic Messages / OpenAI chat schemas."""

    def __init__(self, spec: ProviderSpec, timeout: float = 60.0):
        if spec.kind not in ("anthropic", "openai_compat"):
            raise AgentError(f"{spec.name}: not an HTTP provider ({spec.kind})")
        self.spec = spec
        self.timeout = timeout

    def _post_json(
        self, url: str, headers: Dict[str, str], body: Dict[str, Any]
    ) -> Dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:  # 4xx/5xx carry a useful body
            detail = exc.read().decode("utf-8", "replace") if exc.fp else ""
            raise TransportError(
                f"HTTP {exc.code} from {self.spec.name}: {detail[:500]}"
            )
        except urllib.error.URLError as exc:
            raise TransportError(f"network error to {self.spec.name}: {exc.reason}")
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise TransportError(f"non-JSON reply from {self.spec.name}: {exc}")

    def chat(
        self,
        messages: List[Dict[str, str]],
        *,
        system: str = "",
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        role: str = "assistant",
    ) -> ChatResult:
        key = self.spec.resolved_api_key()
        base = self.spec.resolved_base_url()
        model = model or self.spec.resolved_model()
        if not key:
            raise ProviderUnavailable(
                f"{self.spec.name}: no API key ("
                + "/".join(self.spec.api_key_envs)
                + ")"
            )
        if not base:
            raise ProviderUnavailable(f"{self.spec.name}: no base url configured")
        if not model:
            raise ProviderUnavailable(f"{self.spec.name}: no model configured")

        t0 = time.perf_counter()
        if self.spec.kind == "anthropic":
            result = self._chat_anthropic(
                base, key, model, system, messages, max_tokens, temperature
            )
        else:
            result = self._chat_openai(
                base, key, model, system, messages, max_tokens, temperature
            )
        result.latency_ms = (time.perf_counter() - t0) * 1000.0
        result.role = role
        return result

    def _chat_anthropic(
        self, base, key, model, system, messages, max_tokens, temperature
    ) -> ChatResult:
        headers = {
            "x-api-key": key,
            "anthropic-version": os.environ.get("ANTHROPIC_VERSION", "2023-06-01"),
        }
        headers.update(self.spec.extra_headers)
        body: Dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if system:
            body["system"] = system
        raw = self._post_json(base + "/v1/messages", headers, body)
        text_parts = [
            blk.get("text", "")
            for blk in raw.get("content", [])
            if isinstance(blk, dict) and blk.get("type") == "text"
        ]
        usage = raw.get("usage", {}) or {}
        return ChatResult(
            text="".join(text_parts),
            provider=self.spec.name,
            model=model,
            transport="anthropic",
            prompt_tokens=int(usage.get("input_tokens", 0) or 0),
            completion_tokens=int(usage.get("output_tokens", 0) or 0),
            raw=raw,
        )

    def _chat_openai(
        self, base, key, model, system, messages, max_tokens, temperature
    ) -> ChatResult:
        headers = {"Authorization": f"Bearer {key}"}
        headers.update(self.spec.extra_headers)
        full_messages: List[Dict[str, str]] = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)
        body: Dict[str, Any] = {
            "model": model,
            "messages": full_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        raw = self._post_json(base + "/chat/completions", headers, body)
        choices = raw.get("choices") or []
        text = ""
        if choices:
            text = (choices[0].get("message") or {}).get("content") or ""
        usage = raw.get("usage", {}) or {}
        return ChatResult(
            text=text,
            provider=self.spec.name,
            model=model,
            transport="openai_compat",
            prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage.get("completion_tokens", 0) or 0),
            raw=raw,
        )


# ======================================================================
# MCP stdio transport (JSON-RPC 2.0 over a subprocess)
# ======================================================================
class McpStdioClient:
    """Minimal but real MCP client over a child process's stdio.

    Frames JSON-RPC 2.0 messages as newline-delimited UTF-8 JSON (the MCP
    stdio transport). A background thread drains the child's stdout onto a
    queue so request/response correlation and timeouts work on every platform
    (``select`` on pipes is not portable to Windows).
    """

    PROTOCOL_VERSION = "2025-06-18"

    def __init__(
        self,
        command: Tuple[str, ...],
        *,
        env: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        client_name: str = "file-analyzer-dynamic",
    ):
        if not command:
            raise AgentError("McpStdioClient needs a non-empty command")
        self.command = tuple(command)
        self.timeout = timeout
        self.client_name = client_name
        self._env = env
        self._proc: Optional[subprocess.Popen] = None
        self._rx: "queue.Queue[str]" = queue.Queue()
        self._reader: Optional[threading.Thread] = None
        self._stderr_reader: Optional[threading.Thread] = None
        self._stderr_tail: List[str] = []
        self._next_id = 0
        self._initialized = False

    # -- lifecycle ----------------------------------------------------
    def start(self) -> "McpStdioClient":
        binary = self.command[0]
        if shutil.which(binary) is None and not os.path.exists(binary):
            raise ProviderUnavailable(f"MCP binary {binary!r} not found on PATH")
        env = dict(os.environ)
        if self._env:
            env.update(self._env)
        try:
            self._proc = subprocess.Popen(
                list(self.command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                encoding="utf-8",
                bufsize=1,  # line-buffered
            )
        except OSError as exc:
            raise ProviderUnavailable(f"cannot launch {binary!r}: {exc}")
        self._reader = threading.Thread(target=self._drain_stdout, daemon=True)
        self._reader.start()
        self._stderr_reader = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_reader.start()
        return self

    def _drain_stdout(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            line = line.strip()
            if line:
                self._rx.put(line)
        self._rx.put("")  # sentinel: stream closed

    def _drain_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        for line in self._proc.stderr:
            self._stderr_tail.append(line.rstrip())
            if len(self._stderr_tail) > 50:
                self._stderr_tail.pop(0)

    # -- framing ------------------------------------------------------
    def _send(self, message: Dict[str, Any]) -> None:
        if not self._proc or self._proc.stdin is None:
            raise TransportError("MCP process not started")
        try:
            self._proc.stdin.write(json.dumps(message) + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise TransportError(f"MCP write failed: {exc}")

    def _await_response(self, request_id: int) -> Dict[str, Any]:
        """Block for the response whose id matches, honoring the timeout."""
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError(
                    f"MCP timeout after {self.timeout}s "
                    f"(stderr: {' | '.join(self._stderr_tail[-3:])})"
                )
            try:
                line = self._rx.get(timeout=remaining)
            except queue.Empty:
                continue
            if line == "":  # stream closed
                code = self._proc.poll() if self._proc else None
                raise TransportError(
                    f"MCP stream closed (exit={code}; "
                    f"stderr: {' | '.join(self._stderr_tail[-3:])})"
                )
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip non-JSON log noise on stdout
            if msg.get("id") == request_id and ("result" in msg or "error" in msg):
                if "error" in msg:
                    raise TransportError(
                        f"MCP error {msg['error'].get('code')}: "
                        f"{msg['error'].get('message')}"
                    )
                return msg["result"]
            # notifications and out-of-band messages are ignored here

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        self._next_id += 1
        rid = self._next_id
        self._send(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        )
        return self._await_response(rid)

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # -- MCP methods --------------------------------------------------
    def initialize(self) -> Dict[str, Any]:
        result = self._request(
            "initialize",
            {
                "protocolVersion": self.PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "clientInfo": {"name": self.client_name, "version": "1.0"},
            },
        )
        self._notify("notifications/initialized")
        self._initialized = True
        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        if not self._initialized:
            self.initialize()
        result = self._request("tools/list")
        return result.get("tools", []) if isinstance(result, dict) else []

    def call_tool(
        self, name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        if not self._initialized:
            self.initialize()
        t0 = time.perf_counter()
        result = self._request(
            "tools/call", {"name": name, "arguments": arguments or {}}
        )
        dt = (time.perf_counter() - t0) * 1000.0
        text = self._flatten_content(result.get("content", []))
        return ToolResult(
            name=name,
            content=text,
            provider="/".join(self.command[:1]),
            is_error=bool(result.get("isError")),
            latency_ms=dt,
            raw=result,
        )

    @staticmethod
    def _flatten_content(blocks: Any) -> str:
        if isinstance(blocks, str):
            return blocks
        parts: List[str] = []
        for blk in blocks or []:
            if isinstance(blk, dict):
                if blk.get("type") == "text":
                    parts.append(blk.get("text", ""))
                elif "text" in blk:
                    parts.append(str(blk["text"]))
                else:
                    parts.append(json.dumps(blk))
            else:
                parts.append(str(blk))
        return "\n".join(parts)

    def close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except OSError:
            pass
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            try:
                self._proc.kill()
            except OSError:
                pass
        self._proc = None

    def __enter__(self) -> "McpStdioClient":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.close()


# ======================================================================
# MCP Streamable-HTTP transport (JSON-RPC 2.0 over a POST endpoint)
# ======================================================================
class McpHttpClient:
    """Real MCP client over the **Streamable HTTP** transport.

    The client POSTs newline-free JSON-RPC 2.0 messages to a single endpoint
    and accepts a reply that is *either* a JSON object (``application/json``)
    *or* an SSE stream (``text/event-stream``) carrying one or more messages.
    It honours the ``Mcp-Session-Id`` handed back on ``initialize`` (echoing it
    on every subsequent request) and the negotiated ``MCP-Protocol-Version``
    header. This is the transport remote MCP servers -- and the servers already
    registered in the Claude desktop app / ``claude`` CLI -- speak, so no
    per-provider API key is needed here: the endpoint carries its own auth
    (bearer token, cookie, etc.) via the configured headers.

    Its public surface (``initialize`` / ``list_tools`` / ``call_tool`` /
    ``close``) is duck-type identical to :class:`McpStdioClient`, so
    :class:`AgentConnector` drives either transport through one code path.
    """

    PROTOCOL_VERSION = "2025-06-18"

    def __init__(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 60.0,
        client_name: str = "file-analyzer-dynamic",
    ):
        if not url:
            raise AgentError("McpHttpClient needs a non-empty URL")
        self.url = url
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.client_name = client_name
        self._next_id = 0
        self._initialized = False
        self._session_id: Optional[str] = None
        self._negotiated_version = self.PROTOCOL_VERSION

    # -- transport ----------------------------------------------------
    def _post(
        self, message: Dict[str, Any], *, is_notification: bool = False
    ) -> Optional[Any]:
        data = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        # The protocol-version header is required only *after* initialize.
        if self._initialized:
            req.add_header("MCP-Protocol-Version", self._negotiated_version)
        if self._session_id:
            req.add_header("Mcp-Session-Id", self._session_id)
        for k, v in self.headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self._session_id = sid
                ctype = resp.headers.get("Content-Type", "") or ""
                body = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace") if exc.fp else ""
            raise TransportError(f"MCP HTTP {exc.code} at {self.url}: {detail[:500]}")
        except urllib.error.URLError as exc:
            raise TransportError(f"MCP HTTP network error to {self.url}: {exc.reason}")
        if is_notification:
            return None
        return self._extract_result(body, ctype, message.get("id"))

    def _extract_result(self, body: str, ctype: str, rid: Any) -> Any:
        if "text/event-stream" in ctype.lower():
            messages = self._parse_sse(body)
        else:
            body = body.strip()
            if not body:
                return {}
            try:
                obj = json.loads(body)
            except json.JSONDecodeError as exc:
                raise TransportError(f"non-JSON MCP reply from {self.url}: {exc}")
            messages = obj if isinstance(obj, list) else [obj]
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            if msg.get("id") == rid and ("result" in msg or "error" in msg):
                if "error" in msg:
                    err = msg["error"] or {}
                    raise TransportError(
                        f"MCP error {err.get('code')}: {err.get('message')}"
                    )
                return msg["result"]
        raise TransportError(f"no matching JSON-RPC response from {self.url}")

    @staticmethod
    def _parse_sse(body: str) -> List[Any]:
        """Extract JSON payloads from an ``text/event-stream`` body."""
        out: List[Any] = []
        for block in re.split(r"\r?\n\r?\n", body):
            data_lines = [
                ln[5:].lstrip() for ln in block.splitlines() if ln.startswith("data:")
            ]
            if not data_lines:
                continue
            try:
                out.append(json.loads("\n".join(data_lines)))
            except json.JSONDecodeError:
                continue
        return out

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if not self._initialized and method != "initialize":
            self.initialize()
        self._next_id += 1
        rid = self._next_id
        return self._post(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        )

    # -- MCP methods --------------------------------------------------
    def initialize(self) -> Dict[str, Any]:
        self._next_id += 1
        rid = self._next_id
        result = self._post(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "method": "initialize",
                "params": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "clientInfo": {"name": self.client_name, "version": "1.0"},
                },
            }
        )
        if isinstance(result, dict) and result.get("protocolVersion"):
            self._negotiated_version = result["protocolVersion"]
        self._initialized = True
        # notifications/initialized carries no id and expects 202/no body
        self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            is_notification=True,
        )
        return result if isinstance(result, dict) else {}

    def list_tools(self) -> List[Dict[str, Any]]:
        result = self._request("tools/list")
        return result.get("tools", []) if isinstance(result, dict) else []

    def call_tool(
        self, name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        t0 = time.perf_counter()
        result = self._request(
            "tools/call", {"name": name, "arguments": arguments or {}}
        )
        dt = (time.perf_counter() - t0) * 1000.0
        result = result if isinstance(result, dict) else {}
        text = McpStdioClient._flatten_content(result.get("content", []))
        return ToolResult(
            name=name,
            content=text,
            provider=self.url,
            is_error=bool(result.get("isError")),
            latency_ms=dt,
            raw=result,
        )

    def close(self) -> None:
        # best-effort session teardown (DELETE with the session id)
        if self._session_id:
            try:
                req = urllib.request.Request(self.url, method="DELETE")
                req.add_header("Mcp-Session-Id", self._session_id)
                if self._initialized:
                    req.add_header("MCP-Protocol-Version", self._negotiated_version)
                for k, v in self.headers.items():
                    req.add_header(k, v)
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass
        self._session_id = None
        self._initialized = False

    def __enter__(self) -> "McpHttpClient":
        self.initialize()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


# ======================================================================
# Desktop / CLI MCP-server discovery
#
# Every mainstream coding agent stores the MCP servers the user has already
# connected in its own config file, in its own dialect. This block reads those
# files across the tools the request named -- Claude desktop & CLI, Antigravity
# desktop/CLI, the Gemini CLI, Grok CLI, OpenCode, Cursor, Windsurf, Zed,
# VS Code -- and turns each configured server (stdio or http/sse) into a
# :class:`ProviderSpec`, so the dynamic layer can drive exactly those tools /
# agents over MCP with no new credentials (each endpoint carries its own auth).
# ======================================================================
# Dialects: how one server entry is shaped inside a given tool's config.
_DIALECT_STANDARD = "standard"  # {command,args,env} | {url|httpUrl,headers,type}
_DIALECT_OPENCODE = "opencode"  # {type:local,command:[...],environment} | remote
_DIALECT_ZED = "zed"  # {source,command:str|{path,args,env},args,env}


def _config_home() -> str:
    return os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )


def _load_json_file(path: str) -> Optional[Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    # tolerate JSONC (comments / trailing commas) for tools that allow it
    for candidate in (text, _strip_jsonc(text)):
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    return None


def _load_toml_file(path: str) -> Optional[Any]:
    """Parse a TOML config if a TOML reader is importable (3.11+); else skip.

    Kept as a lazy import so the module still imports on the bare 3.10 the CI
    gate uses -- absence of ``tomllib`` just means TOML sources are skipped,
    not that discovery fails.
    """
    try:
        import tomllib  # type: ignore
    except Exception:
        return None
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (OSError, ValueError):
        return None


def _strip_jsonc(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments and trailing commas, string-safe.

    Scans character by character tracking string state so a ``//`` inside a
    URL (``https://``) or a value is never mistaken for a comment.
    """
    out: List[str] = []
    i, n = 0, len(text)
    in_str = False
    quote = ""
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    # drop trailing commas: ",]" / ",}" (possibly with whitespace between)
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


@dataclass
class _ConfigSource:
    source: str
    path: str
    key: str  # top-level object holding the servers
    dialect: str = _DIALECT_STANDARD
    fmt: str = "json"  # "json" | "toml"
    scan_projects: bool = False  # Claude Code's projects.<abspath>.mcpServers


def _config_sources(project_dir: Optional[str] = None) -> List[_ConfigSource]:
    """Every candidate config file, tagged by tool, key and dialect.

    Global (home-based) sources first, then the current project's local files
    (most specific last). Non-existent files are simply skipped later.
    """
    home = os.path.expanduser("~")
    cfg = _config_home()
    appdata = os.environ.get("APPDATA")
    srcs: List[_ConfigSource] = []

    def add(
        source,
        path,
        key="mcpServers",
        dialect=_DIALECT_STANDARD,
        fmt="json",
        scan_projects=False,
    ):
        srcs.append(_ConfigSource(source, path, key, dialect, fmt, scan_projects))

    # --- Claude Code CLI (global; also per-project blocks inside it) ---
    add("claude_code", os.path.join(home, ".claude.json"), scan_projects=True)
    # --- Claude desktop app ---
    if appdata:
        add(
            "claude_desktop",
            os.path.join(appdata, "Claude", "claude_desktop_config.json"),
        )
    add(
        "claude_desktop",
        os.path.join(
            home,
            "Library",
            "Application Support",
            "Claude",
            "claude_desktop_config.json",
        ),
    )
    add("claude_desktop", os.path.join(cfg, "Claude", "claude_desktop_config.json"))
    # --- Gemini CLI (mcpServers; entries may use httpUrl/url) ---
    add("gemini_cli", os.path.join(home, ".gemini", "settings.json"))
    # --- Antigravity desktop / CLI (shared ~/.gemini/... mcp_config.json) ---
    add("antigravity", os.path.join(home, ".gemini", "antigravity", "mcp_config.json"))
    add("antigravity", os.path.join(home, ".gemini", "config", "mcp_config.json"))
    # --- Grok CLI (JSON variants + a TOML config) ---
    for fn in ("settings.json", "user-settings.json", "mcp-config.json"):
        add("grok_cli", os.path.join(home, ".grok", fn))
    add("grok_cli", os.path.join(home, ".grok", "config.toml"), fmt="toml")
    # --- OpenCode (global; key "mcp", opencode dialect) ---
    add(
        "opencode",
        os.path.join(cfg, "opencode", "opencode.json"),
        key="mcp",
        dialect=_DIALECT_OPENCODE,
    )
    add(
        "opencode",
        os.path.join(cfg, "opencode", "opencode.jsonc"),
        key="mcp",
        dialect=_DIALECT_OPENCODE,
    )
    if appdata:
        add(
            "opencode",
            os.path.join(appdata, "opencode", "opencode.json"),
            key="mcp",
            dialect=_DIALECT_OPENCODE,
        )
    # --- Cursor (global) ---
    add("cursor", os.path.join(home, ".cursor", "mcp.json"))
    # --- Windsurf / Codeium (global) ---
    add("windsurf", os.path.join(home, ".codeium", "windsurf", "mcp_config.json"))
    # --- Zed (global; key "context_servers", zed dialect) ---
    add(
        "zed",
        os.path.join(cfg, "zed", "settings.json"),
        key="context_servers",
        dialect=_DIALECT_ZED,
    )
    if appdata:
        add(
            "zed",
            os.path.join(appdata, "Zed", "settings.json"),
            key="context_servers",
            dialect=_DIALECT_ZED,
        )

    # --- explicit override (highest-trust single file) ---
    override = os.environ.get("MCP_CONFIG_FILE")
    if override:
        add("env", override)

    # --- project-local files (most specific) ---
    pdir = project_dir or os.getcwd()
    add("mcp_json", os.path.join(pdir, ".mcp.json"))
    add("cursor", os.path.join(pdir, ".cursor", "mcp.json"))
    add("vscode", os.path.join(pdir, ".vscode", "mcp.json"), key="servers")
    add("gemini_cli", os.path.join(pdir, ".gemini", "settings.json"))
    add("antigravity", os.path.join(pdir, ".agents", "mcp_config.json"))
    add(
        "opencode",
        os.path.join(pdir, "opencode.json"),
        key="mcp",
        dialect=_DIALECT_OPENCODE,
    )
    add(
        "opencode",
        os.path.join(pdir, "opencode.jsonc"),
        key="mcp",
        dialect=_DIALECT_OPENCODE,
    )
    add("grok_cli", os.path.join(pdir, ".grok", "settings.json"))
    add(
        "zed",
        os.path.join(pdir, ".zed", "settings.json"),
        key="context_servers",
        dialect=_DIALECT_ZED,
    )
    return srcs


def _safe_provider_name(name: str) -> str:
    slug = re.sub(r"[^0-9a-zA-Z]+", "_", name).strip("_").lower()
    return "mcp_" + (slug or "server")


def _as_str_map(obj: Any) -> Dict[str, str]:
    return {str(k): str(v) for k, v in obj.items()} if isinstance(obj, dict) else {}


def _normalize_entry(dialect: str, cfg: Any) -> Optional[Dict[str, Any]]:
    """Flatten one tool-specific server entry to a common shape.

    Returns ``{disabled, url, type, command, args, env, headers, chat_tool}``
    or ``None`` when the entry is not a dict.
    """
    if not isinstance(cfg, dict):
        return None
    chat_tool = str(cfg.get("chatTool") or cfg.get("chat_tool") or "")

    if dialect == _DIALECT_OPENCODE:
        t = str(cfg.get("type") or "").lower()
        disabled = cfg.get("enabled") is False
        if t == "remote" or cfg.get("url"):
            return {
                "disabled": disabled,
                "url": cfg.get("url"),
                "type": "http",
                "command": None,
                "args": [],
                "env": {},
                "headers": _as_str_map(cfg.get("headers")),
                "chat_tool": chat_tool,
            }
        cmd = cfg.get("command") or []
        if isinstance(cmd, str):
            cmd = [cmd]
        cmd = [str(c) for c in cmd]
        return {
            "disabled": disabled,
            "url": None,
            "type": "",
            "command": (cmd[0] if cmd else None),
            "args": cmd[1:],
            "env": _as_str_map(cfg.get("environment") or cfg.get("env")),
            "headers": {},
            "chat_tool": chat_tool,
        }

    if dialect == _DIALECT_ZED:
        disabled = cfg.get("enabled") is False
        cmdobj = cfg.get("command")
        if isinstance(cmdobj, dict):
            command = cmdobj.get("path")
            args = cmdobj.get("args") or []
            env = cmdobj.get("env") or {}
        else:
            command = cmdobj
            args = cfg.get("args") or []
            env = cfg.get("env") or {}
        return {
            "disabled": disabled,
            "url": cfg.get("url"),
            "type": "",
            "command": (str(command) if command else None),
            "args": [str(a) for a in args],
            "env": _as_str_map(env),
            "headers": _as_str_map(cfg.get("headers")),
            "chat_tool": chat_tool,
        }

    # standard dialect (Claude, Gemini, Cursor, Windsurf, Antigravity, VS Code)
    disabled = cfg.get("disabled") is True or cfg.get("enabled") is False
    # Gemini uses httpUrl for streamable HTTP and url for legacy SSE
    url = cfg.get("url") or cfg.get("httpUrl") or cfg.get("serverUrl")
    return {
        "disabled": disabled,
        "url": url,
        "type": str(cfg.get("type") or "").lower().replace("-", "_"),
        "command": (str(cfg["command"]) if cfg.get("command") else None),
        "args": [str(a) for a in (cfg.get("args") or [])],
        "env": _as_str_map(cfg.get("env")),
        "headers": _as_str_map(cfg.get("headers")),
        "chat_tool": chat_tool,
    }


def _spec_from_entry(
    source: str, name: str, dialect: str, cfg: Any
) -> Optional[ProviderSpec]:
    norm = _normalize_entry(dialect, cfg)
    if norm is None or norm.get("disabled"):
        return None
    pname = _safe_provider_name(name)
    url = norm.get("url")
    command = norm.get("command")
    # An http/sse url wins; otherwise a command means stdio.
    if url and (
        not command or norm.get("type") in ("http", "streamable_http", "sse", "")
    ):
        return ProviderSpec(
            name=pname,
            kind="mcp_http",
            description=f"{source}:{name}",
            url=str(url),
            extra_headers=norm["headers"],
            default_model=name,
            mcp_chat_tool=norm["chat_tool"],
            source=source,
        )
    if command:
        return ProviderSpec(
            name=pname,
            kind="mcp_stdio",
            description=f"{source}:{name}",
            command=tuple([command] + list(norm["args"])),
            mcp_env=norm["env"],
            default_model=name,
            mcp_chat_tool=norm["chat_tool"],
            source=source,
        )
    return None


def _servers_from_config(
    src: _ConfigSource, data: Any, project_dir: Optional[str] = None
) -> List[ProviderSpec]:
    if not isinstance(data, dict):
        return []
    server_maps: List[Dict[str, Any]] = []
    top = data.get(src.key)
    if isinstance(top, dict):
        server_maps.append(top)
    # Claude Code stores per-project servers under projects.<abspath>.mcpServers
    if src.scan_projects and isinstance(data.get("projects"), dict):
        pdir = os.path.abspath(project_dir or os.getcwd())
        for pkey, pval in data["projects"].items():
            if not isinstance(pval, dict):
                continue
            smap = pval.get(src.key)
            if isinstance(smap, dict) and os.path.abspath(pkey) == pdir:
                server_maps.append(smap)
    specs: List[ProviderSpec] = []
    for smap in server_maps:
        for name, cfg in smap.items():
            spec = _spec_from_entry(src.source, name, src.dialect, cfg)
            if spec is not None:
                specs.append(spec)
    return specs


def discover_mcp_servers(
    project_dir: Optional[str] = None, dedupe: bool = True
) -> List[ProviderSpec]:
    """Discover MCP servers from every supported agent's config file.

    Reads the config files of the Claude desktop app & CLI, Antigravity
    (desktop/CLI), the Gemini CLI, Grok CLI, OpenCode, Cursor, Windsurf, Zed and
    VS Code -- global first, then the current project's local files -- honouring
    each tool's own dialect (standard ``mcpServers``; OpenCode's ``mcp`` with a
    ``command`` array; Zed's ``context_servers`` with a nested ``command``;
    Gemini's ``httpUrl``; JSONC/TOML). Every enabled server, stdio *or*
    http/sse, becomes a :class:`ProviderSpec` tagged with its ``source`` and
    ``config_path``. ``disabled``/``enabled:false`` servers are skipped, as are
    missing or unreadable files. When ``dedupe`` is set, the first occurrence of
    a given provider name wins (global before project).
    """
    specs: List[ProviderSpec] = []
    seen: Dict[str, str] = {}
    for src in _config_sources(project_dir):
        loader = _load_toml_file if src.fmt == "toml" else _load_json_file
        data = loader(src.path)
        if data is None:
            continue
        for spec in _servers_from_config(src, data, project_dir):
            if dedupe and spec.name in seen:
                continue
            seen[spec.name] = src.path
            spec.config_path = src.path
            specs.append(spec)
    return specs


# ======================================================================
# Unified connector + registry
# ======================================================================
class AgentConnector:
    """One provider, one uniform ``chat`` / ``call_tool`` facade.

    HTTP providers implement ``chat``; MCP providers implement ``call_tool``
    and also expose ``chat`` when the server offers a chat-shaped tool (its
    name is configurable via ``mcp_chat_tool``). Reachability is enforced up
    front: an unconfigured provider raises :class:`ProviderUnavailable`.
    """

    def __init__(
        self,
        spec: ProviderSpec,
        *,
        timeout: float = 60.0,
        mcp_chat_tool: str = "",
    ):
        self.spec = spec
        self.timeout = timeout
        self.mcp_chat_tool = (
            mcp_chat_tool
            or os.environ.get(f"{spec.name.upper()}_MCP_CHAT_TOOL", "")
            or spec.mcp_chat_tool
        )
        self._mcp: Optional[Any] = None  # McpStdioClient | McpHttpClient

    @property
    def transport(self) -> str:
        if self.spec.kind in ("mcp_stdio", "mcp_http"):
            return self.spec.kind
        return "http"

    def probe(self) -> Dict[str, Any]:
        return self.spec.probe()

    def reachable(self) -> bool:
        return bool(self.spec.probe().get("reachable"))

    # -- HTTP path ----------------------------------------------------
    def chat(
        self,
        messages: List[Dict[str, str]],
        *,
        system: str = "",
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        role: str = "assistant",
    ) -> ChatResult:
        if self.spec.kind in ("anthropic", "openai_compat"):
            client = HttpLLMClient(self.spec, timeout=self.timeout)
            return client.chat(
                messages,
                system=system,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                role=role,
            )
        if self.spec.kind in ("mcp_stdio", "mcp_http"):
            return self._chat_via_mcp(messages, system=system, role=role)
        raise AgentError(f"{self.spec.name}: unsupported kind {self.spec.kind}")

    def _chat_via_mcp(
        self, messages: List[Dict[str, str]], *, system: str, role: str
    ) -> ChatResult:
        tool = self.mcp_chat_tool
        if not tool:
            raise ProviderUnavailable(
                f"{self.spec.name}: MCP chat needs a chat tool name "
                f"(set {self.spec.name.upper()}_MCP_CHAT_TOOL)"
            )
        prompt = "\n\n".join(
            (f"[{m.get('role', 'user')}] " + m.get("content", "")) for m in messages
        )
        if system:
            prompt = f"[system] {system}\n\n{prompt}"
        t0 = time.perf_counter()
        res = self.call_tool(tool, {"prompt": prompt})
        return ChatResult(
            text=res.content,
            provider=self.spec.name,
            model=self.spec.resolved_model(),
            transport=self.spec.kind,
            role=role,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            status="error" if res.is_error else "ok",
            error=res.error,
            raw=res.raw,
        )

    # -- MCP path -----------------------------------------------------
    def _ensure_mcp(self) -> Any:
        if self.spec.kind not in ("mcp_stdio", "mcp_http"):
            raise AgentError(f"{self.spec.name}: not an MCP provider")
        if self._mcp is None:
            if self.spec.kind == "mcp_stdio":
                cmd = self.spec.resolved_command()
                self._mcp = McpStdioClient(
                    cmd, env=(self.spec.mcp_env or None), timeout=self.timeout
                ).start()
            else:
                self._mcp = McpHttpClient(
                    self.spec.resolved_url(),
                    headers=self.spec.resolved_headers(),
                    timeout=self.timeout,
                )
            self._mcp.initialize()
        return self._mcp

    def list_tools(self) -> List[Dict[str, Any]]:
        return self._ensure_mcp().list_tools()

    def call_tool(
        self, name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        res = self._ensure_mcp().call_tool(name, arguments)
        res.provider = self.spec.name
        return res

    def close(self) -> None:
        if self._mcp is not None:
            self._mcp.close()
            self._mcp = None


class AgentRegistry:
    """All configured providers, with honest reachability probing."""

    def __init__(
        self,
        specs: Optional[List[ProviderSpec]] = None,
        timeout: float = 60.0,
        *,
        discover: bool = False,
        project_dir: Optional[str] = None,
    ):
        self.specs: Dict[str, ProviderSpec] = {}
        for spec in specs if specs is not None else default_provider_specs():
            self.specs[spec.name] = spec
        if discover:
            # desktop/CLI-configured servers fill in only names not already set,
            # so an explicit spec always wins over a discovered one.
            for spec in discover_mcp_servers(project_dir):
                self.specs.setdefault(spec.name, spec)
        self.timeout = timeout

    @classmethod
    def from_desktop(
        cls, project_dir: Optional[str] = None, timeout: float = 60.0
    ) -> "AgentRegistry":
        """Registry of *only* the MCP servers configured in the desktop/CLI."""
        return cls(
            specs=discover_mcp_servers(project_dir),
            timeout=timeout,
        )

    def add(self, spec: ProviderSpec) -> None:
        self.specs[spec.name] = spec

    def discovered(self) -> List[str]:
        """Names of providers that came from a desktop/CLI config file."""
        return [n for n, s in self.specs.items() if s.source != "builtin"]

    def names(self) -> List[str]:
        return list(self.specs)

    def select(
        self,
        include: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
    ) -> "AgentRegistry":
        """Return a new registry keeping only the wanted providers.

        ``include`` (when non-empty) is a whitelist: only providers whose name
        is listed survive. ``exclude`` is always removed afterwards. Names are
        matched case-insensitively and unknown names are ignored, so the filter
        never raises and the surrounding agent layer stays soft. An empty/None
        filter is a no-op and returns ``self`` unchanged.
        """
        inc = {n.strip().lower() for n in (include or []) if n and str(n).strip()}
        exc = {n.strip().lower() for n in (exclude or []) if n and str(n).strip()}
        if not inc and not exc:
            return self
        kept: Dict[str, ProviderSpec] = {}
        for name, spec in self.specs.items():
            low = name.lower()
            if inc and low not in inc:
                continue
            if low in exc:
                continue
            kept[name] = spec
        new = AgentRegistry(specs=[], timeout=self.timeout)
        new.specs = kept
        return new

    def connector(self, name: str) -> AgentConnector:
        if name not in self.specs:
            raise AgentError(f"unknown provider {name!r}")
        return AgentConnector(self.specs[name], timeout=self.timeout)

    def probe_all(self) -> List[Dict[str, Any]]:
        return [self.specs[n].probe() for n in self.specs]

    def available(self) -> List[str]:
        """Names of providers reachable in this environment right now."""
        return [n for n, s in self.specs.items() if s.probe().get("reachable")]
