# Multi-agent connectors (DocumentParser Parts B & C)

The DocumentParser dynamic layer (Part B — the agent proposes, code validates,
errors are fed back, the agent repairs) and the Part-C LLM-as-judge RAG metrics
both talk to external coding agents and LLM/VLM backends through one connector
module: [`src/document/agent_mcp.py`](../src/document/agent_mcp.py).

Everything here is built on the **standard library** (`urllib`, `subprocess`,
`threading`, `json`). The only optional dependency is `mcp[cli]` — and even that
is *not* required by `agent_mcp.py` itself; it is the pin the standalone MCP
server (`mcp_server.py`) uses. Vendor SDKs (`anthropic`, `openai`,
`google-genai`) are **not** needed: the generic transports below cover every
provider.

## Two real transports

| Transport | Class | Speaks to |
|---|---|---|
| HTTP JSON | `HttpLLMClient` | Anthropic Messages API (Claude) and the OpenAI chat-completions schema (Grok/xAI, DeepSeek, Moonshot/Kimi, Gemini's OpenAI-compatible endpoint, any self-hosted OpenAI-compatible server) |
| MCP stdio | `McpStdioClient` | a coding agent's own `mcp` server run as a subprocess (Claude Code, Gemini CLI, Antigravity, OpenCode, Kimi agent, OpenClaw, …) — JSON-RPC 2.0 over newline-framed stdio |
| MCP Streamable HTTP | `McpHttpClient` | remote MCP servers and those already registered in the Claude desktop app / `claude` CLI — same JSON-RPC 2.0 over a single POST endpoint (JSON or SSE), honouring `Mcp-Session-Id` |

`AgentConnector` presents one uniform `chat()` / `call_tool()` facade over all
three, and `AgentRegistry` enumerates the named providers and **probes
reachability honestly** — nothing is faked:

- an HTTP provider is reachable when its API-key env var is set;
- an MCP-stdio provider is reachable when its CLI binary is on `PATH`;
- an MCP-http provider is reachable when a URL is configured.

An unconfigured provider reports `reachable = False` and raises
`ProviderUnavailable` when called, rather than inventing a response.

## Built-in providers

Named in `default_provider_specs()`. Every field is overridable by environment
variable so the registry maps onto whatever the operator actually has installed.

| Provider | Kind | Default endpoint / command | API-key env | Model env |
|---|---|---|---|---|
| `claude` | anthropic | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` / `CLAUDE_API_KEY` | `CLAUDE_MODEL` |
| `claude_code` | mcp_stdio | `claude mcp serve` | — (binary on PATH) | `CLAUDE_CODE_MODEL` |
| `gemini` | openai_compat | `…googleapis.com/v1beta/openai` | `GEMINI_API_KEY` / `GOOGLE_API_KEY` | `GEMINI_MODEL` |
| `gemini_code` | mcp_stdio | `gemini mcp` | — | `GEMINI_CODE_MODEL` |
| `antigravity` | mcp_stdio | `antigravity mcp` | — | `ANTIGRAVITY_MODEL` |
| `grok` | openai_compat | `https://api.x.ai/v1` | `XAI_API_KEY` / `GROK_API_KEY` | `GROK_MODEL` |
| `opencode` | mcp_stdio | `opencode mcp` | — | `OPENCODE_MODEL` |
| `deepseek` | openai_compat | `https://api.deepseek.com` | `DEEPSEEK_API_KEY` | `DEEPSEEK_MODEL` |
| `moonshot` | openai_compat | `https://api.moonshot.cn/v1` | `MOONSHOT_API_KEY` / `KIMI_API_KEY` | `MOONSHOT_MODEL` |
| `kimi_agent` | mcp_stdio | `kimi mcp` | — | `KIMI_AGENT_MODEL` |
| `openclaw` | mcp_stdio | `openclaw mcp` | — | `OPENCLAW_MODEL` |
| `openai_compat` | openai_compat | `OPENAI_COMPAT_BASE_URL` | `OPENAI_API_KEY` / `OPENAI_COMPAT_API_KEY` | `OPENAI_COMPAT_MODEL` |
| `mcp_http` | mcp_http | `MCP_HTTP_URL` | (endpoint carries its own auth) | `MCP_HTTP_MODEL` |

Per-provider overrides: `<PROVIDER>_BASE_URL` (HTTP), `<PROVIDER>_MCP_CMD`
(stdio command), `<PROVIDER>_MCP_CHAT_TOOL` (the MCP tool name to use for a
chat-shaped call). See each `ProviderSpec` for the exact env-var names.

## Zero-config desktop / CLI discovery

`discover_mcp_servers()` reads the MCP servers you have **already** connected in
your tools' own config files and turns each into a provider — no new
credentials, because each endpoint carries its own auth:

- Claude desktop app (`claude_desktop_config.json`) and Claude Code
  (`~/.claude.json`, including per-project `projects.<abspath>.mcpServers`);
- Gemini CLI (`~/.gemini/settings.json`, `httpUrl`/`url`);
- Antigravity (`~/.gemini/antigravity/mcp_config.json`, `.agents/mcp_config.json`);
- Grok CLI (`~/.grok/*.json` + `config.toml`);
- OpenCode (`opencode.json[c]`, `mcp` key, `command` array);
- Cursor (`~/.cursor/mcp.json`, `.cursor/mcp.json`);
- Windsurf (`~/.codeium/windsurf/mcp_config.json`);
- Zed (`context_servers` key, nested `command`);
- VS Code (`.vscode/mcp.json`, `servers` key);
- a project `.mcp.json`; an explicit `MCP_CONFIG_FILE` override.

JSONC (comments / trailing commas) and TOML are tolerated. `disabled` /
`enabled: false` servers are skipped. Enable discovery with
`AgentRegistry(discover=True)` or `AgentRegistry.from_desktop()`; an explicit
built-in spec always wins over a discovered one of the same name.

## Selecting which agents run (include / exclude)

Every agent-driven layer accepts an allow-list / deny-list of provider names so
an operator can steer which agents are eligible without editing env vars or
config. The primitive is one method on the registry:

```python
reg = AgentRegistry(discover=True)
reg.select(include=["claude", "gemini"])     # keep only these
reg.select(exclude=["grok"])                  # drop these
reg.select(include=["claude", "grok"], exclude=["grok"])  # include, then exclude
```

`select()` returns a **new** registry. Names match provider names
case-insensitively; unknown names are simply ignored and an empty/`None` filter
is a no-op — the filter never raises, so the surrounding layer stays soft.
`include` (when non-empty) is a whitelist applied first; `exclude` is removed
afterwards, so a name in both is dropped.

The same include/exclude pair is threaded through all three agent layers:

- **DB3 dynamic** — `DocumentParser.dynamic_analyze(..., agents_include=?,
  agents_exclude=?)`;
- **DB4 evaluation** — `DocumentParser.evaluate(..., agents_include=?,
  agents_exclude=?)` (narrows the pool the C3 RAG judge is picked from);
- **DB5 enrichment** — `McpEnrichmentEngine(..., agents_include=?,
  agents_exclude=?)`.

`AnalysisEngine` exposes one global `agents_include` / `agents_exclude` pair (plus
`discover_agents`, which lets the DB3/DB4 parser layers resolve a registry from
the desktop/CLI-configured servers so the filter has providers to act on — DB5
enrichment discovers on its own) and applies it to all three layers. On the CLI
these are `--agents-include`, `--agents-exclude` (comma/space-separated),
`--discover-agents`, and `--agent-roster`; see
[document-engine-libraries.md](document-engine-libraries.md).

## Internal prompt injection + prompt engine

"Prompt injection" here is **internal context injection**, not an attack: the
dynamic engine (`dynamic_engine.py`) folds static-layer findings and prior-agent
outputs into the next prompt via a `ContextBus` blackboard, and the Part-C
`EvalPromptEngine` builds strict-JSON judge prompts the same way. The connector
only ever sends the operator's own document context to the operator's own
configured agents.

## Usage sketch

```python
from src.document.agent_mcp import AgentRegistry

reg = AgentRegistry(discover=True)          # built-ins + desktop-configured MCP
print(reg.available())                       # honestly reachable right now
conn = reg.connector("claude")               # or "claude_code", "grok", …
res = conn.chat([{"role": "user", "content": "…"}], system="…", max_tokens=512)
print(res.text, res.prompt_tokens, res.completion_tokens, res.latency_ms)
```

For the Part-C judge, `DocumentParser.evaluate(..., judge="claude")` selects
which reachable provider scores the RAG metrics; with no reachable judge it
falls back to the deterministic heuristic and records `judge_method=heuristic`
on every row. See [document-engine-libraries.md](document-engine-libraries.md)
for the metric catalogue and Database-4 layout.
