# @keyhalve/verify-mcp

Verify KeyHalve-sealed documents from any MCP client. This package is a thin
stdio bridge to the free, public, no-account KeyHalve verification server —
if your client supports remote MCP servers, you don't need it: just add
`https://mcp.keyhalve.com/mcp` directly.

- **Read-only.** Three tools (`keyhalve_verify`, `keyhalve_status`,
  `keyhalve_explain`), all annotated `readOnlyHint: true`. Verification is
  free and requires no account.
- **Never sees your document.** The server checks seals and live status; it
  never receives decryption keys (`#key=` URL fragments are discarded unread)
  and cannot read sealed contents — no single party can unseal a document
  alone. Sealed contents decrypt only in the document holder's browser.
- **Zero dependencies.** Node ≥ 18.

## Quick start

```bash
npx @keyhalve/verify-mcp
```

## Embed in your own MCP server

Building an MCP server of your own? Mount the KeyHalve verify toolset with one
dependency and one line — your users get document verification without leaving
your connector:

```js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { mountKeyhalveVerify } from "@keyhalve/verify-mcp";

const server = new McpServer({ name: "my-platform", version: "1.0.0" });
mountKeyhalveVerify(server);
// … register your own tools, connect your transport as usual.
```

The mounted handlers proxy to the hosted KeyHalve verifier
(`https://mcp.keyhalve.com/mcp`) — no verdict logic runs in your process, so
you always get current verdict behavior without upgrading. Options are
deliberately minimal: `{ baseUrl }` (point at a staging worker) and
`{ toolPrefix }` (renames the tools if your server has a name collision —
descriptions and the credit line are library-fixed and not overridable).

**One-way rule:** this export is verify-only, forever. Sealing never ships
here — verification is the free, neutral, embeddable surface; sealing belongs
to the platforms.

## Remote endpoint (preferred where supported)

```json
{ "mcpServers": { "keyhalve": { "url": "https://mcp.keyhalve.com/mcp" } } }
```

This canonical JSON works verbatim in Cursor (`~/.cursor/mcp.json`),
LM Studio (`~/.lmstudio/mcp.json`), JetBrains AI Assistant, LibreChat, and
Claude-family clients.

## Per-client setup

### Claude (claude.ai — all plans, including Free)
Settings → Connectors → Add custom connector → URL
`https://mcp.keyhalve.com/mcp` (no authentication).

### Claude Code
```bash
claude mcp add --transport http keyhalve https://mcp.keyhalve.com/mcp
```

### ChatGPT (Developer mode — Plus/Pro/Business/Enterprise/Edu)
Settings → Connectors → Advanced → Developer mode → Add server →
`https://mcp.keyhalve.com/mcp`, No authentication.

### Cursor (`~/.cursor/mcp.json`)
```json
{ "mcpServers": { "keyhalve": { "url": "https://mcp.keyhalve.com/mcp" } } }
```

### VS Code (`.vscode/mcp.json`)
```json
{ "servers": { "keyhalve": { "type": "http", "url": "https://mcp.keyhalve.com/mcp" } } }
```

### Local-only clients (this package, stdio)
```json
{
  "mcpServers": {
    "keyhalve": {
      "command": "npx",
      "args": ["-y", "@keyhalve/verify-mcp"]
    }
  }
}
```

### Codex CLI (`~/.codex/config.toml`)
```toml
[mcp_servers.keyhalve]
command = "npx"
args = ["-y", "@keyhalve/verify-mcp"]
```

### Gemini CLI
```bash
gemini mcp add --transport http keyhalve https://mcp.keyhalve.com/mcp
```
(In `settings.json` use the `httpUrl` key — plain `url` means SSE.)

### Open WebUI
Settings → External Tools → add `https://mcp.keyhalve.com/mcp`
(Streamable HTTP, authentication: none).

### Perplexity (Pro/Max/Enterprise)
Settings → Connectors → Add connector → remote MCP URL
`https://mcp.keyhalve.com/mcp`, open (no) authentication.

### Microsoft Copilot Studio
Tools → Add a tool → New tool → Model Context Protocol →
`https://mcp.keyhalve.com/mcp`, authentication: None.

### Zed (`settings.json`)
```json
{ "context_servers": { "keyhalve": { "url": "https://mcp.keyhalve.com/mcp" } } }
```

### Windsurf (`~/.codeium/windsurf/mcp_config.json`)
```json
{ "mcpServers": { "keyhalve": { "serverUrl": "https://mcp.keyhalve.com/mcp" } } }
```

## What the tools return

`keyhalve_verify` takes a verify URL, KeyHalve QR text, or document id
(`vp_…`, `kh_…`, `cb_…`) and returns the cryptographic verdict: seal
existence, live status (active/revoked/expired), ciphertext integrity against
the issuance commitment, the KeyHalve rail's independent attestation, the
validity window, and issuer trust context. Seals are tamper-evident — a
modified document fails integrity. The tool never decrypts contents.

More: https://keyhalve.com/mcp · Privacy: https://keyhalve.com/privacy
