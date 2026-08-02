# Install the KeyHalve verify MCP server

> Instructions for AI agents (Cline, Claude, etc.) installing this server for a user.
> KeyHalve verification is free, public, read-only, and requires no account or API key.

## Option 1 — remote server (preferred when the client supports remote MCP)

Add the hosted endpoint directly. Streamable HTTP, no authentication:

```
https://mcp.keyhalve.com/mcp
```

Canonical JSON (Cursor `~/.cursor/mcp.json`, LM Studio `~/.lmstudio/mcp.json`,
JetBrains, LibreChat, Claude-family):

```json
{ "mcpServers": { "keyhalve": { "url": "https://mcp.keyhalve.com/mcp" } } }
```

## Option 2 — local stdio bridge (Cline, Claude Desktop, any stdio-only client)

Requires Node ≥ 18. Add to the client's MCP settings
(Cline: `cline_mcp_settings.json`; Claude Desktop: `claude_desktop_config.json`):

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

The bridge forwards to the hosted server and adds no logic of its own. No
environment variables, no API keys, nothing else to configure.

## Verify the install

Call `keyhalve_explain` with no arguments — a plain-language overview response
confirms the server is reachable.

## The three tools (all read-only, `readOnlyHint: true`)

- **`keyhalve_verify`** — Verify a KeyHalve-sealed document. Accepts a verify
  URL, the raw text of a KeyHalve QR code, or a document id (`vp_…`, `kh_…`,
  `cb_…`). Returns the cryptographic verdict; it NEVER decrypts sealed
  contents — any decryption key in the URL fragment is discarded unread.
- **`keyhalve_status`** — Live status of a sealed document by id: active,
  revoked (with reason/time), or outside its validity window. Status only.
- **`keyhalve_explain`** — Plain-language explanation of what a KeyHalve
  verification verdict means and why it can be trusted (blind rail,
  three-share custody, commitments, revocation).

## Building your own MCP server?

Mount the same verify toolset in one line:

```js
import { mountKeyhalveVerify } from "@keyhalve/verify-mcp";
mountKeyhalveVerify(server);
```

More: https://keyhalve.com/mcp · Privacy: https://keyhalve.com/privacy
