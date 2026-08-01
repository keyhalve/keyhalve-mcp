# Official MCP Registry — publish runbook (com.keyhalve/verify)

Assets in this repo are publish-READY (Prompt 166). **Every step below is
gated: [BOX] runs the bootstrap, Mike gives the publish go.** Nothing here
runs automatically until both have happened.

## What publishing does

One `mcp-publisher publish` of `server.json` lists the server on
registry.modelcontextprotocol.io, which auto-propagates to the GitHub MCP
Registry → VS Code's in-product MCP gallery → PulseMCP → JetBrains/Zed
discovery. The entry carries BOTH the remote endpoint
(`https://mcp.keyhalve.com/mcp`) and the npm stdio package
(`@keyhalve/verify-mcp`).

## [BOX] one-time bootstrap (in order)

1. **npm token** — on the npm `keyhalve` org, create an *automation* token
   with publish rights to the `@keyhalve` scope. Add it as repo secret
   `NPM_TOKEN` on `keyhalve/keyhalve-mcp`.

2. **Ed25519 keypair** (any machine with OpenSSL ≥ 3.0):

   ```bash
   openssl genpkey -algorithm Ed25519 -out keyhalve-mcp-registry.pem
   PUBLIC_KEY="$(openssl pkey -in keyhalve-mcp-registry.pem -pubout -outform DER | tail -c 32 | base64)"
   PRIVATE_KEY="$(openssl pkey -in keyhalve-mcp-registry.pem -noout -text | grep -A3 "priv:" | tail -n +2 | tr -d ' :\n')"
   echo "TXT record: keyhalve.com. IN TXT \"v=MCPv1; k=ed25519; p=${PUBLIC_KEY}\""
   ```

   Store `keyhalve-mcp-registry.pem` with the other KeyHalve key material
   (Mike's offline custody); add the hex `PRIVATE_KEY` as repo secret
   `MCP_PRIVATE_KEY`.

3. **DNS TXT record** (Cloudflare, keyhalve.com zone — [BOX] holds the CF
   keys): add the TXT record from step 2 **on the apex** (`keyhalve.com`),
   NOT under a selector like `_mcp-auth.keyhalve.com` — the registry follows
   SPF-style placement and will not see a selector record. If the key is ever
   rotated, delete the old TXT record; a stale one is tried first and fails
   verification.

4. *(Recommended, from the distribution map)* While in Cloudflare: confirm no
   rule challenges `SmitheryBot/1.0` or unauthenticated traffic to
   `mcp.keyhalve.com` — directory validators probe anonymously.

## Publish (Mike-gated)

After the bootstrap, Mike dispatches the `publish-mcp` workflow (Actions →
publish-mcp → Run workflow). It:

1. fails fast if either secret is missing,
2. runs typecheck + the full test suite,
3. sanity-checks `server.json` ↔ `npm/package.json` (version + mcpName),
4. `npm publish --access public` of `npm/` (the standing SDK publish gate
   applies — this IS the gated npm publish),
5. `mcp-publisher login dns` + `publish`,
6. verifies the listing via the v0.1 search API.

Subsequent GitHub **releases** auto-republish so the registry tracks
versions. Cutting a release is itself Mike-gated by repo convention, so no
unattended publish path exists.

## Verify after publish

```bash
curl -s "https://registry.modelcontextprotocol.io/v0.1/servers?search=com.keyhalve/verify"
```

Then check github.com/mcp (propagation may lag) and VS Code's Extensions view
(`@mcp` search).
