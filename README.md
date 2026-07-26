# KeyHalve verify-MCP

Free, public, no-account [MCP](https://modelcontextprotocol.io) server that lets any AI verify
KeyHalve-sealed documents — from **any** platform on the rail (ValidPay, CheckBooks, …).
*Seal = the door (a platform's paid MCP). Verify = the room (this one, free forever).*

- **Endpoint:** `https://mcp.keyhalve.com/mcp` (Streamable HTTP, stateless)
- **Tools:** `keyhalve_verify` · `keyhalve_status` · `keyhalve_explain` — all read-only, no auth

## The blindness rule

This server **never receives decryption keys.** A verify URL carries the holder's key share in
the `#key=` fragment; `parseInput` discards any fragment **before any other logic runs**, and the
response says so. Verification here covers everything provable *without* the key:

| Check | Meaning |
|---|---|
| status | active / revoked (with reason) on the issuing platform |
| ciphertext integrity | SHA-256 of the served ciphertext = commitment recorded at issuance (v2) |
| rail attestation | Ed25519-verified against the **pinned** rail key; dual-sign content binding when present |
| time lock | validity window judged client-side (Patent D semantics) |
| issuer trust | fail-closed: `declared` at best, never proof |

Reading the sealed contents still happens **only in the holder's browser** — exactly like the web
verifier. The overall verdict fails closed: any failed check → `FAILED — DO NOT TRUST`.

## Design notes

- **Zero runtime dependencies.** WebCrypto only; the whole protocol layer is hand-auditable.
  Same reasoning as the pinned-key rail client in `keyhalve-website`.
- **Stateless.** No sessions, no SSE, no KV, no cookies; every POST gets `application/json`.
  Request bodies are never logged.
- **Tenant-neutral.** Platforms come from the same manifest data as the web verifier
  (`TENANT_MANIFEST` in `src/verifier.ts`); onboarding a platform = one data entry.
- **Fail closed.** Unreachable rail, malformed share, partial dual-sign binding, unknown id
  prefix — all report NOT verified, never a soft pass.

## Develop / deploy

```
npm ci
npm run typecheck && npm test   # 32 tests
npm run dev                      # wrangler dev
```

Deploys are **manual** (`deploy.yml` via workflow_dispatch, same discipline as rail/console).
Needs the `CLOUDFLARE_API_TOKEN` repo secret; the route `mcp.keyhalve.com` is a custom domain
on the business CF account (same account as the watchdog scheduler).

## Directory submissions (Mike-gated)

Submitting to the Claude Connectors Directory / ChatGPT App Directory is an outward-facing
step — prepared separately, goes out only on Mike's go.
