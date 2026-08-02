/**
 * mountKeyhalveVerify — embed KeyHalve verification in any MCP server
 * (Prompt 177; strategy/DISTRIBUTION-BY-DESIGN.md mechanism 1).
 *
 *   import { mountKeyhalveVerify } from "@keyhalve/verify-mcp";
 *   mountKeyhalveVerify(server);
 *
 * Design rulings (Command, 2026-08-02 — firm):
 *   1. NO verdict logic here. Handlers PROXY tools/call to the hosted worker
 *      (mcp.keyhalve.com POST /mcp) and relay its result verbatim. Verdict
 *      behavior stays server-side: a tenant pinning an old library version
 *      still gets current verdicts.
 *   2. Trust copy is library-fixed (see tools.mjs). The host cannot override
 *      names, descriptions, the credit line, or annotations through this API.
 *      `toolPrefix` changes the NAME only — the proxied call always uses the
 *      canonical name, and descriptions/credit are untouched.
 *   3. One-way bundling: this export is verify-only, forever. There is
 *      deliberately no generic mount that takes a tool list.
 *
 * The library never imports @modelcontextprotocol/sdk — it only calls
 * `server.registerTool(...)`, so the SDK stays a loose (optional) peer and the
 * stdio bin keeps working with zero of this in its path. `zod` is required for
 * the input shapes the host SDK consumes.
 */

import { z } from 'zod';
import { CREDIT_LINE, KEYHALVE_VERIFY_TOOLS } from './tools.mjs';

export const KEYHALVE_MCP_URL = 'https://mcp.keyhalve.com/mcp';

const PREFIX_RE = /^[A-Za-z0-9_-]*$/;
const PROXY_TIMEOUT_MS = 30_000;

/** zod input shapes mirroring the fixed JSON schemas (same property names,
 *  same descriptions, same required/optional split). */
function zodShapeFor(tool) {
  const shape = {};
  const required = tool.inputSchema.required ?? [];
  for (const [key, prop] of Object.entries(tool.inputSchema.properties)) {
    let s = Array.isArray(prop.enum) ? z.enum(prop.enum) : z.string();
    if (prop.description) s = s.describe(prop.description);
    if (!required.includes(key)) s = s.optional();
    shape[key] = s;
  }
  return shape;
}

/** Fail-closed result when the hosted worker cannot answer. */
function unverifiedResult(baseUrl, detail) {
  const msg = `KeyHalve verification endpoint unreachable (${baseUrl}) — treat the document as UNVERIFIED. ${detail}`;
  return {
    content: [{ type: 'text', text: msg }],
    structuredContent: { error: 'keyhalve_unreachable', message: msg },
    isError: true,
  };
}

async function proxyCall(baseUrl, toolName, args) {
  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: toolName, arguments: args ?? {} },
  });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        // 2026-07-28 spec routing headers — derived from the body, so they can
        // never disagree with it.
        'Mcp-Method': 'tools/call',
        'Mcp-Name': toolName,
      },
      body,
      signal: controller.signal,
    });
  } catch (e) {
    return unverifiedResult(baseUrl, String((e && e.message) || e));
  } finally {
    clearTimeout(timer);
  }
  let json;
  try {
    json = await res.json();
  } catch {
    return unverifiedResult(baseUrl, `non-JSON response (HTTP ${res.status})`);
  }
  if (!res.ok || !json || typeof json !== 'object' || json.error || !json.result) {
    const detail = json && json.error ? `rpc error ${json.error.code}: ${json.error.message}` : `HTTP ${res.status}`;
    return unverifiedResult(baseUrl, detail);
  }
  // The worker's tools/call result IS a CallToolResult
  // ({content, structuredContent, isError}) — relay it verbatim.
  return json.result;
}

/**
 * Mount the KeyHalve verify toolset onto an MCP server.
 *
 * @param {{ registerTool: Function }} server — an McpServer from
 *   @modelcontextprotocol/sdk (any object exposing `registerTool`).
 * @param {{ baseUrl?: string, toolPrefix?: string }} [opts]
 *   baseUrl — the hosted verify endpoint (default: production worker);
 *   toolPrefix — prepended to tool NAMES only (collision escape hatch);
 *   descriptions, credit line, and proxied canonical names are unaffected.
 */
export function mountKeyhalveVerify(server, opts = {}) {
  if (!server || typeof server.registerTool !== 'function') {
    throw new TypeError(
      'mountKeyhalveVerify: pass an MCP server exposing registerTool(...) (an McpServer from @modelcontextprotocol/sdk)',
    );
  }
  const baseUrl = opts.baseUrl ?? KEYHALVE_MCP_URL;
  const prefix = opts.toolPrefix ?? '';
  if (!PREFIX_RE.test(prefix)) {
    throw new TypeError('mountKeyhalveVerify: toolPrefix may only contain [A-Za-z0-9_-]');
  }
  for (const tool of KEYHALVE_VERIFY_TOOLS) {
    server.registerTool(
      `${prefix}${tool.name}`,
      {
        // Library-fixed trust copy: worker description + the credit line.
        description: `${tool.description}\n\n(${CREDIT_LINE})`,
        inputSchema: zodShapeFor(tool),
        annotations: { ...tool.annotations },
      },
      (args) => proxyCall(baseUrl, tool.name, args),
    );
  }
}
