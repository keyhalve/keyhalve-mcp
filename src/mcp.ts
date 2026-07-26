/**
 * Minimal, STATELESS Model Context Protocol server over Streamable HTTP.
 *
 * Deliberately hand-rolled instead of pulling in the reference SDK: this is a
 * public, security-adjacent KeyHalve surface, so the whole protocol layer must
 * be small enough to audit line-by-line, with zero runtime dependencies (the
 * same reasoning as the pinned-key rail client). The server is stateless by
 * design — every tool is a pure read of public verification state, so there
 * are no sessions, no SSE streams, and no server-initiated messages; every
 * POST gets a plain application/json reply (permitted by the Streamable HTTP
 * transport spec).
 */

import { TOOLS, toolVerify, toolStatus, toolExplain } from './tools';
import { VerifyError } from './verifier';

const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const LATEST_PROTOCOL_VERSION = '2025-06-18';

export const SERVER_INFO = {
  name: 'keyhalve-verify',
  title: 'KeyHalve — verify sealed documents',
  version: '1.0.0',
};

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

type JsonRpcResponse = { jsonrpc: '2.0'; id: string | number | null } & (
  | { result: unknown }
  | { error: { code: number; message: string; data?: unknown } }
);

function rpcResult(id: string | number | null, result: unknown): JsonRpcResponse {
  return { jsonrpc: '2.0', id, result };
}
function rpcError(id: string | number | null, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/** Tool output: JSON pretty-printed as text content + structuredContent, so
 *  both plain-text and structured-aware MCP clients get the full result. */
function toolContent(result: Record<string, unknown>, isError = false) {
  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    structuredContent: result,
    isError,
  };
}

async function callTool(name: string, args: Record<string, unknown>): Promise<ReturnType<typeof toolContent>> {
  try {
    switch (name) {
      case 'keyhalve_verify':
        return toolContent(await toolVerify(args));
      case 'keyhalve_status':
        return toolContent(await toolStatus(args));
      case 'keyhalve_explain':
        return toolContent(toolExplain(args));
      default:
        return toolContent({ error: 'unknown_tool', message: `No such tool: ${name}` }, true);
    }
  } catch (e) {
    // Tool-level failures (bad input, unreachable platform, failed crypto)
    // are ordinary results with isError — not protocol errors — so the model
    // can read them and explain honestly. Fail closed, never fabricate.
    if (e instanceof VerifyError) return toolContent({ error: e.code, message: e.message }, true);
    return toolContent({ error: 'internal', message: 'Verification failed unexpectedly — treat the document as UNVERIFIED.' }, true);
  }
}

async function handleMessage(msg: JsonRpcRequest): Promise<JsonRpcResponse | null> {
  const id = msg.id ?? null;
  if (msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return rpcError(id, -32600, 'Invalid Request');
  }
  // Notifications (no id) get no response body.
  const isNotification = msg.id === undefined;

  switch (msg.method) {
    case 'initialize': {
      const requested = (msg.params?.protocolVersion as string) ?? '';
      const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : LATEST_PROTOCOL_VERSION;
      return rpcResult(id, {
        protocolVersion,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
        instructions:
          'Free, public verification of KeyHalve-sealed documents (from any platform on the rail: ValidPay, CheckBooks, …). Use keyhalve_verify with a verify URL or QR text. This server never receives decryption keys — sealed contents remain readable only in the holder\'s browser.',
      });
    }
    case 'ping':
      return rpcResult(id, {});
    case 'tools/list':
      return rpcResult(id, { tools: TOOLS });
    case 'tools/call': {
      const name = (msg.params?.name as string) ?? '';
      const args = (msg.params?.arguments as Record<string, unknown>) ?? {};
      return rpcResult(id, await callTool(name, args));
    }
    default:
      if (isNotification) return null; // notifications/initialized, cancelled, …
      return rpcError(id, -32601, `Method not found: ${msg.method}`);
  }
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id',
  'Access-Control-Max-Age': '86400',
};

export async function handleMcpRequest(request: Request): Promise<Response> {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });
  if (request.method === 'GET') {
    // Stateless server: no SSE stream to open.
    return new Response(JSON.stringify({ error: 'This MCP server is stateless — POST JSON-RPC messages to this endpoint.' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', Allow: 'POST, OPTIONS', ...CORS_HEADERS },
    });
  }
  if (request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { Allow: 'POST, GET, OPTIONS', ...CORS_HEADERS } });
  }

  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    return new Response(JSON.stringify(rpcError(null, -32700, 'Parse error')), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
    });
  }

  const messages: JsonRpcRequest[] = Array.isArray(parsed) ? parsed : [parsed as JsonRpcRequest];
  if (messages.length === 0) {
    return new Response(JSON.stringify(rpcError(null, -32600, 'Invalid Request')), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
    });
  }

  const responses = (await Promise.all(messages.map(handleMessage))).filter((r): r is JsonRpcResponse => r !== null);

  // All-notification batch → accepted, nothing to say.
  if (responses.length === 0) return new Response(null, { status: 202, headers: CORS_HEADERS });

  const body = Array.isArray(parsed) ? responses : responses[0];
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json', ...CORS_HEADERS } });
}
