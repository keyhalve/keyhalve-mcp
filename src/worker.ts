/**
 * Cloudflare Worker entry — mcp.keyhalve.com.
 *
 * Routes:
 *   POST /mcp  — the Model Context Protocol endpoint (Streamable HTTP, stateless)
 *   GET  /     — human/robot-readable service description
 *   GET  /health — liveness for the watchdog
 *
 * Nothing is stored: no KV, no logs of request bodies, no cookies. The worker
 * is a pure ephemeral verifier client of public APIs, like any browser tab.
 */

import { handleMcpRequest, SERVER_INFO } from './mcp';

const DESCRIPTION = {
  service: SERVER_INFO.name,
  version: SERVER_INFO.version,
  what: 'Free, public, no-account MCP server for verifying KeyHalve-sealed documents from any platform on the rail.',
  endpoint: { transport: 'streamable-http', url: 'https://mcp.keyhalve.com/mcp' },
  tools: ['keyhalve_verify', 'keyhalve_status', 'keyhalve_explain'],
  privacy:
    'This server never receives decryption keys (URL #key= fragments are discarded unread), stores nothing, and cannot read sealed documents. Decryption happens only in the document holder\'s browser.',
  docs: 'https://keyhalve.com',
};

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/mcp') return await handleMcpRequest(request);
      if (url.pathname === '/health') {
        return new Response(JSON.stringify({ ok: true, service: SERVER_INFO.name }), {
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.pathname === '/') {
        return new Response(JSON.stringify(DESCRIPTION, null, 2), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        });
      }
      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
    } catch {
      // Fail closed with a structured error — never a bare 1101 page.
      return new Response(JSON.stringify({ error: 'internal' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  },
} satisfies ExportedHandler;
