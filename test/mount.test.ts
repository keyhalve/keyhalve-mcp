/**
 * mountKeyhalveVerify (Prompt 177).
 *
 * - DRIFT PIN: the library's fixed tool copy must byte-match the worker's
 *   TOOLS — the mount proxies to the worker, so the two surfaces must never
 *   diverge. This test IS the enforcement.
 * - Scratch-server mount: a real @modelcontextprotocol/sdk McpServer +
 *   Client over an in-memory transport pair — tools/list shows the fixed
 *   copy (+ credit line), calls proxy to a stubbed worker and relay its
 *   result verbatim, unreachable worker fails closed as UNVERIFIED.
 * - LIVE (LIVE=1): the mounted keyhalve_explain round-trips against the real
 *   hosted worker.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
// @ts-expect-error untyped .mjs internals (types ship via lib/index.d.ts)
import { mountKeyhalveVerify, KEYHALVE_MCP_URL, CREDIT_LINE, KEYHALVE_VERIFY_TOOLS } from '../npm/lib/index.mjs';
import { TOOLS } from '../src/tools';

const live = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.LIVE === '1';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function scratchPair(opts?: { baseUrl?: string; toolPrefix?: string }) {
  const server = new McpServer({ name: 'scratch-host', version: '0.0.1' });
  mountKeyhalveVerify(server, opts);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'scratch-client', version: '0.0.1' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { server, client };
}

describe('drift pin — library copy vs worker TOOLS', () => {
  it('names, descriptions, schemas, and annotations byte-match the worker', () => {
    expect(KEYHALVE_VERIFY_TOOLS.length).toBe(TOOLS.length);
    for (let i = 0; i < TOOLS.length; i++) {
      expect(JSON.stringify(KEYHALVE_VERIFY_TOOLS[i])).toBe(JSON.stringify(TOOLS[i]));
    }
  });
});

describe('mountKeyhalveVerify — scratch SDK server', () => {
  it('lists the three tools with fixed descriptions + credit line + annotations', async () => {
    const { client } = await scratchPair();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['keyhalve_explain', 'keyhalve_status', 'keyhalve_verify']);
    for (const t of tools) {
      const fixed = KEYHALVE_VERIFY_TOOLS.find((f: { name: string }) => f.name === t.name)!;
      expect(t.description).toBe(`${fixed.description}\n\n(${CREDIT_LINE})`);
      expect(t.annotations?.readOnlyHint).toBe(true);
      expect(t.annotations?.title).toBe(fixed.annotations.title);
      // schema survives the SDK's zod round-trip: same properties + required
      const props = (t.inputSchema as { properties?: Record<string, { description?: string }> }).properties ?? {};
      for (const [key, prop] of Object.entries(fixed.inputSchema.properties)) {
        expect(props[key]).toBeDefined();
        expect(props[key]?.description).toBe((prop as { description?: string }).description);
      }
      expect((t.inputSchema as { required?: string[] }).required ?? []).toEqual(fixed.inputSchema.required ?? []);
    }
  });

  it('proxies tools/call to the worker with the canonical name and relays the result verbatim', async () => {
    const seen: { url?: string; body?: any; headers?: Record<string, string> } = {};
    const workerResult = {
      content: [{ type: 'text', text: '{"verdict":"SEAL VERIFIED"}' }],
      structuredContent: { verdict: 'SEAL VERIFIED' },
      isError: false,
    };
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      seen.url = String(url);
      seen.body = JSON.parse(String(init.body));
      seen.headers = init.headers as Record<string, string>;
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: workerResult }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }));
    const { client } = await scratchPair();
    const res = await client.callTool({ name: 'keyhalve_verify', arguments: { input: 'vp_zzzzzzzzzzzz' } });
    expect(seen.url).toBe(KEYHALVE_MCP_URL);
    expect(seen.body.method).toBe('tools/call');
    expect(seen.body.params).toEqual({ name: 'keyhalve_verify', arguments: { input: 'vp_zzzzzzzzzzzz' } });
    expect(seen.headers?.['Mcp-Method']).toBe('tools/call');
    expect(seen.headers?.['Mcp-Name']).toBe('keyhalve_verify');
    expect(res.structuredContent).toEqual(workerResult.structuredContent);
    expect(res.content).toEqual(workerResult.content);
    expect(res.isError).toBeFalsy();
  });

  it('relays worker isError results untouched (tool-level failures stay results)', async () => {
    const errResult = {
      content: [{ type: 'text', text: '{"error":"not_found"}' }],
      structuredContent: { error: 'not_found' },
      isError: true,
    };
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: errResult }), { status: 200 }),
    ));
    const { client } = await scratchPair();
    const res = await client.callTool({ name: 'keyhalve_status', arguments: { document_id: 'vp_missing000' } });
    expect(res.isError).toBe(true);
    expect(res.structuredContent).toEqual({ error: 'not_found' });
  });

  it('fails closed as UNVERIFIED when the worker is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('net down'); }));
    const { client } = await scratchPair();
    const res = await client.callTool({ name: 'keyhalve_verify', arguments: { input: 'vp_zzzzzzzzzzzz' } });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain('UNVERIFIED');
  });

  it('fails closed on an rpc-error envelope', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32603, message: 'boom' } }), { status: 500 }),
    ));
    const { client } = await scratchPair();
    const res = await client.callTool({ name: 'keyhalve_explain', arguments: {} });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain('UNVERIFIED');
  });

  it('toolPrefix renames the tools only — canonical name still crosses the wire, copy unchanged', async () => {
    const seen: { body?: any } = {};
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
      seen.body = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [], isError: false } }), { status: 200 });
    }));
    const { client } = await scratchPair({ toolPrefix: 'vp_' });
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['vp_keyhalve_explain', 'vp_keyhalve_status', 'vp_keyhalve_verify']);
    for (const t of tools) {
      const fixed = KEYHALVE_VERIFY_TOOLS.find((f: { name: string }) => `vp_${f.name}` === t.name)!;
      expect(t.description).toBe(`${fixed.description}\n\n(${CREDIT_LINE})`);
    }
    await client.callTool({ name: 'vp_keyhalve_verify', arguments: { input: 'vp_zzzzzzzzzzzz' } });
    expect(seen.body.params.name).toBe('keyhalve_verify');
  });

  it('rejects a non-server argument and an unsafe prefix', async () => {
    expect(() => mountKeyhalveVerify(undefined)).toThrow(/registerTool/);
    const server = new McpServer({ name: 's', version: '0' });
    expect(() => mountKeyhalveVerify(server, { toolPrefix: 'bad prefix!' })).toThrow(/toolPrefix/);
  });
});

describe.skipIf(!live)('mountKeyhalveVerify — LIVE hosted worker', () => {
  it('mounted keyhalve_explain round-trips against mcp.keyhalve.com', async () => {
    const { client } = await scratchPair();
    const res = await client.callTool({ name: 'keyhalve_explain', arguments: { topic: 'verdict' } });
    expect(res.isError).toBeFalsy();
    expect(JSON.stringify(res.content)).toMatch(/verdict/i);
  });
});
