import { describe, it, expect, vi, afterEach } from 'vitest';
import { handleMcpRequest } from '../src/mcp';

function post(body: unknown): Request {
  return new Request('https://mcp.keyhalve.com/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

afterEach(() => vi.restoreAllMocks());

describe('MCP protocol (stateless Streamable HTTP)', () => {
  it('initialize negotiates a supported protocol version', async () => {
    const res = await handleMcpRequest(post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } }));
    const json = (await res.json()) as any;
    expect(json.result.protocolVersion).toBe('2025-03-26');
    expect(json.result.serverInfo.name).toBe('keyhalve-verify');
    expect(json.result.capabilities.tools).toBeDefined();
  });

  it('initialize falls back to the latest version for unknown requests', async () => {
    const res = await handleMcpRequest(post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '9999-01-01' } }));
    const json = (await res.json()) as any;
    expect(json.result.protocolVersion).toBe('2025-06-18');
  });

  it('notifications get 202 with no body', async () => {
    const res = await handleMcpRequest(post({ jsonrpc: '2.0', method: 'notifications/initialized' }));
    expect(res.status).toBe(202);
  });

  it('tools/list exposes the three tools with read-only annotations', async () => {
    const res = await handleMcpRequest(post({ jsonrpc: '2.0', id: 2, method: 'tools/list' }));
    const json = (await res.json()) as any;
    const names = json.result.tools.map((t: any) => t.name);
    expect(names).toEqual(['keyhalve_verify', 'keyhalve_status', 'keyhalve_explain']);
    for (const t of json.result.tools) expect(t.annotations.readOnlyHint).toBe(true);
  });

  it('unknown method → -32601; malformed JSON → parse error; GET → 405', async () => {
    const bad = await handleMcpRequest(post({ jsonrpc: '2.0', id: 3, method: 'resources/list' }));
    expect(((await bad.json()) as any).error.code).toBe(-32601);

    const parse = await handleMcpRequest(
      new Request('https://mcp.keyhalve.com/mcp', { method: 'POST', body: '{nope' }),
    );
    expect(parse.status).toBe(400);
    expect(((await parse.json()) as any).error.code).toBe(-32700);

    const get = await handleMcpRequest(new Request('https://mcp.keyhalve.com/mcp'));
    expect(get.status).toBe(405);
  });

  it('keyhalve_explain works end-to-end through tools/call', async () => {
    const res = await handleMcpRequest(
      post({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'keyhalve_explain', arguments: { topic: 'blindness' } } }),
    );
    const json = (await res.json()) as any;
    expect(json.result.isError).toBe(false);
    expect(json.result.structuredContent.topic).toBe('blindness');
    expect(json.result.content[0].text).toContain('browser');
  });

  it('a tool failure is an isError RESULT, not a protocol error', async () => {
    const res = await handleMcpRequest(
      post({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'keyhalve_verify', arguments: { input: 'garbage' } } }),
    );
    const json = (await res.json()) as any;
    expect(json.error).toBeUndefined();
    expect(json.result.isError).toBe(true);
    expect(json.result.structuredContent.error).toBe('unrecognized_input');
  });

  it('unknown tool → isError result', async () => {
    const res = await handleMcpRequest(post({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'nope', arguments: {} } }));
    const json = (await res.json()) as any;
    expect(json.result.isError).toBe(true);
  });
});

describe('tools with mocked network', () => {
  const INTENT = {
    intent_id: 'vp_abc123',
    issuer: 'Acme Rentals LLC',
    issuer_verified: true,
    verification_level: 'domain',
    verified_domains: ['acme.example'],
    status: 'active',
    encrypted_payload: 'payload',
    commitment_hash: '239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5',
    commitment_version: 2,
    document_type: 'lease',
    registered_at: '2026-07-01T00:00:00Z',
  };

  it('keyhalve_verify: SEAL VERIFIED with integrity verified + key-discard note', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const u = String(input);
        if (u.includes('/v1/intent/')) return new Response(JSON.stringify(INTENT), { status: 200 });
        if (u.includes('/v1/piece/')) return new Response(JSON.stringify({ error: 'mac_required' }), { status: 403 });
        return new Response('not found', { status: 404 });
      }),
    );
    const res = await handleMcpRequest(
      post({
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: { name: 'keyhalve_verify', arguments: { input: 'https://verify.keyhalve.com/verify/vp_abc123#key=SECRET' } },
      }),
    );
    const json = (await res.json()) as any;
    const out = json.result.structuredContent;
    expect(json.result.isError).toBe(false);
    expect(out.verdict).toBe('SEAL VERIFIED');
    expect(out.checks.ciphertext_integrity.state).toBe('verified');
    expect(out.checks.rail_attestation.state).toBe('mac_required');
    expect(out.notes.join(' ')).toContain('DISCARDED UNREAD');
    // The key must appear NOWHERE in the response.
    expect(JSON.stringify(json)).not.toContain('SECRET');
  });

  it('keyhalve_verify: tampered ciphertext → FAILED verdict', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const u = String(input);
        if (u.includes('/v1/intent/'))
          return new Response(JSON.stringify({ ...INTENT, commitment_hash: 'f'.repeat(64) }), { status: 200 });
        if (u.includes('/v1/piece/')) return new Response('nope', { status: 404 });
        return new Response('not found', { status: 404 });
      }),
    );
    const res = await handleMcpRequest(
      post({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'keyhalve_verify', arguments: { input: 'vp_abc123' } } }),
    );
    const out = ((await res.json()) as any).result.structuredContent;
    expect(out.verdict).toBe('FAILED — DO NOT TRUST');
    expect(out.checks.ciphertext_integrity.state).toBe('failed');
  });

  it('keyhalve_verify: revoked document', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({ intent_id: 'vp_abc123', status: 'revoked', encrypted_payload: null, revoked_at: '2026-07-20T00:00:00Z', revocation_reason: 'reissued' }),
          { status: 200 },
        ),
      ),
    );
    const res = await handleMcpRequest(
      post({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'keyhalve_verify', arguments: { input: 'vp_abc123' } } }),
    );
    const out = ((await res.json()) as any).result.structuredContent;
    expect(out.verdict).toBe('REVOKED');
    expect(out.revocation_reason).toBe('reissued');
  });

  it('keyhalve_status: light status with validity window', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ ...INTENT, valid_until: '2026-01-01T00:00:00Z' }), { status: 200 }),
      ),
    );
    const res = await handleMcpRequest(
      post({ jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'keyhalve_status', arguments: { document_id: 'vp_abc123' } } }),
    );
    const out = ((await res.json()) as any).result.structuredContent;
    expect(out.status).toBe('expired');
  });

  it('keyhalve_verify: unknown document → not_found isError', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 404 })));
    const res = await handleMcpRequest(
      post({ jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'keyhalve_verify', arguments: { input: 'vp_missing1' } } }),
    );
    const json = (await res.json()) as any;
    expect(json.result.isError).toBe(true);
    expect(json.result.structuredContent.error).toBe('not_found');
  });
});
