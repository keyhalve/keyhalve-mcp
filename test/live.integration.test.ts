/**
 * LIVE integration smoke — talks to the real platform APIs + the real rail.
 * Skipped in CI (network-dependent, non-hermetic); run locally with:
 *     LIVE=1 npx vitest run test/live.integration.test.ts
 * Exercises the exact handleMcpRequest path the Worker serves, minus workerd.
 */
import { describe, it, expect } from 'vitest';
import { handleMcpRequest } from '../src/mcp';

const live = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.LIVE === '1';

function post(body: unknown): Request {
  return new Request('https://mcp.keyhalve.com/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe.skipIf(!live)('live integration (real network)', () => {
  it('initialize + tools/list round-trip', async () => {
    const init = await handleMcpRequest(post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }));
    expect(((await init.json()) as any).result.serverInfo.name).toBe('keyhalve-verify');
    const list = await handleMcpRequest(post({ jsonrpc: '2.0', id: 2, method: 'tools/list' }));
    expect(((await list.json()) as any).result.tools).toHaveLength(3);
  });

  it('keyhalve_status: unknown-but-well-formed vp_ id → not_found from the LIVE ValidPay API', async () => {
    const res = await handleMcpRequest(
      post({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'keyhalve_status', arguments: { document_id: 'vp_zzzzzzzzzzzz' } } }),
    );
    const out = (await res.json()) as any;
    expect(out.result.isError).toBe(true);
    expect(out.result.structuredContent.error).toBe('not_found');
  }, 20_000);

  it('keyhalve_verify: unknown cb_ id → not_found from the LIVE CheckBooks API (and any pasted key is discarded)', async () => {
    const res = await handleMcpRequest(
      post({
        jsonrpc: '2.0', id: 4, method: 'tools/call',
        params: { name: 'keyhalve_verify', arguments: { input: 'https://verify.keyhalve.com/verify/cb_zzzzzzzzzzzz#key=FAKEKEY' } },
      }),
    );
    const body = JSON.stringify(await res.json());
    expect(body).toContain('not_found');
    expect(body).not.toContain('FAKEKEY');
  }, 20_000);

  it('the LIVE rail answers the piece route (bogus id → clean rail error, fail-closed)', async () => {
    const res = await fetch('https://rail.keyhalve.com/v1/piece/vp_zzzzzzzzzzzz', { headers: { Accept: 'application/json' } });
    // 404 (no share) or 403 (mac_required under enforcement) both prove the
    // rail is reachable and refusing safely — never a 200 for a bogus id.
    expect([403, 404]).toContain(res.status);
  }, 20_000);
});
