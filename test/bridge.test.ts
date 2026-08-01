/**
 * npm/ stdio bridge tests.
 *
 * Hermetic part: spin a local HTTP server that mimics the worker's contract
 * (JSON responses, 202 for notifications) and drive the bridge subprocess over
 * stdio — proves framing, forwarding, notification silence, and the fail-closed
 * error path with no network.
 *
 * LIVE part (LIVE=1): same subprocess against the real mcp.keyhalve.com —
 * proves the published bridge works end-to-end.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
type Child = any; // untyped module shim — see node-shims.d.ts
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const BRIDGE = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'npm', 'bin', 'keyhalve-verify-mcp.mjs');
const live = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.LIVE === '1';

const children: Child[] = [];
const servers: any[] = [];
afterAll(() => {
  for (const c of children) c.kill();
  for (const s of servers) (s as any).close();
});

// This repo types against workers-types (the worker is the product), so node
// globals are reached via globalThis — same pattern as live.integration.test.ts.
const nodeProcess = (globalThis as any).process;

function startBridge(endpoint: string): Child {
  const child = spawn(nodeProcess.execPath, [BRIDGE], {
    env: { ...nodeProcess.env, KEYHALVE_MCP_URL: endpoint },
    stdio: 'pipe',
  });
  children.push(child);
  return child;
}

/** Send one message, resolve with the next stdout line (parsed). */
function roundTrip(child: Child, msg: unknown, timeoutMs = 15000): Promise<any> {
  return new Promise((resolvePromise, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error('bridge round-trip timeout')), timeoutMs);
    const onData = (chunk: any) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl !== -1) {
        clearTimeout(timer);
        child.stdout.off('data', onData);
        resolvePromise(JSON.parse(buf.slice(0, nl)));
      }
    };
    child.stdout.on('data', onData);
    child.stdin.write(JSON.stringify(msg) + '\n');
  });
}

describe('stdio bridge (hermetic, local mock endpoint)', () => {
  function mockEndpoint(handler: (body: any, headers: Record<string, string | string[] | undefined>) => { status: number; body?: unknown }): Promise<string> {
    return new Promise((resolvePromise) => {
      // Typed loosely: this repo types against workers-types (the worker is
      // the product); node:http here is test-harness only.
      const srv = createServer((req: any, res: any) => {
        let raw = '';
        req.on('data', (c: any) => (raw += c));
        req.on('end', () => {
          const out = handler(JSON.parse(raw), req.headers as Record<string, string>);
          res.writeHead(out.status, { 'Content-Type': 'application/json' });
          res.end(out.body === undefined ? undefined : JSON.stringify(out.body));
        });
      });
      servers.push(srv);
      srv.listen(0, '127.0.0.1', () => {
        const addr = srv.address() as { port: number };
        resolvePromise(`http://127.0.0.1:${addr.port}/mcp`);
      });
    });
  }

  it('forwards requests, mirrors Mcp-Method/Mcp-Name, relays the response', async () => {
    let seenHeaders: Record<string, string | string[] | undefined> = {};
    const url = await mockEndpoint((body, headers) => {
      seenHeaders = headers;
      return { status: 200, body: { jsonrpc: '2.0', id: body.id, result: { ok: true, echo: body.method } } };
    });
    const child = startBridge(url);
    const res = await roundTrip(child, {
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'keyhalve_explain', arguments: { topic: 'verdicts' } },
    });
    expect(res.id).toBe(7);
    expect(res.result.echo).toBe('tools/call');
    expect(seenHeaders['mcp-method']).toBe('tools/call');
    expect(seenHeaders['mcp-name']).toBe('keyhalve_explain');
  });

  it('notifications (202, no body) produce NO stdout line', async () => {
    const url = await mockEndpoint(() => ({ status: 202 }));
    const child = startBridge(url);
    let wrote = false;
    child.stdout.on('data', () => (wrote = true));
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    await new Promise((r) => setTimeout(r, 500));
    expect(wrote).toBe(false);
  });

  it('unreachable endpoint → structured fail-closed error, matching id', async () => {
    const child = startBridge('http://127.0.0.1:1/mcp');
    const res = await roundTrip(child, { jsonrpc: '2.0', id: 3, method: 'tools/list' });
    expect(res.id).toBe(3);
    expect(res.error.code).toBe(-32603);
    expect(res.error.message).toContain('UNVERIFIED');
  });
});

describe.skipIf(!live)('stdio bridge (LIVE endpoint)', () => {
  it('initialize + tools/list against mcp.keyhalve.com', async () => {
    const child = startBridge('https://mcp.keyhalve.com/mcp');
    const init = await roundTrip(child, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
    expect(init.result.serverInfo.name).toBe('keyhalve-verify');
    const list = await roundTrip(child, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    expect(list.result.tools).toHaveLength(3);
    for (const t of list.result.tools) expect(t.annotations.readOnlyHint).toBe(true);
  });
});
