/**
 * Node adapter for LOCAL TESTING ONLY — serves the exact Worker fetch handler
 * over node:http so a tunnel can expose it to a real chat client before the
 * Cloudflare deploy exists. Not part of the production path. workerd crashes
 * on this Windows box (access violation), hence this bridge.
 *
 *   npx esbuild scripts/node-entry.ts --bundle --format=esm --platform=node --outfile=dist/server.mjs
 *   node dist/server.mjs
 */
import worker from '../src/worker';
import { createServer } from 'node:http';

const PORT = Number(process.env.PORT || 8787);

createServer(async (req, res) => {
  try {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers[k] = v;
    const request = new Request(`http://localhost:${PORT}${req.url ?? '/'}`, {
      method: req.method ?? 'GET',
      headers,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
    });
    const response = await (worker as { fetch(r: Request): Promise<Response> }).fetch(request);
    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end('{"error":"internal"}');
  }
}).listen(PORT, () => console.log(`keyhalve verify-MCP (node adapter) on http://localhost:${PORT}`));
