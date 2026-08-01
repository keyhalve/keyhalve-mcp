#!/usr/bin/env node
/**
 * @keyhalve/verify-mcp — stdio → remote bridge.
 *
 * A thin MCP stdio server that forwards every JSON-RPC message, unmodified, to
 * the public KeyHalve verification endpoint (https://mcp.keyhalve.com/mcp) and
 * writes the responses back to stdout. The tools live server-side — this
 * bridge implements NO verification logic of its own, so local-only MCP
 * clients (`npx @keyhalve/verify-mcp`) get byte-identical behavior to the
 * remote Streamable HTTP endpoint.
 *
 * Zero dependencies; Node >= 18 (global fetch). Framing: newline-delimited
 * JSON per the MCP stdio transport.
 */

const ENDPOINT = process.env.KEYHALVE_MCP_URL ?? 'https://mcp.keyhalve.com/mcp';

/** Forward one JSON-RPC message; return the response body text ('' for none). */
async function forward(raw, msg) {
  const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
  // Mirror body fields into the 2026-07-28 spec's routing headers. Values are
  // derived from the body, so they can never disagree with it.
  if (typeof msg?.method === 'string') headers['Mcp-Method'] = msg.method;
  const name = msg?.params?.name ?? msg?.params?.uri;
  if (typeof name === 'string' && /^[\x21-\x7e]+$/.test(name)) headers['Mcp-Name'] = name;

  const res = await fetch(ENDPOINT, { method: 'POST', headers, body: raw });
  if (res.status === 202) return ''; // accepted notification — nothing to relay
  return await res.text();
}

function errorResponse(id, message) {
  return JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code: -32603, message } });
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let nl;
  while ((nl = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (line === '') continue;
    handleLine(line);
  }
});
process.stdin.on('end', () => process.exit(0));

function handleLine(line) {
  let msg = null;
  try {
    msg = JSON.parse(line);
  } catch {
    process.stdout.write(errorResponse(null, 'Parse error: stdin line was not valid JSON') + '\n');
    return;
  }
  const isNotification = !Array.isArray(msg) && msg?.id === undefined;
  forward(line, Array.isArray(msg) ? msg[0] : msg)
    .then((body) => {
      if (body !== '') process.stdout.write(body + '\n');
    })
    .catch(() => {
      // Fail closed, never silently: requests get a structured error the
      // client can surface; notifications have no reply channel.
      if (!isNotification) {
        process.stdout.write(
          errorResponse(msg?.id, `KeyHalve verification endpoint unreachable (${ENDPOINT}) — treat documents as UNVERIFIED.`) + '\n',
        );
      }
    });
}
