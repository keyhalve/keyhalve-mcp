/**
 * Test-only shims: this repo types against @cloudflare/workers-types (the
 * worker is the product) and deliberately carries no @types/node. The bridge
 * test needs a handful of node builtins purely as a test harness — declare
 * them as untyped modules rather than dragging node's global types into the
 * worker's type universe.
 */
declare module 'node:child_process';
declare module 'node:http';
declare module 'node:url';
declare module 'node:path';

interface ImportMeta {
  url: string;
}
