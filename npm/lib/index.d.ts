/**
 * @keyhalve/verify-mcp — library surface (the stdio bridge is the package bin).
 *
 * The mount is verify-only, forever (one-way bundling ruling). Trust copy —
 * tool names, descriptions, credit line, annotations — is library-fixed and
 * not overridable through this API; `toolPrefix` renames tools only.
 */

/** JSON-schema shaped fixed tool copy (byte-matched to the hosted worker). */
export interface KeyhalveVerifyToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description?: string; enum?: string[] }>;
    required?: string[];
  };
  annotations: { title: string; readOnlyHint: boolean; openWorldHint: boolean };
}

export declare const KEYHALVE_MCP_URL: string;
export declare const CREDIT_LINE: string;
export declare const KEYHALVE_VERIFY_TOOLS: KeyhalveVerifyToolDef[];

export interface MountKeyhalveVerifyOptions {
  /** Hosted verify endpoint. Default: https://mcp.keyhalve.com/mcp (production). */
  baseUrl?: string;
  /** Prepended to tool NAMES only (collision escape hatch, [A-Za-z0-9_-]*).
   *  Descriptions, the credit line, and the proxied canonical names are unaffected. */
  toolPrefix?: string;
}

/**
 * Mount the KeyHalve verify toolset onto an MCP server. `server` is an
 * McpServer from @modelcontextprotocol/sdk — typed structurally so the SDK
 * stays an optional peer dependency.
 */
export declare function mountKeyhalveVerify(
  server: { registerTool: (name: string, config: object, cb: (args: any) => unknown) => unknown },
  opts?: MountKeyhalveVerifyOptions,
): void;
