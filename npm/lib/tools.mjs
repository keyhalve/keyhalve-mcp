/**
 * @keyhalve/verify-mcp — the LIBRARY-FIXED tool copy (Prompt 177, ruling 2).
 *
 * Names, descriptions, schemas, annotations, and the credit line are constants
 * the mounting host CANNOT override through the public API. They are a
 * byte-for-byte copy of the hosted worker's TOOLS (src/tools.ts) — pinned by
 * test/mount.test.ts, which fails the build if the two ever drift. Claims
 * language is the approved register's; do not edit here without editing the
 * worker (and vice versa).
 */

export const CREDIT_LINE =
  'verification via the KeyHalve rail — free, neutral, the AI never reads the document';

export const EXPLAIN_TOPICS = [
  'verdict',
  'blindness',
  'rail',
  'revocation',
  'integrity',
  'issuer_trust',
  'limits',
];

export const KEYHALVE_VERIFY_TOOLS = [
  {
    name: 'keyhalve_verify',
    description:
      "Verify a KeyHalve-sealed document. Accepts a verify URL, the raw text of a KeyHalve QR code, or a document id (vp_…, kh_…, cb_…). Returns the cryptographic verdict: whether the seal exists, its live status (active/revoked/expired), ciphertext integrity against the issuance commitment, the KeyHalve rail's independent attestation, the validity window, and the issuer's trust context. This tool NEVER decrypts sealed contents — any decryption key in the URL fragment is discarded unread; contents are only readable by opening the verify URL in a browser.",
    inputSchema: {
      type: 'object',
      properties: {
        input: {
          type: 'string',
          description: 'A KeyHalve verify URL, QR-code text, or bare document id.',
        },
      },
      required: ['input'],
    },
    annotations: { title: 'Verify a sealed document', readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'keyhalve_status',
    description:
      'Live status of a KeyHalve-sealed document by id: active, revoked (with reason/time), or outside its validity window. Lighter than keyhalve_verify — status only, no integrity or rail checks. Use for "is this still good right now?"',
    inputSchema: {
      type: 'object',
      properties: {
        document_id: { type: 'string', description: 'The document id, e.g. vp_…, kh_…, cb_….' },
      },
      required: ['document_id'],
    },
    annotations: { title: 'Check live document status', readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'keyhalve_explain',
    description:
      'Plain-language explanation of what a KeyHalve verification verdict means and why it can be trusted (blind rail, split keys, commitments, revocation). Optionally focused on one topic.',
    inputSchema: {
      type: 'object',
      properties: {
        topic: {
          type: 'string',
          enum: [...EXPLAIN_TOPICS],
          description: 'Optional single topic; omit for the overview.',
        },
      },
    },
    annotations: { title: 'Explain a KeyHalve verdict', readOnlyHint: true, openWorldHint: false },
  },
];
