/**
 * The three verify-MCP tools. All public, no auth, read-only — verifying is
 * the rail's universal free surface ("seal = the door, verify = the room").
 * Every tool response is plain JSON-as-text so any MCP client can render it.
 */

import {
  parseInput,
  fetchIntent,
  checkIntegrity,
  checkRail,
  computeTimeLock,
  computeIdentityAssurance,
  VerifyError,
  TENANT_MANIFEST,
  type IntentResponse,
} from './verifier';
import { explain, EXPLAIN_TOPICS } from './explain';

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: Record<string, unknown>;
}

export const TOOLS: ToolDef[] = [
  {
    name: 'keyhalve_verify',
    description:
      'Verify a KeyHalve-sealed document. Accepts a verify URL, the raw text of a KeyHalve QR code, or a document id (vp_…, kh_…, cb_…). Returns the cryptographic verdict: whether the seal exists, its live status (active/revoked/expired), ciphertext integrity against the issuance commitment, the KeyHalve rail\'s independent attestation, the validity window, and the issuer\'s trust context. This tool NEVER decrypts sealed contents — any decryption key in the URL fragment is discarded unread; contents are only readable by opening the verify URL in a browser.',
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

/** Overall verdict, derived strictly fail-closed from the individual checks. */
function overallVerdict(opts: {
  status: string;
  integrityFailed: boolean;
  railFailed: boolean;
  timeLockState: string;
}): string {
  if (opts.integrityFailed || opts.railFailed) return 'FAILED — DO NOT TRUST';
  if (opts.status === 'revoked') return 'REVOKED';
  if (opts.timeLockState === 'expired') return 'EXPIRED';
  if (opts.timeLockState === 'not_yet_valid') return 'NOT YET VALID';
  return 'SEAL VERIFIED';
}

function issuerBlock(intent: IntentResponse) {
  return {
    name: intent.issuer ?? null,
    identity_assurance: computeIdentityAssurance(intent),
    verification_level: intent.verification_level ?? 'none',
    verified_domains: intent.verified_domains ?? [],
    delegated_by: intent.delegated_by ?? null,
    issuer_verified_at: intent.issuer_verified_at ?? null,
    documents_registered: intent.issuer_documents_registered ?? null,
  };
}

export async function toolVerify(args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const input = typeof args.input === 'string' ? args.input : '';
  const parsed = parseInput(input);
  if (!parsed.tenant) {
    throw new VerifyError('unknown_tenant', `The id prefix matches no platform on the KeyHalve rail (known: ${TENANT_MANIFEST.map((t) => t.idPrefix).join(', ')}).`);
  }
  const intent = await fetchIntent(parsed.id, parsed.tenant.apiBase);

  const notes: string[] = [];
  if (parsed.keyMaterialDiscarded) {
    notes.push(
      'The input contained the holder\'s decryption key fragment (#key=…). It was DISCARDED UNREAD — this service never receives, uses, or stores key material. Sealed contents can only be read by opening the verify URL in a browser, where decryption happens locally.',
    );
  }
  if (intent.served_stale) {
    notes.push(`The platform served CACHED status (last confirmed ${intent.status_last_confirmed ?? 'unknown'}) — revocation since then would not show here.`);
  }

  // Revoked: platform withholds the payload; no integrity/rail checks possible.
  if (intent.status === 'revoked') {
    return {
      verdict: 'REVOKED',
      document_id: intent.intent_id,
      platform: parsed.tenant.id,
      revoked_at: intent.revoked_at ?? null,
      revocation_reason: intent.revocation_reason ?? null,
      issuer: issuerBlock(intent),
      sealed_contents: 'withheld — revoked documents are never served',
      notes,
    };
  }

  const { check: integrity, ciphertextCommitment } = await checkIntegrity(intent);
  const rail = await checkRail(parsed.id, parsed.qrMac, ciphertextCommitment);
  const timeLock = computeTimeLock(intent.valid_from, intent.valid_until);

  if (rail.state === 'mac_required') notes.push(rail.detail);

  const verdict = overallVerdict({
    status: intent.status ?? 'active',
    integrityFailed: integrity.state === 'failed',
    railFailed: rail.state === 'failed',
    timeLockState: timeLock.state,
  });

  return {
    verdict,
    document_id: intent.intent_id,
    platform: parsed.tenant.id,
    checks: {
      status: intent.status ?? 'active',
      ciphertext_integrity: integrity,
      rail_attestation: rail,
      time_lock: timeLock,
    },
    issuer: issuerBlock(intent),
    document: {
      document_type: intent.document_type ?? null,
      registered_at: intent.registered_at ?? null,
      file_name: intent.file_original_name ?? null,
      file_size_bytes: intent.file_size_bytes ?? null,
      file_content_type: intent.file_content_type ?? null,
      page_count: intent.page_count ?? null,
      verification_count: intent.verification_count ?? null,
      last_verified_at: intent.last_verified_at ?? null,
    },
    /** Issuer-DISCLOSED plaintext fields — platform-hosted display metadata,
     *  explicitly public, NOT inside the cryptographic seal. */
    disclosed_fields: intent.disclosed_fields ?? null,
    sealed_contents:
      'not accessible to this tool — decryption requires the QR\'s key fragment, which never leaves the holder\'s browser. Open the verify URL to view the sealed document.',
    notes,
  };
}

export async function toolStatus(args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const id = typeof args.document_id === 'string' ? args.document_id : '';
  const parsed = parseInput(id);
  if (!parsed.tenant) {
    throw new VerifyError('unknown_tenant', `The id prefix matches no platform on the KeyHalve rail (known: ${TENANT_MANIFEST.map((t) => t.idPrefix).join(', ')}).`);
  }
  const intent = await fetchIntent(parsed.id, parsed.tenant.apiBase);
  const timeLock = computeTimeLock(intent.valid_from, intent.valid_until);
  const status =
    intent.status === 'revoked' ? 'revoked' : timeLock.state === 'expired' ? 'expired' : timeLock.state === 'not_yet_valid' ? 'not_yet_valid' : 'active';
  return {
    document_id: intent.intent_id,
    platform: parsed.tenant.id,
    status,
    revoked_at: intent.revoked_at ?? null,
    revocation_reason: intent.revocation_reason ?? null,
    valid_from: timeLock.valid_from,
    valid_until: timeLock.valid_until,
    served_stale: intent.served_stale ?? false,
    status_last_confirmed: intent.status_last_confirmed ?? null,
    registered_at: intent.registered_at ?? null,
  };
}

export function toolExplain(args: Record<string, unknown>): Record<string, unknown> {
  const topic = typeof args.topic === 'string' ? args.topic : undefined;
  return explain(topic);
}
