/**
 * Blind-safe verification engine for the KeyHalve verify-MCP.
 *
 * THE ONE RULE THIS FILE EXISTS TO ENFORCE: key material never reaches this
 * server's logic. A verify URL carries the holder's ShareA in the `#key=`
 * fragment; browsers never send fragments to servers, but an AI pasting the
 * full URL into an MCP tool WOULD include it. `parseInput` therefore DISCARDS
 * the fragment before anything else sees the input, and nothing downstream
 * ever receives, logs, or returns it. Decryption of sealed contents happens
 * ONLY in the holder's browser — this tool verifies everything that is
 * verifiable WITHOUT the key:
 *
 *   1. the intent exists on its platform and its live status (active/revoked),
 *   2. ciphertext integrity — SHA-256(encrypted_payload) equals the commitment
 *      recorded at issuance (v2 commitments only, same rule as the web engine),
 *   3. rail attestation — the KeyHalve rail released a share whose Ed25519
 *      signature verifies against the PINNED rail key, and (dual-sign, M2)
 *      whose rail-signed ciphertext commitment matches the ciphertext the
 *      platform actually served,
 *   4. the time-lock window (Patent D — client-side judgment on timestamps),
 *   5. the issuer-trust context (fail-closed: self-asserted claims are
 *      'declared' at best, never proof).
 *
 * Everything fails closed: any uncertain state is reported as NOT verified.
 */

// ── Tenant manifest — same single source of truth as the web verifier
//    (keyhalve-website src/verify/tenant-manifest.json). Onboarding a platform
//    = add one entry; this engine never changes per tenant. ──
export const RAIL_BASE_URL = 'https://rail.keyhalve.com';
const RAIL_HOLDER = 'keyhalve';

export interface TenantEntry {
  id: string;
  idPrefix: string;
  apiBase: string;
  baseDomain: string;
}

export const TENANT_MANIFEST: TenantEntry[] = [
  { id: 'keyhalve', idPrefix: 'kh_', apiBase: 'https://pbou3nydj1.execute-api.us-east-1.amazonaws.com', baseDomain: 'keyhalve.com' },
  { id: 'validpay', idPrefix: 'vp_', apiBase: 'https://api.validpay.com', baseDomain: 'validpay.com' },
  { id: 'checkbooks', idPrefix: 'cb_', apiBase: 'https://checkbooks.ai', baseDomain: 'checkbooks.ai' },
];

// SPKI DER (base64) of the live rail KMS Ed25519 key — PINNED, never fetched.
// Identical to keyhalve-website src/verify/rail.ts; rotating it = a new build.
const RAIL_PUBLIC_KEY_SPKI_B64 = 'MCowBQYDK2VwAyEAngOcqC4hL467C9RyWUh4bAQD3Fohi9zqhY+l65bul6w=';

/** Shape gate for a forwarded QR MAC (8–16 base64url chars) — anything else is
 *  treated as absent, never forwarded to the rail. */
const QR_MAC_RE = /^[A-Za-z0-9_-]{8,16}$/;

const ID_PREFIX_RE = new RegExp(
  `^(${TENANT_MANIFEST.map((t) => t.idPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`,
);
/** Full intent-id shape: known tenant prefix + base64url-ish body. */
const ID_RE = new RegExp(`${ID_PREFIX_RE.source}[A-Za-z0-9_-]{4,64}$`);

const FETCH_TIMEOUT_MS = 10_000;

// ── Parsing ────────────────────────────────────────────────────────────────

export interface ParsedInput {
  id: string;
  qrMac: string | null;
  /** True when the pasted input carried a `#key=` fragment that was DISCARDED.
   *  Surfaced so the tool response can tell the caller (and the caller's user)
   *  that sealed contents stay readable only in their own browser. */
  keyMaterialDiscarded: boolean;
  tenant: TenantEntry | null;
}

/**
 * Accepts a full verify URL, a bare `vp_…?m=…#key=…` code, or a plain intent
 * id. The `#key=` fragment — the holder's ShareA — is dropped on the floor
 * here, unconditionally, before any other logic runs.
 */
export function parseInput(raw: string): ParsedInput {
  let trimmed = raw.trim();
  if (!trimmed) throw new VerifyError('empty_input', 'Empty input — paste a KeyHalve verify URL, QR text, or document id.');

  // Discard key material FIRST, whatever the input shape.
  let keyMaterialDiscarded = false;
  const hashIdx = trimmed.indexOf('#');
  if (hashIdx >= 0) {
    keyMaterialDiscarded = /key=/.test(trimmed.slice(hashIdx + 1));
    trimmed = trimmed.slice(0, hashIdx);
  }

  let id: string | null = null;
  let qrMac: string | null = null;
  try {
    const url = new URL(trimmed);
    const segments = url.pathname.split('/').filter(Boolean);
    const last = segments[segments.length - 1];
    if (last && ID_RE.test(last)) id = last;
    // Some tenants route as ?i=<id> — accept that too.
    const qi = url.searchParams.get('i');
    if (!id && qi && ID_RE.test(qi)) id = qi;
    const m = url.searchParams.get('m');
    if (m && QR_MAC_RE.test(m)) qrMac = m;
  } catch {
    const qIdx = trimmed.indexOf('?');
    let idPart = trimmed;
    if (qIdx >= 0) {
      const m = new URLSearchParams(trimmed.slice(qIdx + 1)).get('m');
      if (m && QR_MAC_RE.test(m)) qrMac = m;
      idPart = trimmed.slice(0, qIdx);
    }
    if (ID_RE.test(idPart)) id = idPart;
  }

  if (!id) {
    throw new VerifyError(
      'unrecognized_input',
      'Could not find a KeyHalve document id in the input. Expected a verify URL (https://verify.keyhalve.com/verify/<id>?m=…) or an id like vp_…, kh_…, cb_….',
    );
  }
  const tenant = TENANT_MANIFEST.find((t) => id!.startsWith(t.idPrefix)) ?? null;
  return { id, qrMac, keyMaterialDiscarded, tenant };
}

// ── Errors ─────────────────────────────────────────────────────────────────

export class VerifyError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

// ── Fetch helpers (both fail closed on timeout/network) ────────────────────

async function fetchWithTimeout(url: string): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { headers: { Accept: 'application/json' }, signal: controller.signal });
  } catch {
    throw new VerifyError('unreachable', 'Could not reach the verification service — the request failed or timed out.');
  } finally {
    clearTimeout(timer);
  }
}

export interface IntentResponse {
  intent_id: string;
  issuer?: string;
  issuer_verified?: boolean;
  verification_level?: string;
  verified_domains?: string[];
  delegated_by?: { platform: string; platform_level: string } | null;
  status?: string;
  encrypted_payload: string | null;
  registered_at?: string;
  document_type?: string;
  verification_count?: number;
  last_verified_at?: string | null;
  issuer_verified_at?: string | null;
  issuer_documents_registered?: number;
  served_stale?: boolean;
  status_last_confirmed?: string | null;
  commitment_hash?: string | null;
  commitment_version?: number;
  revoked_at?: string | null;
  revocation_reason?: string | null;
  end_cell?: boolean;
  split_key?: boolean;
  selective_disclosure?: boolean;
  valid_from?: string | null;
  valid_until?: string | null;
  disclosed_fields?: Record<string, unknown> | null;
  page_count?: number | null;
  file_size_bytes?: number | null;
  file_content_type?: string | null;
  file_original_name?: string | null;
}

export async function fetchIntent(id: string, base: string): Promise<IntentResponse> {
  const res = await fetchWithTimeout(`${base}/v1/intent/${encodeURIComponent(id)}`);
  if (res.status === 404) throw new VerifyError('not_found', 'No sealed document with this id is registered on its platform.');
  if (res.status === 429) throw new VerifyError('rate_limited', 'The platform is rate-limiting — try again shortly.');
  if (!res.ok) throw new VerifyError('platform_error', `The platform verification service returned ${res.status}.`);
  const json = (await res.json()) as IntentResponse;
  json.served_stale = res.headers.get('x-served-stale') === 'true';
  json.status_last_confirmed = res.headers.get('x-status-last-confirmed') || null;
  if (!json.encrypted_payload && json.status !== 'revoked') {
    throw new VerifyError('platform_malformed', 'The platform returned a malformed response (active intent without a payload).');
  }
  return json;
}

// ── Rail share: fetch + Ed25519 verification against the pinned key ────────
// Byte-identical canonical payloads to keyhalve-rail / keyhalve-website.

function canonicalMessageV1(intentId: string, piece: string): string {
  return `keyhalve-rail.v1\n${intentId}\n${RAIL_HOLDER}\n${piece}`;
}
function canonicalMessageV2(intentId: string, piece: string, commitment: string): string {
  return `keyhalve-rail.v2\n${intentId}\n${RAIL_HOLDER}\n${piece}\n${commitment}`;
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importRailKey(spkiB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('spki', base64ToBytes(spkiB64), { name: 'Ed25519' }, false, ['verify']);
}

async function verifySig(key: CryptoKey, sigB64: string, message: string): Promise<boolean> {
  return crypto.subtle.verify({ name: 'Ed25519' }, key, base64ToBytes(sigB64), new TextEncoder().encode(message));
}

export interface RailShareResult {
  /** Rail-signed ciphertext commitment (lowercase 64-hex) or null (custody-only). */
  commitment: string | null;
}

/**
 * Verify a `/v1/piece/:id` response. The v1 custody `sig` must ALWAYS verify;
 * a PARTIAL commitment pair (one of commitment/commitment_sig) fails closed as
 * tampering, never downgrades to custody-only. `publicKeySpkiB64` is for TESTS
 * ONLY — production callers never pass it, so the pinned key stands.
 * NOTE: the share `piece` itself is validated and then intentionally NOT
 * returned — this server has no use for key-share material beyond checking the
 * rail's signature over it.
 */
export async function verifyRailShare(intentId: string, body: unknown, publicKeySpkiB64?: string): Promise<RailShareResult> {
  const json = (body ?? {}) as Record<string, unknown>;
  if (typeof json.piece !== 'string' || !json.piece || typeof json.sig !== 'string' || !json.sig || json.holder !== RAIL_HOLDER) {
    throw new VerifyError('rail_malformed', 'The rail returned a malformed share response.');
  }
  const key = await importRailKey(publicKeySpkiB64 ?? RAIL_PUBLIC_KEY_SPKI_B64);
  if (!(await verifySig(key, json.sig, canonicalMessageV1(intentId, json.piece)))) {
    throw new VerifyError('rail_bad_signature', "The rail share's signature does NOT verify against the pinned KeyHalve rail key.");
  }
  const hasCommitment = json.commitment !== undefined && json.commitment !== null;
  const hasCommitmentSig = json.commitment_sig !== undefined && json.commitment_sig !== null;
  if (!hasCommitment && !hasCommitmentSig) return { commitment: null };
  if (
    !hasCommitment ||
    !hasCommitmentSig ||
    typeof json.commitment !== 'string' ||
    !/^[0-9a-f]{64}$/.test(json.commitment) ||
    typeof json.commitment_sig !== 'string' ||
    !json.commitment_sig
  ) {
    throw new VerifyError('rail_malformed', 'The rail share carried a partial or malformed content binding — treated as tampering, not legacy.');
  }
  if (!(await verifySig(key, json.commitment_sig, canonicalMessageV2(intentId, json.piece, json.commitment)))) {
    throw new VerifyError('rail_bad_signature', "The rail share's content-binding signature does NOT verify against the pinned KeyHalve rail key.");
  }
  return { commitment: json.commitment };
}

export type RailCheck =
  | { state: 'bound'; detail: string }
  | { state: 'custody_verified'; detail: string }
  | { state: 'no_rail_share'; detail: string }
  | { state: 'mac_required'; detail: string }
  | { state: 'failed'; detail: string };

export async function checkRail(intentId: string, qrMac: string | null, expectedCommitmentHex: string | null): Promise<RailCheck> {
  const mac = qrMac ? `?m=${encodeURIComponent(qrMac)}` : '';
  let res: Response;
  try {
    res = await fetchWithTimeout(`${RAIL_BASE_URL}/v1/piece/${encodeURIComponent(intentId)}${mac}`);
  } catch {
    return { state: 'failed', detail: 'The KeyHalve rail was unreachable — verification fails closed.' };
  }
  if (res.status === 404) {
    return { state: 'no_rail_share', detail: 'The rail holds no share for this document (single-key or split-key document — the rail attests nothing for it).' };
  }
  if (res.status === 409) return { state: 'failed', detail: 'The rail reports this document as revoked.' };
  if (res.status === 403) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    if (body.error === 'mac_required') {
      return {
        state: 'mac_required',
        detail: 'The rail requires the QR code\'s ?m= value to release its attestation. Paste the FULL verify URL (including ?m=…) to complete the rail check.',
      };
    }
    if (body.error === 'mac_invalid') {
      return { state: 'failed', detail: 'The rail REJECTED the QR MAC — this QR code does not match what was sealed. Do not trust this document.' };
    }
    return { state: 'failed', detail: 'The rail refused the request — verification fails closed.' };
  }
  if (!res.ok) return { state: 'failed', detail: `The rail returned ${res.status} — verification fails closed.` };

  let share: RailShareResult;
  try {
    share = await verifyRailShare(intentId, await res.json());
  } catch (e) {
    return { state: 'failed', detail: e instanceof Error ? e.message : 'Rail share verification failed.' };
  }
  if (share.commitment === null) {
    return { state: 'custody_verified', detail: 'The rail cryptographically attests it released a share for this document id (custody). This share predates content binding.' };
  }
  if (expectedCommitmentHex && share.commitment === expectedCommitmentHex.toLowerCase()) {
    return {
      state: 'bound',
      detail: 'The rail independently signed the ciphertext at seal time, and that rail-signed commitment matches the ciphertext the platform served now — the strongest rail attestation.',
    };
  }
  return {
    state: 'failed',
    detail: 'RAIL BINDING FAILED — the ciphertext served by the platform does not match the commitment the KeyHalve rail signed at seal time. This document may have been tampered with.',
  };
}

// ── Ciphertext commitment (Prompt 097 C-1 semantics, v2 only) ──────────────

export async function computeCommitmentHash(ciphertextB64: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ciphertextB64));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export type IntegrityCheck =
  | { state: 'verified'; detail: string }
  | { state: 'legacy_v1'; detail: string }
  | { state: 'no_commitment'; detail: string }
  | { state: 'failed'; detail: string };

export async function checkIntegrity(intent: IntentResponse): Promise<{ check: IntegrityCheck; ciphertextCommitment: string | null }> {
  if (!intent.encrypted_payload) return { check: { state: 'no_commitment', detail: 'No payload to check (revoked documents withhold it).' }, ciphertextCommitment: null };
  const ciphertextCommitment = await computeCommitmentHash(intent.encrypted_payload);
  if (!intent.commitment_hash) {
    return { check: { state: 'no_commitment', detail: 'The platform recorded no integrity commitment for this document.' }, ciphertextCommitment };
  }
  if ((intent.commitment_version ?? 1) < 2) {
    // v1 commitments hashed the PLAINTEXT — a confirmation oracle for
    // low-entropy documents; the web engine skips them and so do we.
    return { check: { state: 'legacy_v1', detail: 'Legacy v1 commitment (plaintext-hash) — skipped by design; these documents expire naturally.' }, ciphertextCommitment };
  }
  if (ciphertextCommitment !== intent.commitment_hash) {
    return {
      check: { state: 'failed', detail: 'INTEGRITY FAILED — the ciphertext does not match the commitment recorded at issuance. This document may have been tampered with.' },
      ciphertextCommitment,
    };
  }
  return { check: { state: 'verified', detail: 'SHA-256 of the served ciphertext equals the commitment recorded at issuance.' }, ciphertextCommitment };
}

// ── Time lock (Patent D — our judgment on the stored timestamps) ───────────

export type TimeLock = { state: 'valid' | 'not_yet_valid' | 'expired' | 'none'; valid_from: string | null; valid_until: string | null };

export function computeTimeLock(validFrom: string | null | undefined, validUntil: string | null | undefined, now = Date.now()): TimeLock {
  if (!validFrom && !validUntil) return { state: 'none', valid_from: null, valid_until: null };
  if (validFrom) {
    const from = new Date(validFrom).getTime();
    if (Number.isFinite(from) && now < from) return { state: 'not_yet_valid', valid_from: validFrom, valid_until: validUntil ?? null };
  }
  if (validUntil) {
    const until = new Date(validUntil).getTime();
    if (Number.isFinite(until) && now > until) return { state: 'expired', valid_from: validFrom ?? null, valid_until: validUntil };
  }
  return { state: 'valid', valid_from: validFrom ?? null, valid_until: validUntil ?? null };
}

/** A3 fail-closed identity assurance — self-asserted claims are 'declared' at
 *  best, never proof; an omitted/false flag is 'unverified', never green. */
export function computeIdentityAssurance(intent: IntentResponse): 'declared' | 'unverified' {
  return intent.issuer_verified === true ? 'declared' : 'unverified';
}
