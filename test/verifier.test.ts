import { describe, it, expect } from 'vitest';
import {
  parseInput,
  verifyRailShare,
  computeCommitmentHash,
  computeTimeLock,
  computeIdentityAssurance,
  checkIntegrity,
  VerifyError,
  type IntentResponse,
} from '../src/verifier';

describe('parseInput — key material is ALWAYS discarded', () => {
  it('drops #key= from a full verify URL and flags it', () => {
    const p = parseInput('https://verify.keyhalve.com/verify/vp_abc123?m=AbCd1234#key=SUPERSECRET');
    expect(p.id).toBe('vp_abc123');
    expect(p.qrMac).toBe('AbCd1234');
    expect(p.keyMaterialDiscarded).toBe(true);
    // The parsed structure carries NO field that could hold the key.
    expect(JSON.stringify(p)).not.toContain('SUPERSECRET');
  });

  it('drops #key= from a bare code', () => {
    const p = parseInput('vp_abc123?m=AbCd1234#key=SECRET');
    expect(p.id).toBe('vp_abc123');
    expect(p.qrMac).toBe('AbCd1234');
    expect(p.keyMaterialDiscarded).toBe(true);
  });

  it('a fragment without key= is dropped but not flagged', () => {
    const p = parseInput('vp_abc123#section');
    expect(p.id).toBe('vp_abc123');
    expect(p.keyMaterialDiscarded).toBe(false);
  });

  it('accepts a plain id and resolves the tenant', () => {
    const p = parseInput('cb_0011aabb');
    expect(p.id).toBe('cb_0011aabb');
    expect(p.tenant?.id).toBe('checkbooks');
    expect(p.qrMac).toBeNull();
  });

  it('accepts ?i= routing', () => {
    const p = parseInput('https://validpay.com/verify?i=vp_abc123&m=AbCd1234');
    expect(p.id).toBe('vp_abc123');
    expect(p.qrMac).toBe('AbCd1234');
  });

  it('rejects junk MACs instead of forwarding them', () => {
    const p = parseInput('vp_abc123?m=<script>alert(1)</script>');
    expect(p.qrMac).toBeNull();
  });

  it('fails closed on unknown input', () => {
    expect(() => parseInput('what even is this')).toThrow(VerifyError);
    expect(() => parseInput('')).toThrow(VerifyError);
  });

  it('unknown prefix parses to a null tenant (caller fails closed)', () => {
    expect(() => parseInput('zz_abc123')).toThrow(VerifyError);
  });
});

// ── Rail share verification with a locally generated Ed25519 test key ──────

async function makeTestKey() {
  const pair = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey('spki', pair.publicKey)) as ArrayBuffer);
  const spkiB64 = btoa(String.fromCharCode(...spki));
  const sign = async (message: string) => {
    const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, new TextEncoder().encode(message)));
    return btoa(String.fromCharCode(...sig));
  };
  return { spkiB64, sign };
}

describe('verifyRailShare', () => {
  it('accepts a custody-only share with a valid v1 signature', async () => {
    const { spkiB64, sign } = await makeTestKey();
    const sig = await sign('keyhalve-rail.v1\nvp_x\nkeyhalve\nPIECE');
    const share = await verifyRailShare('vp_x', { holder: 'keyhalve', piece: 'PIECE', sig }, spkiB64);
    expect(share.commitment).toBeNull();
  });

  it('rejects a bad v1 signature', async () => {
    const { spkiB64, sign } = await makeTestKey();
    const sig = await sign('keyhalve-rail.v1\nvp_DIFFERENT\nkeyhalve\nPIECE');
    await expect(verifyRailShare('vp_x', { holder: 'keyhalve', piece: 'PIECE', sig }, spkiB64)).rejects.toThrow(/does NOT verify/);
  });

  it('accepts a dual-signed share and returns the commitment', async () => {
    const { spkiB64, sign } = await makeTestKey();
    const commitment = 'a'.repeat(64);
    const sig = await sign('keyhalve-rail.v1\nvp_x\nkeyhalve\nPIECE');
    const commitment_sig = await sign(`keyhalve-rail.v2\nvp_x\nkeyhalve\nPIECE\n${commitment}`);
    const share = await verifyRailShare('vp_x', { holder: 'keyhalve', piece: 'PIECE', sig, commitment, commitment_sig }, spkiB64);
    expect(share.commitment).toBe(commitment);
  });

  it('fails closed on a PARTIAL binding (commitment without sig)', async () => {
    const { spkiB64, sign } = await makeTestKey();
    const sig = await sign('keyhalve-rail.v1\nvp_x\nkeyhalve\nPIECE');
    await expect(
      verifyRailShare('vp_x', { holder: 'keyhalve', piece: 'PIECE', sig, commitment: 'a'.repeat(64) }, spkiB64),
    ).rejects.toThrow(/partial or malformed/);
  });

  it('fails closed on uppercase commitment hex (no normalization before signing check)', async () => {
    const { spkiB64, sign } = await makeTestKey();
    const sig = await sign('keyhalve-rail.v1\nvp_x\nkeyhalve\nPIECE');
    await expect(
      verifyRailShare('vp_x', { holder: 'keyhalve', piece: 'PIECE', sig, commitment: 'A'.repeat(64), commitment_sig: 'x' }, spkiB64),
    ).rejects.toThrow(/partial or malformed/);
  });

  it('rejects a wrong holder', async () => {
    const { spkiB64 } = await makeTestKey();
    await expect(verifyRailShare('vp_x', { holder: 'evil', piece: 'PIECE', sig: 'x' }, spkiB64)).rejects.toThrow(/malformed/);
  });
});

describe('commitment integrity', () => {
  it('computes the same hex as the web engine scheme (SHA-256 of the b64 string)', async () => {
    // Independently computed: sha256("payload") hex.
    expect(await computeCommitmentHash('payload')).toBe('239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5');
  });

  it('verifies a v2 match and fails a v2 mismatch', async () => {
    const good: IntentResponse = {
      intent_id: 'vp_x',
      encrypted_payload: 'payload',
      commitment_hash: '239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5',
      commitment_version: 2,
    };
    expect((await checkIntegrity(good)).check.state).toBe('verified');
    const bad = { ...good, commitment_hash: 'f'.repeat(64) };
    expect((await checkIntegrity(bad)).check.state).toBe('failed');
  });

  it('skips legacy v1 commitments by design', async () => {
    const v1: IntentResponse = { intent_id: 'vp_x', encrypted_payload: 'payload', commitment_hash: 'x', commitment_version: 1 };
    expect((await checkIntegrity(v1)).check.state).toBe('legacy_v1');
  });
});

describe('time lock', () => {
  const T = Date.parse('2026-07-26T12:00:00Z');
  it('none / valid / not_yet_valid / expired', () => {
    expect(computeTimeLock(null, null, T).state).toBe('none');
    expect(computeTimeLock('2026-01-01T00:00:00Z', '2026-12-31T00:00:00Z', T).state).toBe('valid');
    expect(computeTimeLock('2026-08-01T00:00:00Z', null, T).state).toBe('not_yet_valid');
    expect(computeTimeLock(null, '2026-07-01T00:00:00Z', T).state).toBe('expired');
  });
});

describe('identity assurance fails closed', () => {
  it('true → declared (never a stronger claim), anything else → unverified', () => {
    expect(computeIdentityAssurance({ intent_id: 'x', encrypted_payload: 'p', issuer_verified: true })).toBe('declared');
    expect(computeIdentityAssurance({ intent_id: 'x', encrypted_payload: 'p', issuer_verified: false })).toBe('unverified');
    expect(computeIdentityAssurance({ intent_id: 'x', encrypted_payload: 'p' })).toBe('unverified');
  });
});
