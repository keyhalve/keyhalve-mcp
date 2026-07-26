/**
 * keyhalve_explain — the FAQ, in the AI's answer. Static, honest, and aligned
 * with the approved claims language: neutral wording, "3-of-3"/"blind rail"
 * framing, no overclaiming. Every string here is customer-facing copy.
 */

export const EXPLAIN_TOPICS = ['verdict', 'blindness', 'rail', 'revocation', 'integrity', 'issuer_trust', 'limits'] as const;
export type ExplainTopic = (typeof EXPLAIN_TOPICS)[number];

const TOPICS: Record<ExplainTopic, { title: string; text: string }> = {
  verdict: {
    title: 'What a KeyHalve verdict means',
    text:
      'SEAL VERIFIED means: the document id is registered on its issuing platform, the encrypted payload served today is byte-identical to what was committed at issuance (SHA-256 commitment), the independent KeyHalve rail cryptographically attests its part of the seal, and the document is inside its validity window and not revoked. REVOKED means the issuer has withdrawn it — the platform refuses to serve it at all. FAILED means a cryptographic check did not pass: do not trust the document.',
  },
  blindness: {
    title: 'Why no one could read the document',
    text:
      'A sealed document is encrypted, and the decryption key is split. The QR code on the physical document carries one share; the issuing platform holds another; the KeyHalve rail holds a third (3-of-3 for sealing). No single party — not the platform, not KeyHalve, not this tool — holds enough to decrypt. Decryption happens only in the verifier\'s own browser, where the QR\'s share (the URL #key= fragment, which browsers never transmit) is combined locally. This verification tool discards any key material it is handed and works purely on public, verifiable facts.',
  },
  rail: {
    title: 'What the KeyHalve rail attests',
    text:
      'The rail is a neutral, blind co-signer. At seal time it stores one key share and signs a commitment to the ciphertext. At verify time it returns that share signed with its Ed25519 key (verified here against a pinned public key, never fetched). When the rail-signed commitment matches the ciphertext the platform serves today, two independent parties in separate trust domains agree the document is unaltered — a platform alone cannot forge that.',
  },
  revocation: {
    title: 'How revocation works',
    text:
      'An issuer can revoke a sealed document at any time (blind revocation — the rail never learns why or what the document said). Verification is real-time and stateless by design: there is no offline cache, so a revoked document fails on the very next check. If a platform serves cached status, this tool says so honestly (served_stale).',
  },
  integrity: {
    title: 'The integrity commitment',
    text:
      'At issuance the platform records SHA-256 of the ciphertext. At verification the hash is recomputed over the bytes actually served and must match — any post-issuance modification of the stored document flips the verdict to FAILED. The rail additionally counter-signs this commitment (dual-sign), so tampering would have to defeat two independent parties.',
  },
  issuer_trust: {
    title: 'Issuer identity — what is and is not proven',
    text:
      'Cryptographic verification proves the DOCUMENT is intact and its seal genuine. Issuer identity is graded honestly and fails closed: "declared" means the platform asserts it verified the issuer (e.g. domain control via DNS); "unverified" means no such claim. A verified seal from an unverified issuer is still a genuine, intact document — from an issuer whose identity you should judge separately.',
  },
  limits: {
    title: 'What this tool cannot do',
    text:
      'It cannot read sealed contents — it never receives the decryption key (any pasted key fragment is discarded unread). It cannot confirm the paper in your hand matches the sealed file; comparing the decrypted document to the physical one happens in the browser verify page. And it cannot make an unverified issuer trustworthy — it reports identity assurance exactly as strong as the evidence.',
  },
};

export function explain(topic?: string): Record<string, unknown> {
  if (topic && (EXPLAIN_TOPICS as readonly string[]).includes(topic)) {
    const t = TOPICS[topic as ExplainTopic];
    return { topic, title: t.title, explanation: t.text };
  }
  return {
    overview:
      'KeyHalve is a neutral, blind co-signing rail for document authenticity — think "the room every sealed document is verified in", free and account-free for anyone, while platforms (ValidPay, CheckBooks, banks) are the doors where documents get sealed. Verification checks the seal cryptographically without anyone — including KeyHalve — being able to read the document.',
    topics: Object.fromEntries((EXPLAIN_TOPICS as readonly string[]).map((k) => [k, TOPICS[k as ExplainTopic].title])),
    tip: 'Call keyhalve_explain with a topic for detail, or keyhalve_verify with a verify URL to check a document.',
  };
}
