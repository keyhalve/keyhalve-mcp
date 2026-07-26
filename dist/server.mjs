// src/verifier.ts
var RAIL_BASE_URL = "https://rail.keyhalve.com";
var RAIL_HOLDER = "keyhalve";
var TENANT_MANIFEST = [
  { id: "keyhalve", idPrefix: "kh_", apiBase: "https://pbou3nydj1.execute-api.us-east-1.amazonaws.com", baseDomain: "keyhalve.com" },
  { id: "validpay", idPrefix: "vp_", apiBase: "https://api.validpay.com", baseDomain: "validpay.com" },
  { id: "checkbooks", idPrefix: "cb_", apiBase: "https://checkbooks.ai", baseDomain: "checkbooks.ai" }
];
var RAIL_PUBLIC_KEY_SPKI_B64 = "MCowBQYDK2VwAyEAngOcqC4hL467C9RyWUh4bAQD3Fohi9zqhY+l65bul6w=";
var QR_MAC_RE = /^[A-Za-z0-9_-]{8,16}$/;
var ID_PREFIX_RE = new RegExp(
  `^(${TENANT_MANIFEST.map((t) => t.idPrefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`
);
var ID_RE = new RegExp(`${ID_PREFIX_RE.source}[A-Za-z0-9_-]{4,64}$`);
var FETCH_TIMEOUT_MS = 1e4;
function parseInput(raw) {
  let trimmed = raw.trim();
  if (!trimmed) throw new VerifyError("empty_input", "Empty input \u2014 paste a KeyHalve verify URL, QR text, or document id.");
  let keyMaterialDiscarded = false;
  const hashIdx = trimmed.indexOf("#");
  if (hashIdx >= 0) {
    keyMaterialDiscarded = /key=/.test(trimmed.slice(hashIdx + 1));
    trimmed = trimmed.slice(0, hashIdx);
  }
  let id = null;
  let qrMac = null;
  try {
    const url = new URL(trimmed);
    const segments = url.pathname.split("/").filter(Boolean);
    const last = segments[segments.length - 1];
    if (last && ID_RE.test(last)) id = last;
    const qi = url.searchParams.get("i");
    if (!id && qi && ID_RE.test(qi)) id = qi;
    const m = url.searchParams.get("m");
    if (m && QR_MAC_RE.test(m)) qrMac = m;
  } catch {
    const qIdx = trimmed.indexOf("?");
    let idPart = trimmed;
    if (qIdx >= 0) {
      const m = new URLSearchParams(trimmed.slice(qIdx + 1)).get("m");
      if (m && QR_MAC_RE.test(m)) qrMac = m;
      idPart = trimmed.slice(0, qIdx);
    }
    if (ID_RE.test(idPart)) id = idPart;
  }
  if (!id) {
    throw new VerifyError(
      "unrecognized_input",
      "Could not find a KeyHalve document id in the input. Expected a verify URL (https://verify.keyhalve.com/verify/<id>?m=\u2026) or an id like vp_\u2026, kh_\u2026, cb_\u2026."
    );
  }
  const tenant = TENANT_MANIFEST.find((t) => id.startsWith(t.idPrefix)) ?? null;
  return { id, qrMac, keyMaterialDiscarded, tenant };
}
var VerifyError = class extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
};
async function fetchWithTimeout(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { headers: { Accept: "application/json" }, signal: controller.signal });
  } catch {
    throw new VerifyError("unreachable", "Could not reach the verification service \u2014 the request failed or timed out.");
  } finally {
    clearTimeout(timer);
  }
}
async function fetchIntent(id, base) {
  const res = await fetchWithTimeout(`${base}/v1/intent/${encodeURIComponent(id)}`);
  if (res.status === 404) throw new VerifyError("not_found", "No sealed document with this id is registered on its platform.");
  if (res.status === 429) throw new VerifyError("rate_limited", "The platform is rate-limiting \u2014 try again shortly.");
  if (!res.ok) throw new VerifyError("platform_error", `The platform verification service returned ${res.status}.`);
  const json = await res.json();
  json.served_stale = res.headers.get("x-served-stale") === "true";
  json.status_last_confirmed = res.headers.get("x-status-last-confirmed") || null;
  if (!json.encrypted_payload && json.status !== "revoked") {
    throw new VerifyError("platform_malformed", "The platform returned a malformed response (active intent without a payload).");
  }
  return json;
}
function canonicalMessageV1(intentId, piece) {
  return `keyhalve-rail.v1
${intentId}
${RAIL_HOLDER}
${piece}`;
}
function canonicalMessageV2(intentId, piece, commitment) {
  return `keyhalve-rail.v2
${intentId}
${RAIL_HOLDER}
${piece}
${commitment}`;
}
function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function importRailKey(spkiB64) {
  return crypto.subtle.importKey("spki", base64ToBytes(spkiB64), { name: "Ed25519" }, false, ["verify"]);
}
async function verifySig(key, sigB64, message) {
  return crypto.subtle.verify({ name: "Ed25519" }, key, base64ToBytes(sigB64), new TextEncoder().encode(message));
}
async function verifyRailShare(intentId, body, publicKeySpkiB64) {
  const json = body ?? {};
  if (typeof json.piece !== "string" || !json.piece || typeof json.sig !== "string" || !json.sig || json.holder !== RAIL_HOLDER) {
    throw new VerifyError("rail_malformed", "The rail returned a malformed share response.");
  }
  const key = await importRailKey(publicKeySpkiB64 ?? RAIL_PUBLIC_KEY_SPKI_B64);
  if (!await verifySig(key, json.sig, canonicalMessageV1(intentId, json.piece))) {
    throw new VerifyError("rail_bad_signature", "The rail share's signature does NOT verify against the pinned KeyHalve rail key.");
  }
  const hasCommitment = json.commitment !== void 0 && json.commitment !== null;
  const hasCommitmentSig = json.commitment_sig !== void 0 && json.commitment_sig !== null;
  if (!hasCommitment && !hasCommitmentSig) return { commitment: null };
  if (!hasCommitment || !hasCommitmentSig || typeof json.commitment !== "string" || !/^[0-9a-f]{64}$/.test(json.commitment) || typeof json.commitment_sig !== "string" || !json.commitment_sig) {
    throw new VerifyError("rail_malformed", "The rail share carried a partial or malformed content binding \u2014 treated as tampering, not legacy.");
  }
  if (!await verifySig(key, json.commitment_sig, canonicalMessageV2(intentId, json.piece, json.commitment))) {
    throw new VerifyError("rail_bad_signature", "The rail share's content-binding signature does NOT verify against the pinned KeyHalve rail key.");
  }
  return { commitment: json.commitment };
}
async function checkRail(intentId, qrMac, expectedCommitmentHex) {
  const mac = qrMac ? `?m=${encodeURIComponent(qrMac)}` : "";
  let res;
  try {
    res = await fetchWithTimeout(`${RAIL_BASE_URL}/v1/piece/${encodeURIComponent(intentId)}${mac}`);
  } catch {
    return { state: "failed", detail: "The KeyHalve rail was unreachable \u2014 verification fails closed." };
  }
  if (res.status === 404) {
    return { state: "no_rail_share", detail: "The rail holds no share for this document (single-key or split-key document \u2014 the rail attests nothing for it)." };
  }
  if (res.status === 409) return { state: "failed", detail: "The rail reports this document as revoked." };
  if (res.status === 403) {
    const body = await res.json().catch(() => ({}));
    if (body.error === "mac_required") {
      return {
        state: "mac_required",
        detail: "The rail requires the QR code's ?m= value to release its attestation. Paste the FULL verify URL (including ?m=\u2026) to complete the rail check."
      };
    }
    if (body.error === "mac_invalid") {
      return { state: "failed", detail: "The rail REJECTED the QR MAC \u2014 this QR code does not match what was sealed. Do not trust this document." };
    }
    return { state: "failed", detail: "The rail refused the request \u2014 verification fails closed." };
  }
  if (!res.ok) return { state: "failed", detail: `The rail returned ${res.status} \u2014 verification fails closed.` };
  let share;
  try {
    share = await verifyRailShare(intentId, await res.json());
  } catch (e) {
    return { state: "failed", detail: e instanceof Error ? e.message : "Rail share verification failed." };
  }
  if (share.commitment === null) {
    return { state: "custody_verified", detail: "The rail cryptographically attests it released a share for this document id (custody). This share predates content binding." };
  }
  if (expectedCommitmentHex && share.commitment === expectedCommitmentHex.toLowerCase()) {
    return {
      state: "bound",
      detail: "The rail independently signed the ciphertext at seal time, and that rail-signed commitment matches the ciphertext the platform served now \u2014 the strongest rail attestation."
    };
  }
  return {
    state: "failed",
    detail: "RAIL BINDING FAILED \u2014 the ciphertext served by the platform does not match the commitment the KeyHalve rail signed at seal time. This document may have been tampered with."
  };
}
async function computeCommitmentHash(ciphertextB64) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ciphertextB64));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function checkIntegrity(intent) {
  if (!intent.encrypted_payload) return { check: { state: "no_commitment", detail: "No payload to check (revoked documents withhold it)." }, ciphertextCommitment: null };
  const ciphertextCommitment = await computeCommitmentHash(intent.encrypted_payload);
  if (!intent.commitment_hash) {
    return { check: { state: "no_commitment", detail: "The platform recorded no integrity commitment for this document." }, ciphertextCommitment };
  }
  if ((intent.commitment_version ?? 1) < 2) {
    return { check: { state: "legacy_v1", detail: "Legacy v1 commitment (plaintext-hash) \u2014 skipped by design; these documents expire naturally." }, ciphertextCommitment };
  }
  if (ciphertextCommitment !== intent.commitment_hash) {
    return {
      check: { state: "failed", detail: "INTEGRITY FAILED \u2014 the ciphertext does not match the commitment recorded at issuance. This document may have been tampered with." },
      ciphertextCommitment
    };
  }
  return { check: { state: "verified", detail: "SHA-256 of the served ciphertext equals the commitment recorded at issuance." }, ciphertextCommitment };
}
function computeTimeLock(validFrom, validUntil, now = Date.now()) {
  if (!validFrom && !validUntil) return { state: "none", valid_from: null, valid_until: null };
  if (validFrom) {
    const from = new Date(validFrom).getTime();
    if (Number.isFinite(from) && now < from) return { state: "not_yet_valid", valid_from: validFrom, valid_until: validUntil ?? null };
  }
  if (validUntil) {
    const until = new Date(validUntil).getTime();
    if (Number.isFinite(until) && now > until) return { state: "expired", valid_from: validFrom ?? null, valid_until: validUntil };
  }
  return { state: "valid", valid_from: validFrom ?? null, valid_until: validUntil ?? null };
}
function computeIdentityAssurance(intent) {
  return intent.issuer_verified === true ? "declared" : "unverified";
}

// src/explain.ts
var EXPLAIN_TOPICS = ["verdict", "blindness", "rail", "revocation", "integrity", "issuer_trust", "limits"];
var TOPICS = {
  verdict: {
    title: "What a KeyHalve verdict means",
    text: "SEAL VERIFIED means: the document id is registered on its issuing platform, the encrypted payload served today is byte-identical to what was committed at issuance (SHA-256 commitment), the independent KeyHalve rail cryptographically attests its part of the seal, and the document is inside its validity window and not revoked. REVOKED means the issuer has withdrawn it \u2014 the platform refuses to serve it at all. FAILED means a cryptographic check did not pass: do not trust the document."
  },
  blindness: {
    title: "Why no one could read the document",
    text: "A sealed document is encrypted, and the decryption key is split. The QR code on the physical document carries one share; the issuing platform holds another; the KeyHalve rail holds a third (3-of-3 for sealing). No single party \u2014 not the platform, not KeyHalve, not this tool \u2014 holds enough to decrypt. Decryption happens only in the verifier's own browser, where the QR's share (the URL #key= fragment, which browsers never transmit) is combined locally. This verification tool discards any key material it is handed and works purely on public, verifiable facts."
  },
  rail: {
    title: "What the KeyHalve rail attests",
    text: "The rail is a neutral, blind co-signer. At seal time it stores one key share and signs a commitment to the ciphertext. At verify time it returns that share signed with its Ed25519 key (verified here against a pinned public key, never fetched). When the rail-signed commitment matches the ciphertext the platform serves today, two independent parties in separate trust domains agree the document is unaltered \u2014 a platform alone cannot forge that."
  },
  revocation: {
    title: "How revocation works",
    text: "An issuer can revoke a sealed document at any time (blind revocation \u2014 the rail never learns why or what the document said). Verification is real-time and stateless by design: there is no offline cache, so a revoked document fails on the very next check. If a platform serves cached status, this tool says so honestly (served_stale)."
  },
  integrity: {
    title: "The integrity commitment",
    text: "At issuance the platform records SHA-256 of the ciphertext. At verification the hash is recomputed over the bytes actually served and must match \u2014 any post-issuance modification of the stored document flips the verdict to FAILED. The rail additionally counter-signs this commitment (dual-sign), so tampering would have to defeat two independent parties."
  },
  issuer_trust: {
    title: "Issuer identity \u2014 what is and is not proven",
    text: 'Cryptographic verification proves the DOCUMENT is intact and its seal genuine. Issuer identity is graded honestly and fails closed: "declared" means the platform asserts it verified the issuer (e.g. domain control via DNS); "unverified" means no such claim. A verified seal from an unverified issuer is still a genuine, intact document \u2014 from an issuer whose identity you should judge separately.'
  },
  limits: {
    title: "What this tool cannot do",
    text: "It cannot read sealed contents \u2014 it never receives the decryption key (any pasted key fragment is discarded unread). It cannot confirm the paper in your hand matches the sealed file; comparing the decrypted document to the physical one happens in the browser verify page. And it cannot make an unverified issuer trustworthy \u2014 it reports identity assurance exactly as strong as the evidence."
  }
};
function explain(topic) {
  if (topic && EXPLAIN_TOPICS.includes(topic)) {
    const t = TOPICS[topic];
    return { topic, title: t.title, explanation: t.text };
  }
  return {
    overview: 'KeyHalve is a neutral, blind co-signing rail for document authenticity \u2014 think "the room every sealed document is verified in", free and account-free for anyone, while platforms (ValidPay, CheckBooks, banks) are the doors where documents get sealed. Verification checks the seal cryptographically without anyone \u2014 including KeyHalve \u2014 being able to read the document.',
    topics: Object.fromEntries(EXPLAIN_TOPICS.map((k) => [k, TOPICS[k].title])),
    tip: "Call keyhalve_explain with a topic for detail, or keyhalve_verify with a verify URL to check a document."
  };
}

// src/tools.ts
var TOOLS = [
  {
    name: "keyhalve_verify",
    description: "Verify a KeyHalve-sealed document. Accepts a verify URL, the raw text of a KeyHalve QR code, or a document id (vp_\u2026, kh_\u2026, cb_\u2026). Returns the cryptographic verdict: whether the seal exists, its live status (active/revoked/expired), ciphertext integrity against the issuance commitment, the KeyHalve rail's independent attestation, the validity window, and the issuer's trust context. This tool NEVER decrypts sealed contents \u2014 any decryption key in the URL fragment is discarded unread; contents are only readable by opening the verify URL in a browser.",
    inputSchema: {
      type: "object",
      properties: {
        input: {
          type: "string",
          description: "A KeyHalve verify URL, QR-code text, or bare document id."
        }
      },
      required: ["input"]
    },
    annotations: { readOnlyHint: true, openWorldHint: true }
  },
  {
    name: "keyhalve_status",
    description: 'Live status of a KeyHalve-sealed document by id: active, revoked (with reason/time), or outside its validity window. Lighter than keyhalve_verify \u2014 status only, no integrity or rail checks. Use for "is this still good right now?"',
    inputSchema: {
      type: "object",
      properties: {
        document_id: { type: "string", description: "The document id, e.g. vp_\u2026, kh_\u2026, cb_\u2026." }
      },
      required: ["document_id"]
    },
    annotations: { readOnlyHint: true, openWorldHint: true }
  },
  {
    name: "keyhalve_explain",
    description: "Plain-language explanation of what a KeyHalve verification verdict means and why it can be trusted (blind rail, split keys, commitments, revocation). Optionally focused on one topic.",
    inputSchema: {
      type: "object",
      properties: {
        topic: {
          type: "string",
          enum: [...EXPLAIN_TOPICS],
          description: "Optional single topic; omit for the overview."
        }
      }
    },
    annotations: { readOnlyHint: true, openWorldHint: false }
  }
];
function overallVerdict(opts) {
  if (opts.integrityFailed || opts.railFailed) return "FAILED \u2014 DO NOT TRUST";
  if (opts.status === "revoked") return "REVOKED";
  if (opts.timeLockState === "expired") return "EXPIRED";
  if (opts.timeLockState === "not_yet_valid") return "NOT YET VALID";
  return "SEAL VERIFIED";
}
function issuerBlock(intent) {
  return {
    name: intent.issuer ?? null,
    identity_assurance: computeIdentityAssurance(intent),
    verification_level: intent.verification_level ?? "none",
    verified_domains: intent.verified_domains ?? [],
    delegated_by: intent.delegated_by ?? null,
    issuer_verified_at: intent.issuer_verified_at ?? null,
    documents_registered: intent.issuer_documents_registered ?? null
  };
}
async function toolVerify(args) {
  const input = typeof args.input === "string" ? args.input : "";
  const parsed = parseInput(input);
  if (!parsed.tenant) {
    throw new VerifyError("unknown_tenant", `The id prefix matches no platform on the KeyHalve rail (known: ${TENANT_MANIFEST.map((t) => t.idPrefix).join(", ")}).`);
  }
  const intent = await fetchIntent(parsed.id, parsed.tenant.apiBase);
  const notes = [];
  if (parsed.keyMaterialDiscarded) {
    notes.push(
      "The input contained the holder's decryption key fragment (#key=\u2026). It was DISCARDED UNREAD \u2014 this service never receives, uses, or stores key material. Sealed contents can only be read by opening the verify URL in a browser, where decryption happens locally."
    );
  }
  if (intent.served_stale) {
    notes.push(`The platform served CACHED status (last confirmed ${intent.status_last_confirmed ?? "unknown"}) \u2014 revocation since then would not show here.`);
  }
  if (intent.status === "revoked") {
    return {
      verdict: "REVOKED",
      document_id: intent.intent_id,
      platform: parsed.tenant.id,
      revoked_at: intent.revoked_at ?? null,
      revocation_reason: intent.revocation_reason ?? null,
      issuer: issuerBlock(intent),
      sealed_contents: "withheld \u2014 revoked documents are never served",
      notes
    };
  }
  const { check: integrity, ciphertextCommitment } = await checkIntegrity(intent);
  const rail = await checkRail(parsed.id, parsed.qrMac, ciphertextCommitment);
  const timeLock = computeTimeLock(intent.valid_from, intent.valid_until);
  if (rail.state === "mac_required") notes.push(rail.detail);
  const verdict = overallVerdict({
    status: intent.status ?? "active",
    integrityFailed: integrity.state === "failed",
    railFailed: rail.state === "failed",
    timeLockState: timeLock.state
  });
  return {
    verdict,
    document_id: intent.intent_id,
    platform: parsed.tenant.id,
    checks: {
      status: intent.status ?? "active",
      ciphertext_integrity: integrity,
      rail_attestation: rail,
      time_lock: timeLock
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
      last_verified_at: intent.last_verified_at ?? null
    },
    /** Issuer-DISCLOSED plaintext fields — platform-hosted display metadata,
     *  explicitly public, NOT inside the cryptographic seal. */
    disclosed_fields: intent.disclosed_fields ?? null,
    sealed_contents: "not accessible to this tool \u2014 decryption requires the QR's key fragment, which never leaves the holder's browser. Open the verify URL to view the sealed document.",
    notes
  };
}
async function toolStatus(args) {
  const id = typeof args.document_id === "string" ? args.document_id : "";
  const parsed = parseInput(id);
  if (!parsed.tenant) {
    throw new VerifyError("unknown_tenant", `The id prefix matches no platform on the KeyHalve rail (known: ${TENANT_MANIFEST.map((t) => t.idPrefix).join(", ")}).`);
  }
  const intent = await fetchIntent(parsed.id, parsed.tenant.apiBase);
  const timeLock = computeTimeLock(intent.valid_from, intent.valid_until);
  const status = intent.status === "revoked" ? "revoked" : timeLock.state === "expired" ? "expired" : timeLock.state === "not_yet_valid" ? "not_yet_valid" : "active";
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
    registered_at: intent.registered_at ?? null
  };
}
function toolExplain(args) {
  const topic = typeof args.topic === "string" ? args.topic : void 0;
  return explain(topic);
}

// src/mcp.ts
var SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
var LATEST_PROTOCOL_VERSION = "2025-06-18";
var SERVER_INFO = {
  name: "keyhalve-verify",
  title: "KeyHalve \u2014 verify sealed documents",
  version: "1.0.0"
};
function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}
function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}
function toolContent(result, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    structuredContent: result,
    isError
  };
}
async function callTool(name, args) {
  try {
    switch (name) {
      case "keyhalve_verify":
        return toolContent(await toolVerify(args));
      case "keyhalve_status":
        return toolContent(await toolStatus(args));
      case "keyhalve_explain":
        return toolContent(toolExplain(args));
      default:
        return toolContent({ error: "unknown_tool", message: `No such tool: ${name}` }, true);
    }
  } catch (e) {
    if (e instanceof VerifyError) return toolContent({ error: e.code, message: e.message }, true);
    return toolContent({ error: "internal", message: "Verification failed unexpectedly \u2014 treat the document as UNVERIFIED." }, true);
  }
}
async function handleMessage(msg) {
  const id = msg.id ?? null;
  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return rpcError(id, -32600, "Invalid Request");
  }
  const isNotification = msg.id === void 0;
  switch (msg.method) {
    case "initialize": {
      const requested = msg.params?.protocolVersion ?? "";
      const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : LATEST_PROTOCOL_VERSION;
      return rpcResult(id, {
        protocolVersion,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
        instructions: "Free, public verification of KeyHalve-sealed documents (from any platform on the rail: ValidPay, CheckBooks, \u2026). Use keyhalve_verify with a verify URL or QR text. This server never receives decryption keys \u2014 sealed contents remain readable only in the holder's browser."
      });
    }
    case "ping":
      return rpcResult(id, {});
    case "tools/list":
      return rpcResult(id, { tools: TOOLS });
    case "tools/call": {
      const name = msg.params?.name ?? "";
      const args = msg.params?.arguments ?? {};
      return rpcResult(id, await callTool(name, args));
    }
    default:
      if (isNotification) return null;
      return rpcError(id, -32601, `Method not found: ${msg.method}`);
  }
}
var CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id",
  "Access-Control-Max-Age": "86400"
};
async function handleMcpRequest(request) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
  if (request.method === "GET") {
    return new Response(JSON.stringify({ error: "This MCP server is stateless \u2014 POST JSON-RPC messages to this endpoint." }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "POST, OPTIONS", ...CORS_HEADERS }
    });
  }
  if (request.method !== "POST") {
    return new Response(null, { status: 405, headers: { Allow: "POST, GET, OPTIONS", ...CORS_HEADERS } });
  }
  let parsed;
  try {
    parsed = await request.json();
  } catch {
    return new Response(JSON.stringify(rpcError(null, -32700, "Parse error")), {
      status: 400,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS }
    });
  }
  const messages = Array.isArray(parsed) ? parsed : [parsed];
  if (messages.length === 0) {
    return new Response(JSON.stringify(rpcError(null, -32600, "Invalid Request")), {
      status: 400,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS }
    });
  }
  const responses = (await Promise.all(messages.map(handleMessage))).filter((r) => r !== null);
  if (responses.length === 0) return new Response(null, { status: 202, headers: CORS_HEADERS });
  const body = Array.isArray(parsed) ? responses : responses[0];
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json", ...CORS_HEADERS } });
}

// src/worker.ts
var DESCRIPTION = {
  service: SERVER_INFO.name,
  version: SERVER_INFO.version,
  what: "Free, public, no-account MCP server for verifying KeyHalve-sealed documents from any platform on the rail.",
  endpoint: { transport: "streamable-http", url: "https://mcp.keyhalve.com/mcp" },
  tools: ["keyhalve_verify", "keyhalve_status", "keyhalve_explain"],
  privacy: "This server never receives decryption keys (URL #key= fragments are discarded unread), stores nothing, and cannot read sealed documents. Decryption happens only in the document holder's browser.",
  docs: "https://keyhalve.com"
};
var worker_default = {
  async fetch(request) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/mcp") return await handleMcpRequest(request);
      if (url.pathname === "/health") {
        return new Response(JSON.stringify({ ok: true, service: SERVER_INFO.name }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url.pathname === "/") {
        return new Response(JSON.stringify(DESCRIPTION, null, 2), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
      return new Response(JSON.stringify({ error: "not_found" }), { status: 404, headers: { "Content-Type": "application/json" } });
    } catch {
      return new Response(JSON.stringify({ error: "internal" }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }
};

// scripts/node-entry.ts
import { createServer } from "node:http";
var PORT = Number(process.env.PORT || 8787);
createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers[k] = v;
    const request = new Request(`http://localhost:${PORT}${req.url ?? "/"}`, {
      method: req.method ?? "GET",
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? void 0 : body
    });
    const response = await worker_default.fetch(request);
    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end('{"error":"internal"}');
  }
}).listen(PORT, () => console.log(`keyhalve verify-MCP (node adapter) on http://localhost:${PORT}`));
