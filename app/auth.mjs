// ce-secrets auth — challenge-response authentication over the enrolled device key.
//
// The vault already gives every device an ECDSA P-256 keypair (its "device key"). This module
// turns that key into a login primitive: a relying party (an app) issues a fresh nonce, the
// device SIGNS a flat canonical body { aud, deviceId, nonce, ts }, and the app VERIFIES that the
// signer is an ENROLLED device (a `d.<id>` record) of the operator's vault. "Enrolled in vault X"
// == "is the operator of X." No bearer tokens are ever delivered or pasted — only single-use,
// time-bound, nonce-bound proofs.
//
// INTEROP CONTRACT (the five traps the Rust + TS SDKs must reproduce byte-for-byte):
//   1. Signature is ECDSA P-256 / SHA-256, RAW IEEE-P1363 r||s (64 bytes), NEVER DER.
//   2. The 64-byte signature is base64url, NO padding.
//   3. Canonicalization is top-level-sorted-key JSON, no whitespace, nested values untouched:
//        stableStringify(o) = JSON.stringify(o, Object.keys(o).sort())
//   4. The signed body is FLAT — exactly { aud, deviceId, nonce, ts }, all strings.
//   5. The stateless nonce is HMAC-SHA256(serverSecret, ts), hex; TTL 300s on `ts`.

import * as C from './crypto.mjs';

const subtle = globalThis.crypto.subtle;

// Default replay/skew window, in seconds. Mirrors the hub's SIG_TTL_SECS.
export const AUTH_TTL_SECS = 300;

// Canonicalize a flat object: top-level keys sorted, no whitespace. The single source of truth
// for what gets signed/verified. Re-exported so apps and tests use the EXACT same bytes.
export function stable_stringify(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

// ---- nonce (stateless, HMAC-SHA256(serverSecret, ts)) -----------------------
// A relying party that keeps no per-nonce state derives the nonce from a timestamp and its own
// secret, then re-derives + TTL-checks it at verify time. serverSecret may be a string or bytes.
async function hmacKey(serverSecret) {
  const raw = typeof serverSecret === 'string' ? C.enc.utf8.enc(serverSecret) : new Uint8Array(serverSecret);
  return subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

// makeNonce(serverSecret, ts) -> hex string. `ts` is the ISO-8601 string that will go in the body.
export async function makeNonce(serverSecret, ts) {
  const key = await hmacKey(serverSecret);
  const mac = new Uint8Array(await subtle.sign('HMAC', key, C.enc.utf8.enc(String(ts))));
  return C.enc.hex.enc(mac);
}

// checkNonce(serverSecret, ts, nonce) -> bool. Recomputes HMAC, constant-time compares, and
// enforces the TTL on `ts` (within ±ttlSecs of now). Stateless: no nonce cache required.
export async function checkNonce(serverSecret, ts, nonce, ttlSecs = AUTH_TTL_SECS) {
  const tms = Date.parse(ts);
  if (Number.isNaN(tms)) return false;
  if (Math.abs(Date.now() - tms) > ttlSecs * 1000) return false;
  const expected = await makeNonce(serverSecret, ts);
  return constantTimeEqualHex(expected, String(nonce));
}

function constantTimeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---- sign / verify ----------------------------------------------------------
// Build the flat canonical auth body. Kept in one place so signer and verifier agree.
export function authBody({ aud, deviceId, nonce, ts }) {
  return { aud: String(aud), deviceId: String(deviceId), nonce: String(nonce), ts: String(ts) };
}

// signChallenge(device, { aud, nonce, ts }) -> base64url(P1363 sig).
// `device` is a full device key (from crypto.generateDeviceKey()); its `.id` is the deviceId.
// Signs UTF8(stableStringify({aud,deviceId,nonce,ts})) with ECDSA P-256/SHA-256, raw P1363.
export async function signChallenge(device, { aud, nonce, ts }) {
  const body = authBody({ aud, deviceId: device.id, nonce, ts });
  // Reuse the vault's record signer: ECDSA/SHA-256 over stableStringify -> base64url no-pad raw sig.
  return C.signRecord(device, body);
}

// verifyAuth(enrolledDevicePubJwk, { aud, deviceId, nonce, ts }, sig) -> bool.
// `enrolledDevicePubJwk` is the ECDSA public JWK from the vault's d.<deviceId> record. Verifies the
// raw-P1363 base64url signature over the canonical flat body. This is the PURE crypto check; the
// "is this an enrolled device + nonce/ts fresh" policy lives in verifyAuthFull / vault.verifyAuth.
export async function verifyAuth(enrolledDevicePubJwk, { aud, deviceId, nonce, ts }, sig) {
  const body = authBody({ aud, deviceId, nonce, ts });
  return C.verifyRecord(enrolledDevicePubJwk, body, sig);
}

// Full relying-party verification with freshness + identity binding. `lookupDevice(deviceId)`
// returns the enrolled `d.<id>` record (with .ecdsaPub) or null. Returns { ok, deviceId, label }.
export async function verifyAuthFull(
  { aud, deviceId, nonce, ts, sig },
  { expectedAud, serverSecret, lookupDevice, ttlSecs = AUTH_TTL_SECS } = {},
) {
  if (expectedAud != null && aud !== String(expectedAud)) return { ok: false, reason: 'aud-mismatch' };
  if (serverSecret != null && !(await checkNonce(serverSecret, ts, nonce, ttlSecs))) {
    return { ok: false, reason: 'bad-nonce-or-expired' };
  }
  const rec = lookupDevice ? await lookupDevice(deviceId) : null;
  if (!rec) return { ok: false, reason: 'not-enrolled' };
  if (!(await verifyAuth(rec.ecdsaPub, { aud, deviceId, nonce, ts }, sig))) {
    return { ok: false, reason: 'bad-signature' };
  }
  return { ok: true, deviceId, label: rec.label };
}

export function nowISO() { return new Date().toISOString(); }
