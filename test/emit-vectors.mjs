// Emit ce-secrets/fixtures/vectors.json — the GOLDEN cross-language test vectors.
//
// This file is the CANONICAL source of truth that the Rust (ce-secrets-rs) and TS (@ce-net/secrets)
// SDKs assert against. Because AES-GCM and ECDSA are randomized, the vectors are recorded for the
// DETERMINISTIC verify/decrypt direction: every entry records key + input + nonce + output so any
// implementation can reproduce the OUTPUT given the INPUTS, with nothing left to chance.
//
// What is fixed (and why it is reproducible):
//   - device:   a fixed ECDH+ECDSA P-256 keypair (JWK), its raw pub bytes, and deviceId.
//   - master:   a fixed 32-byte master key (hex).
//   - wrapMaster: ECIES blob {eph,iv,ct} produced for the device — others must UNWRAP it back to
//                 the known master (the ephemeral key + iv are recorded, so the AES-GCM input is
//                 fully determined).
//   - sealSecret: a secret plaintext + its AES-GCM {iv,ct} under the master — others DECRYPT it.
//   - auth:     a fixed {aud,deviceId,nonce,ts} + its ECDSA-P1363 base64url signature — others VERIFY.
//
// Run: node test/emit-vectors.mjs   (writes fixtures/vectors.json)

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as C from '../src/crypto.mjs';
import * as A from '../src/auth.mjs';

const subtle = globalThis.crypto.subtle;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, '..', 'fixtures');

// A FIXED device keypair. These JWK `d` values are constants so the vector is reproducible; the
// public coords are derived from them by WebCrypto, guaranteeing internal consistency.
const ECDH_PRIV_D = 'sR3IYJSDqB8x4l3J3p6w8t3y2QZ1m0c9V7n4kL2bA8E';
const ECDSA_PRIV_D = 'pQ7w2zX9c4V6n8m1L3k5J7h9G2f4D6s8A0b2C4e6F8I';

// Import a P-256 private JWK (d only) and export the full {x,y,d} JWK + raw uncompressed pub bytes.
async function p256FromD(dB64u, use) {
  const algSign = use === 'sign'
    ? { name: 'ECDSA', namedCurve: 'P-256' }
    : { name: 'ECDH', namedCurve: 'P-256' };
  const usages = use === 'sign' ? ['sign'] : ['deriveBits'];
  // WebCrypto needs x,y to import a private EC JWK. Derive them by importing as a self-consistent
  // key: we import via a temporary generate? No — we must supply x,y. Instead, reconstruct the
  // public point from d using a one-shot: import the d with computed x,y via the `pkcs8` path is
  // not available. So we generate from the seed deterministically via the SubtleCrypto JWK import
  // that accepts {d} when {x,y} are also present. We therefore compute x,y with a tiny scalar mult.
  const { x, y } = await pubFromPriv(dB64u);
  const jwkPriv = { kty: 'EC', crv: 'P-256', d: dB64u, x, y, ext: true, key_ops: usages };
  const priv = await subtle.importKey('jwk', jwkPriv, algSign, true, usages);
  const fullPriv = await subtle.exportKey('jwk', priv);
  const pubUsages = use === 'sign' ? ['verify'] : [];
  const pub = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x, y, ext: true }, algSign, true, pubUsages);
  const fullPub = await subtle.exportKey('jwk', pub);
  const rawPub = new Uint8Array(await subtle.exportKey('raw', pub));
  return { priv: fullPriv, pub: fullPub, rawPub };
}

// Compute the P-256 public key (x,y base64url) for a scalar d (base64url) over secp256r1.
function pubFromPriv(dB64u) {
  const d = bytesToBig(C.enc.b64.dec(dB64u));
  const { x, y } = scalarMult(d % N);
  return { x: bigToB64u(x), y: bigToB64u(y) };
}

// --- minimal secp256r1 scalar multiplication (for vector generation only) ---
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const Acoef = -3n;
const Bcoef = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
function mod(a, m = P) { const r = a % m; return r >= 0n ? r : r + m; }
function inv(a, m = P) { let [lm, hm, low, high] = [1n, 0n, mod(a, m), m]; while (low > 1n) { const r = high / low; [lm, hm] = [hm - lm * r, lm]; [low, high] = [high - low * r, low]; } return mod(lm, m); }
function ptDouble(p) { if (!p) return null; const { x, y } = p; const s = mod((3n * x * x + Acoef) * inv(2n * y)); const nx = mod(s * s - 2n * x); const ny = mod(s * (x - nx) - y); return { x: nx, y: ny }; }
function ptAdd(p, q) { if (!p) return q; if (!q) return p; if (p.x === q.x && mod(p.y + q.y) === 0n) return null; if (p.x === q.x) return ptDouble(p); const s = mod((q.y - p.y) * inv(q.x - p.x)); const nx = mod(s * s - p.x - q.x); const ny = mod(s * (p.x - nx) - p.y); return { x: nx, y: ny }; }
function scalarMult(k) { let r = null; let a = { x: Gx, y: Gy }; while (k > 0n) { if (k & 1n) r = ptAdd(r, a); a = ptDouble(a); k >>= 1n; } return r; }
function bytesToBig(b) { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n; }
function bigToBytes32(n) { const out = new Uint8Array(32); for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; } return out; }
function bigToB64u(n) { return C.enc.b64.enc(bigToBytes32(n)); }

async function main() {
  const ecdh = await p256FromD(ECDH_PRIV_D, 'deriveBits');
  const ecdsa = await p256FromD(ECDSA_PRIV_D, 'sign');

  const device = {
    ecdhPriv: ecdh.priv, ecdhPub: ecdh.pub,
    ecdsaPriv: ecdsa.priv, ecdsaPub: ecdsa.pub,
  };
  device.id = await C.deviceId(device.ecdhPub, device.ecdsaPub);

  // Fixed 32-byte master.
  const master = C.enc.hex.dec('00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f');

  // ECIES wrap of the master to this device (randomized eph+iv — recorded so others can UNWRAP).
  const wrap = await C.wrapMaster(master, device.ecdhPub);
  // self-check: unwrap returns the master.
  const unwrapped = await C.unwrapMaster(wrap, device.ecdhPriv);
  assertEq(C.enc.hex.enc(unwrapped), C.enc.hex.enc(master), 'wrap/unwrap roundtrip');

  // Secret plaintext sealed under the master (randomized iv — recorded so others can DECRYPT).
  const secretPlaintext = 'sk-ce-secrets-golden-vector-0001';
  const sealed = await C.sealSecret(master, C.enc.utf8.enc(secretPlaintext));
  const opened = await C.openSecret(master, sealed);
  assertEq(C.enc.utf8.dec(opened), secretPlaintext, 'seal/open roundtrip');

  // Auth example: fixed flat body + ECDSA-P1363 base64url signature (others VERIFY).
  const authInput = { aud: 'ce-watch', deviceId: device.id, nonce: 'Z29sZGVuLW5vbmNlLTAwMDAwMDAwMDAwMDAwMDA', ts: '2026-06-24T00:00:00.000Z' };
  const sig = await A.signChallenge(device, authInput);
  const ok = await A.verifyAuth(device.ecdsaPub, authInput, sig);
  assertEq(ok, true, 'auth sign/verify roundtrip');

  // Stateless nonce vector: HMAC-SHA256(serverSecret, ts) hex.
  const serverSecret = 'golden-server-secret';
  const nonceHmac = await A.makeNonce(serverSecret, authInput.ts);

  const vectors = {
    note: 'GOLDEN vectors for ce-secrets. Verify/decrypt direction is deterministic. The five interop traps: (1) HKDF salt=EMPTY 0-bytes + info "ce-secrets/master-wrap/v1"; (2) AES-GCM 12-byte nonce, 16-byte tag appended to ct; (3) ECDSA raw P1363 64-byte sig, NOT DER; (4) base64url NO padding; (5) top-level-sorted-key JSON canonicalization (no whitespace).',
    version: 1,
    canonicalization: {
      algorithm: 'JSON.stringify(obj, Object.keys(obj).sort())',
      example_object: { b: 2, a: 1, c: 3 },
      example_canonical: A.stable_stringify({ b: 2, a: 1, c: 3 }),
    },
    device: {
      ecdhPriv: device.ecdhPriv, ecdhPub: device.ecdhPub,
      ecdsaPriv: device.ecdsaPriv, ecdsaPub: device.ecdsaPub,
      ecdhRawPubHex: C.enc.hex.enc(ecdh.rawPub),
      ecdsaRawPubHex: C.enc.hex.enc(ecdsa.rawPub),
      deviceId: device.id,
      deviceIdInput: '["' + [device.ecdhPub.x, device.ecdhPub.y, device.ecdsaPub.x, device.ecdsaPub.y].join('","') + '"]',
      deviceIdAlgorithm: 'hex(sha256(utf8(JSON.stringify([ecdhPub.x,ecdhPub.y,ecdsaPub.x,ecdsaPub.y]))))[..16]',
    },
    master: { hex: C.enc.hex.enc(master) },
    masterWrap: {
      algorithm: 'ECIES: ephemeral ECDH P-256 -> HKDF(SHA-256, salt=EMPTY, info="ce-secrets/master-wrap/v1") -> AES-256-GCM',
      hkdfSalt: 'EMPTY (zero-length, not absent)',
      hkdfInfo: 'ce-secrets/master-wrap/v1',
      recipientEcdhPub: device.ecdhPub,
      recipientEcdhPriv: device.ecdhPriv,
      wrapped: wrap,
      expectMasterHex: C.enc.hex.enc(master),
    },
    secret: {
      algorithm: 'AES-256-GCM under the master, 12-byte nonce, 16-byte tag appended, no AAD',
      masterHex: C.enc.hex.enc(master),
      plaintext: secretPlaintext,
      plaintextHex: C.enc.hex.enc(C.enc.utf8.enc(secretPlaintext)),
      sealed,
      expectPlaintext: secretPlaintext,
    },
    auth: {
      algorithm: 'ECDSA P-256/SHA-256 over UTF8(stableStringify({aud,deviceId,nonce,ts})), raw P1363 64-byte sig, base64url no-pad',
      body: authInput,
      canonical: A.stable_stringify(authInput),
      ecdsaPub: device.ecdsaPub,
      sig,
      expectVerify: true,
    },
    nonce: {
      algorithm: 'hex(HMAC-SHA256(serverSecret, ts)); TTL 300s on ts',
      serverSecret,
      ts: authInput.ts,
      nonce: nonceHmac,
      ttlSecs: A.AUTH_TTL_SECS,
    },
  };

  await fs.mkdir(FIXTURES, { recursive: true });
  const out = path.join(FIXTURES, 'vectors.json');
  await fs.writeFile(out, JSON.stringify(vectors, null, 2) + '\n');
  console.log(`wrote ${out}`);
}

function assertEq(a, b, msg) { if (JSON.stringify(a) !== JSON.stringify(b)) { console.error(`emit-vectors self-check FAILED: ${msg}: ${a} !== ${b}`); process.exit(1); } }

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
