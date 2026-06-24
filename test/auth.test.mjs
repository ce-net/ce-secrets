// node --test suite for the ce-secrets AUTH primitive + the golden-vector self-check.
//
//   node --test test/
//
// Covers: sign/verify roundtrip, wrong-device rejection, expired-ts rejection, bad-nonce rejection,
// the vault-level verifyAuth (enrolled vs un-enrolled), and a re-verify/re-decrypt of every entry
// in fixtures/vectors.json so the canonical vectors can never silently drift from the .mjs core.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as C from '../src/crypto.mjs';
import * as V from '../src/vault.mjs';
import * as A from '../src/auth.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = path.join(__dirname, '..', 'fixtures', 'vectors.json');

function memStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? JSON.parse(m.get(k)) : null; },
    async put(k, v) { m.set(k, JSON.stringify(v)); },
    async del(k) { m.delete(k); },
    async list(p) { return [...m.entries()].filter(([k]) => k.startsWith(p)).map(([k, v]) => ({ key: k, value: JSON.parse(v) })); },
  };
}

// ---- pure auth primitive ----------------------------------------------------

test('signChallenge / verifyAuth roundtrip', async () => {
  const device = await C.generateDeviceKey();
  const body = { aud: 'ce-watch', deviceId: device.id, nonce: 'abc123', ts: A.nowISO() };
  const sig = await A.signChallenge(device, body);
  assert.equal(typeof sig, 'string');
  assert.ok(!/[+/=]/.test(sig), 'signature is base64url with no padding');
  assert.equal(C.enc.b64.dec(sig).length, 64, 'signature is raw P1363 64 bytes, not DER');
  assert.equal(await A.verifyAuth(device.ecdsaPub, body, sig), true);
});

test('wrong-device signature is rejected', async () => {
  const signer = await C.generateDeviceKey();
  const other = await C.generateDeviceKey();
  const body = { aud: 'ce-watch', deviceId: signer.id, nonce: 'n', ts: A.nowISO() };
  const sig = await A.signChallenge(signer, body);
  assert.equal(await A.verifyAuth(other.ecdsaPub, body, sig), false, 'a different device key must not verify');
});

test('tampered body is rejected', async () => {
  const device = await C.generateDeviceKey();
  const body = { aud: 'ce-watch', deviceId: device.id, nonce: 'n', ts: A.nowISO() };
  const sig = await A.signChallenge(device, body);
  assert.equal(await A.verifyAuth(device.ecdsaPub, { ...body, aud: 'ce-cast' }, sig), false);
});

test('stateless nonce: makeNonce / checkNonce', async () => {
  const ss = 'server-secret';
  const ts = A.nowISO();
  const nonce = await A.makeNonce(ss, ts);
  assert.match(nonce, /^[0-9a-f]{64}$/, 'nonce is hex sha256 mac');
  assert.equal(await A.checkNonce(ss, ts, nonce), true);
});

test('expired-ts nonce is rejected (TTL)', async () => {
  const ss = 'server-secret';
  const oldTs = new Date(Date.now() - 1000 * 1000).toISOString(); // 1000s ago, beyond 300s TTL
  const nonce = await A.makeNonce(ss, oldTs);
  assert.equal(await A.checkNonce(ss, oldTs, nonce), false, 'a stale ts must fail the 300s TTL');
});

test('bad-nonce is rejected (wrong server secret / tampered)', async () => {
  const ts = A.nowISO();
  const good = await A.makeNonce('server-secret', ts);
  assert.equal(await A.checkNonce('other-secret', ts, good), false, 'nonce minted under another secret fails');
  assert.equal(await A.checkNonce('server-secret', ts, good.slice(0, -1) + (good.endsWith('0') ? '1' : '0')), false, 'tampered nonce fails');
});

test('verifyAuthFull ties freshness + enrollment + signature', async () => {
  const device = await C.generateDeviceKey();
  const ss = 'rp-secret';
  const ts = A.nowISO();
  const nonce = await A.makeNonce(ss, ts);
  const sig = await A.signChallenge(device, { aud: 'ce-watch', nonce, ts });
  const lookupDevice = async (id) => (id === device.id ? { ecdsaPub: device.ecdsaPub, label: 'laptop' } : null);

  const ok = await A.verifyAuthFull(
    { aud: 'ce-watch', deviceId: device.id, nonce, ts, sig },
    { expectedAud: 'ce-watch', serverSecret: ss, lookupDevice },
  );
  assert.deepEqual(ok, { ok: true, deviceId: device.id, label: 'laptop' });

  const wrongAud = await A.verifyAuthFull({ aud: 'x', deviceId: device.id, nonce, ts, sig }, { expectedAud: 'ce-watch', serverSecret: ss, lookupDevice });
  assert.equal(wrongAud.ok, false);

  const unknown = await A.verifyAuthFull({ aud: 'ce-watch', deviceId: 'deadbeef', nonce, ts, sig }, { expectedAud: 'ce-watch', serverSecret: ss, lookupDevice: async () => null });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.reason, 'not-enrolled');
});

// ---- vault-level verifyAuth (enrolled device set) ---------------------------

test('vault.signChallenge -> vault.verifyAuth for an enrolled device', async () => {
  const store = memStore();
  const laptop = { device: await C.generateDeviceKey(), store };
  await V.initVault(laptop, 'laptop');

  const nonce = C.enc.b64.enc(C.randomBytes(32));
  const proof = await V.signChallenge(laptop, 'ce-watch', nonce);
  const verdict = await V.verifyAuth(laptop, 'ce-watch', nonce, proof);
  assert.equal(verdict.ok, true);
  assert.equal(verdict.deviceId, laptop.device.id);
});

test('vault.verifyAuth rejects an un-enrolled device', async () => {
  const store = memStore();
  const laptop = { device: await C.generateDeviceKey(), store };
  await V.initVault(laptop, 'laptop');

  const intruder = { device: await C.generateDeviceKey(), store };
  const nonce = C.enc.b64.enc(C.randomBytes(32));
  const proof = await V.signChallenge(intruder, 'ce-watch', nonce);
  const verdict = await V.verifyAuth(laptop, 'ce-watch', nonce, proof);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'not-enrolled');
});

test('vault.verifyAuth rejects aud/nonce mismatch and a swapped key', async () => {
  const store = memStore();
  const laptop = { device: await C.generateDeviceKey(), store };
  await V.initVault(laptop, 'laptop');
  const nonce = C.enc.b64.enc(C.randomBytes(32));
  const proof = await V.signChallenge(laptop, 'ce-watch', nonce);

  assert.equal((await V.verifyAuth(laptop, 'other-aud', nonce, proof)).ok, false);
  assert.equal((await V.verifyAuth(laptop, 'ce-watch', 'other-nonce', proof)).ok, false);

  const other = await C.generateDeviceKey();
  const forged = { ...proof, ecdsaPub: other.ecdsaPub };
  const v = await V.verifyAuth(laptop, 'ce-watch', nonce, forged);
  assert.equal(v.ok, false, 'a proof presenting a key other than the enrolled one must be rejected');
});

// ---- golden vectors self-check (canonical source of truth) ------------------

test('vectors.json: re-verify and re-decrypt every entry', async (t) => {
  const raw = await fs.readFile(VECTORS, 'utf8').catch(() => null);
  assert.ok(raw, 'fixtures/vectors.json must exist (run `npm run vectors`)');
  const vec = JSON.parse(raw);

  await t.test('deviceId reproduces from the pub coords', async () => {
    const id = await C.deviceId(vec.device.ecdhPub, vec.device.ecdsaPub);
    assert.equal(id, vec.device.deviceId);
  });

  await t.test('canonicalization matches stable_stringify', () => {
    assert.equal(A.stable_stringify(vec.canonicalization.example_object), vec.canonicalization.example_canonical);
    assert.equal(A.stable_stringify(vec.auth.body), vec.auth.canonical);
  });

  await t.test('masterWrap UNWRAPs to the known master', async () => {
    const master = await C.unwrapMaster(vec.masterWrap.wrapped, vec.masterWrap.recipientEcdhPriv);
    assert.equal(C.enc.hex.enc(master), vec.masterWrap.expectMasterHex);
  });

  await t.test('secret DECRYPTs to the known plaintext', async () => {
    const master = C.enc.hex.dec(vec.secret.masterHex);
    const pt = await C.openSecret(master, vec.secret.sealed);
    assert.equal(C.enc.utf8.dec(pt), vec.secret.expectPlaintext);
  });

  await t.test('auth signature VERIFIES (raw P1363, base64url no-pad)', async () => {
    assert.equal(C.enc.b64.dec(vec.auth.sig).length, 64);
    assert.ok(!/[+/=]/.test(vec.auth.sig));
    const ok = await A.verifyAuth(vec.auth.ecdsaPub, vec.auth.body, vec.auth.sig);
    assert.equal(ok, vec.auth.expectVerify);
  });

  await t.test('stateless nonce reproduces (HMAC-SHA256 hex)', async () => {
    const n = await A.makeNonce(vec.nonce.serverSecret, vec.nonce.ts);
    assert.equal(n, vec.nonce.nonce);
  });
});
