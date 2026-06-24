// ce-secrets — Node SDK. The programmatic surface other ce-net code uses for auth + secrets.
//
//   import { openVault } from 'ce-secrets';
//   const vault = await openVault();                 // node-id namespace, Keychain device key
//   await vault.gen('youtube-key', { type: 'token' });
//   const key = await vault.get('youtube-key');      // plaintext (SDK callers may read)
//   await vault.use(['youtube-key'], async (env) => { /* env.YOUTUBE_KEY set */ });
//   const token = await vault.grant('relay', { read: ['youtube-key'], expires: '30d' });
//
// Unlike the CLI, the SDK lets callers read values (that's the point of an SDK). The CLI is the
// layer that refuses to print. Storage + crypto are the same isomorphic core the browser uses.

import * as C from './crypto.mjs';
import * as V from './vault.mjs';
import * as S from './store.mjs';
import * as A from './auth.mjs';

const enc = C.enc;

/**
 * Open (or attach to) the vault for this machine.
 * @param {object} [opts]
 * @param {string} [opts.hub]        hub base URL (default https://ce-net.com or CE_HUB)
 * @param {string} [opts.namespace]  vault namespace (default vault-<node-prefix>)
 * @param {object} [opts.store]      custom store {get,put,del,list} (tests/embedding)
 * @param {object} [opts.device]     pre-loaded device key (skip keychain/file)
 */
export async function openVault(opts = {}) {
  const ns = opts.namespace || (await S.vaultNamespace());
  const store = opts.store || S.hubStore(ns, opts.hub);
  let device = opts.device;
  let where = 'provided';
  if (!device) { const r = await S.loadOrCreateDeviceKey(); device = r.dk; where = r.where; }
  const ctx = { store, device };
  return new Vault(ctx, ns, where);
}

export class Vault {
  constructor(ctx, namespace, deviceWhere) {
    this._ctx = ctx; this.namespace = namespace; this.deviceWhere = deviceWhere;
    this.deviceId = ctx.device.id;
  }

  // ---- lifecycle / devices ----
  exists() { return V.vaultExists(this._ctx); }
  enrolled() { return V.isEnrolled(this._ctx); }
  init(label) { return V.initVault(this._ctx, label); }
  requestPairing(label) { return V.requestPairing(this._ctx, label); }
  listPairing() { return V.listPairing(this._ctx); }
  approve(code) { return V.approvePairing(this._ctx, code); }
  devices() { return V.listDevices(this._ctx); }
  revokeDevice(id) { return V.revokeDevice(this._ctx, id); }

  // ---- secrets ----
  /** Generate a secret of `type` and store it. Returns metadata (no value). */
  gen(name, { type = 'token', length } = {}) { return V.generateSecret(this._ctx, name, type, { length }); }
  /** Store an existing secret value (string or Uint8Array). */
  put(name, value, type = 'opaque') {
    const bytes = typeof value === 'string' ? enc.utf8.enc(value) : value;
    return V.putSecret(this._ctx, name, bytes, type);
  }
  rotate(name) { return V.rotateSecret(this._ctx, name); }
  list() { return V.listSecrets(this._ctx); }
  info(name) { return V.secretMeta(this._ctx, name); }
  remove(name) { return V.deleteSecret(this._ctx, name); }
  /** Read a secret as a string (decrypts; SDK callers may see the value). */
  async get(name) { const { bytes } = await V.revealSecret(this._ctx, name); return enc.utf8.dec(bytes); }
  /** Read a secret as raw bytes. */
  async getBytes(name) { return (await V.revealSecret(this._ctx, name)).bytes; }
  async fingerprint(name) { const m = await V.secretMeta(this._ctx, name); return m && m.fp; }

  /** Run `fn(env)` with the named secrets injected into a plain env object (UPPER_SNAKE keys). */
  async use(names, fn) {
    const env = {};
    for (const n of names) env[n.toUpperCase().replace(/[^A-Z0-9]+/g, '_')] = await this.get(n);
    return fn(env);
  }

  // ---- app grants (authorization) ----
  /** Issue a signed grant token authorizing an app/audience to read named secrets. */
  grant(audience, { read = [], expires } = {}) { return V.issueGrant(this._ctx, audience, { read, expires }); }
  revokeGrant(id) { return V.revokeGrant(this._ctx, id); }
  listGrants() { return V.listGrants(this._ctx); }
  /** Verify a grant token (issued by an enrolled device) for an action on a secret. */
  verifyGrant(token, audience, action, name) { return V.verifyGrant(this._ctx, token, audience, action, name); }

  // ---- challenge-response auth (login) ----
  /** Sign a relying party's challenge nonce, proving this enrolled device is the operator. */
  signChallenge(aud, nonce, ts) { return V.signChallenge(this._ctx, aud, nonce, ts); }
  /** Verify an AuthProof against this vault's enrolled devices. -> { ok, deviceId, label }. */
  verifyAuth(aud, nonce, proof) { return V.verifyAuth(this._ctx, aud, nonce, proof); }
  /**
   * Full login round-trip against a relying party.
   * `rp` = { challenge(): Promise<{nonce, aud?, ts?}>, submit(proof): Promise<Session> }.
   */
  async login(rp) {
    const aud = rp.aud;
    const { nonce, aud: cAud = aud, ts } = await rp.challenge();
    const proof = await this.signChallenge(cAud, nonce, ts);
    return rp.submit(proof);
  }
}

export { C as crypto, V as vault, S as store, A as auth };
export const generate = C.generate;
export const {
  stable_stringify, makeNonce, checkNonce, signChallenge, verifyAuth, verifyAuthFull,
  authBody, nowISO, AUTH_TTL_SECS,
} = A;
