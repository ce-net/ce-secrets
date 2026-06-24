// ce-secrets — Browser SDK. The reusable client any ce-net web app embeds for auth + secrets.
// Same isomorphic core as the Node SDK (crypto.mjs + vault.mjs); only storage differs (the
// device key lives in IndexedDB + localStorage, the vault is the CE hub over fetch).
//
//   import { Vault } from 'ce-secrets/client';
//   const v = await Vault.open({ namespace: 'vault-<prefix>' });   // or auto-derive from URL
//   if (!(await v.enrolled())) { const code = await v.pair('my phone'); /* show code */ }
//   const key = await v.get('some-secret');     // once enrolled + approved
//
// The device becomes "yours" when an already-trusted device approves its pairing code.

import * as C from './crypto.mjs';
import * as V from './vault.mjs';

const DEFAULT_HUB = 'https://ce-net.com';
const DEVKEY = 'ce_vault_device';

// Durable device-key storage: IndexedDB (primary) + localStorage (mirror). iOS can wipe one.
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('ce_secrets', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function idbGet(k) { try { const db = await idb(); return await new Promise((res, rej) => { const t = db.transaction('kv').objectStore('kv').get(k); t.onsuccess = () => res(t.result ?? null); t.onerror = () => rej(t.error); }); } catch { return null; } }
async function idbSet(k, v) { try { const db = await idb(); await new Promise((res, rej) => { const tx = db.transaction('kv', 'readwrite'); tx.objectStore('kv').put(v, k); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); }); } catch {} }

async function loadDeviceKey() {
  let dk = await idbGet(DEVKEY);
  if (!dk) { try { dk = JSON.parse(localStorage.getItem(DEVKEY) || 'null'); } catch {} }
  return dk;
}
async function saveDeviceKey(dk) { try { localStorage.setItem(DEVKEY, JSON.stringify(dk)); } catch {} await idbSet(DEVKEY, dk); }

function hubStore(ns, hub) {
  const url = (k) => `${hub}/db/${ns}/${encodeURIComponent(k)}`;
  return {
    async get(k) { const r = await fetch(url(k)); if (r.status === 404) return null; if (!r.ok) throw new Error(`GET ${k} ${r.status}`); return r.json(); },
    async put(k, v) { const r = await fetch(url(k), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(v) }); if (!r.ok) throw new Error(`PUT ${k} ${r.status}`); },
    async del(k) { await fetch(url(k), { method: 'DELETE' }); },
    async list(p) { const r = await fetch(`${hub}/db/${ns}?prefix=${encodeURIComponent(p)}&limit=1000`); if (!r.ok) throw new Error(`LIST ${r.status}`); return (await r.json()).items || []; },
  };
}

// Derive vault namespace from the app host/path when not given: <anything>-<prefix> -> vault-<prefix>.
function deriveNamespace() {
  const q = new URLSearchParams(location.search).get('vaultns');
  if (q) { localStorage.setItem('ce_vault_ns', q); return q; }
  const saved = localStorage.getItem('ce_vault_ns'); if (saved) return saved;
  const m = location.host.match(/-([0-9a-f]{6,})\./) || location.pathname.match(/\/apps\/[^/]*-([0-9a-f]{6,})\//);
  return m ? `vault-${m[1]}` : null;
}

export class Vault {
  constructor(ctx, ns) { this._ctx = ctx; this.namespace = ns; this.deviceId = ctx.device.id; }

  static async open({ namespace, hub = DEFAULT_HUB } = {}) {
    const ns = namespace || deriveNamespace();
    if (!ns) throw new Error('no vault namespace — pass {namespace} or open via an app URL');
    let dk = await loadDeviceKey();
    if (!dk) { dk = await C.generateDeviceKey(); }
    await saveDeviceKey(dk);
    return new Vault({ store: hubStore(ns, hub.replace(/\/+$/, '')), device: dk }, ns);
  }

  exists() { return V.vaultExists(this._ctx); }
  enrolled() { return V.isEnrolled(this._ctx); }
  init(label) { return V.initVault(this._ctx, label); }

  // Enroll THIS browser as a device: reuses a still-pending code so it stops rotating.
  async pair(label) {
    if (await V.isEnrolled(this._ctx)) return null;
    const saved = localStorage.getItem('ce_vault_paircode');
    if (saved && (await this._ctx.store.get(`p.${saved}`))) return saved;
    const code = await V.requestPairing(this._ctx, label || 'browser');
    localStorage.setItem('ce_vault_paircode', code);
    return code;
  }
  async waitEnrolled(timeoutMs = 600000) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) { if (await V.isEnrolled(this._ctx)) { localStorage.removeItem('ce_vault_paircode'); return true; } await new Promise((r) => setTimeout(r, 3000)); }
    return false;
  }
  listPairing() { return V.listPairing(this._ctx); }
  approve(code) { return V.approvePairing(this._ctx, code); }
  devices() { return V.listDevices(this._ctx); }
  revokeDevice(id) { return V.revokeDevice(this._ctx, id); }

  gen(name, { type = 'token', length } = {}) { return V.generateSecret(this._ctx, name, type, { length }); }
  put(name, value, type = 'opaque') { return V.putSecret(this._ctx, name, typeof value === 'string' ? C.enc.utf8.enc(value) : value, type); }
  rotate(name) { return V.rotateSecret(this._ctx, name); }
  list() { return V.listSecrets(this._ctx); }
  info(name) { return V.secretMeta(this._ctx, name); }
  remove(name) { return V.deleteSecret(this._ctx, name); }
  async get(name) { const { bytes } = await V.revealSecret(this._ctx, name); return C.enc.utf8.dec(bytes); }
  async fingerprint(name) { const m = await V.secretMeta(this._ctx, name); return m && m.fp; }

  grant(audience, opts) { return V.issueGrant(this._ctx, audience, opts); }
  revokeGrant(id) { return V.revokeGrant(this._ctx, id); }
  listGrants() { return V.listGrants(this._ctx); }
  verifyGrant(token, audience, action, name) { return V.verifyGrant(this._ctx, token, audience, action, name); }
}

export { C as crypto, V as vault };
export default Vault;
