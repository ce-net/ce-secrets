// ce-secrets Node store — the two things the browser can't do the same way:
//   1. hubStore: the cross-device storage, the CE hub KV at /db/<vault-ns>/<key>.
//   2. deviceKeyStore: persist THIS device's private key in the OS keychain (macOS) or a
//      chmod-600 file (Linux/other). The key value is never printed to the terminal.
//
// The vault namespace is tied to your CE node id (same nodeprefix as ce-app), so it is not a
// global "secrets" bucket: vault-<nodeprefix>. Records are encrypted + signed regardless.

import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import * as C from './crypto.mjs';

const DEFAULT_HUB = process.env.CE_HUB || 'https://ce-net.com';

// ---- identity / namespace ---------------------------------------------------
// Reuse ~/.ce/id (the ce-app stable id; prefers `ce id`). nodeprefix = first 10 hex.
export async function nodePrefix() {
  const idFile = path.join(os.homedir(), '.ce', 'id');
  try { const id = (await fs.readFile(idFile, 'utf8')).trim(); if (/^[0-9a-f]{10,}$/i.test(id)) return id.slice(0, 10); } catch {}
  // fall back to `ce id`
  try { const r = spawnSync('ce', ['id'], { encoding: 'utf8', timeout: 4000 }); const m = (r.stdout || '').match(/[0-9a-f]{16,}/i); if (m) return m[0].slice(0, 10).toLowerCase(); } catch {}
  // last resort: a generated, persisted id
  const gen = C.enc.hex.enc(C.randomBytes(8));
  try { await fs.mkdir(path.dirname(idFile), { recursive: true }); await fs.writeFile(idFile, gen); } catch {}
  return gen.slice(0, 10);
}

export async function vaultNamespace() { return process.env.CE_VAULT_NS || `vault-${await nodePrefix()}`; }

// Keystore selection: 'auto' (macOS Keychain on darwin, else file), 'file', or 'keychain'.
// On Linux servers (the relay) and in CI, set CE_SECRETS_KEYSTORE=file.
function keystoreMode() { return process.env.CE_SECRETS_KEYSTORE || 'auto'; }
function useKeychain() { return process.platform === 'darwin' && keystoreMode() !== 'file'; }

// ---- hub KV store -----------------------------------------------------------
export function hubStore(ns, hub = DEFAULT_HUB) {
  hub = hub.replace(/\/+$/, '');
  const url = (key) => `${hub}/db/${ns}/${encodeURIComponent(key)}`;
  // Always consume the body and bound every request, or undici keeps the socket alive and
  // the CLI never exits. `close: true` avoids connection reuse hangs through Cloudflare.
  async function req(u, init = {}) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 15000);
    try {
      const r = await fetch(u, { ...init, signal: ac.signal, headers: { Connection: 'close', ...(init.headers || {}) } });
      const text = await r.text();
      return { status: r.status, ok: r.ok, text };
    } catch (e) { throw new Error(`hub ${init.method || 'GET'} ${u}: ${e.message}`); }
    finally { clearTimeout(t); }
  }
  return {
    async get(key) {
      const r = await req(url(key));
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`hub GET ${key}: ${r.status}`);
      return r.text ? JSON.parse(r.text) : null;
    },
    async put(key, value) {
      const r = await req(url(key), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
      if (!r.ok) throw new Error(`hub PUT ${key}: ${r.status}`);
    },
    async del(key) {
      const r = await req(url(key), { method: 'DELETE' });
      if (!r.ok && r.status !== 404) throw new Error(`hub DEL ${key}: ${r.status}`);
    },
    async list(prefix) {
      const r = await req(`${hub}/db/${ns}?prefix=${encodeURIComponent(prefix)}&limit=1000`);
      if (!r.ok) throw new Error(`hub LIST ${prefix}: ${r.status}`);
      const { items = [] } = JSON.parse(r.text || '{}');
      return items;
    },
  };
}

// ---- device key persistence (this device's private key) ---------------------
const KC_SERVICE = 'ce-secrets-device';
const FILE_PATH = path.join(os.homedir(), '.ce', 'secrets', 'device.json');

function macKeychainGet() {
  const r = spawnSync('security', ['find-generic-password', '-s', KC_SERVICE, '-w'], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  try { return JSON.parse(Buffer.from(r.stdout.trim(), 'base64').toString('utf8')); } catch { return null; }
}
function macKeychainSet(obj) {
  const b64 = Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
  // -U updates if present. -w value is the device key; it never touches the terminal.
  const r = spawnSync('security', ['add-generic-password', '-a', os.userInfo().username, '-s', KC_SERVICE, '-w', b64, '-U'], { encoding: 'utf8' });
  return r.status === 0;
}

export async function loadDeviceKey() {
  if (useKeychain()) { const k = macKeychainGet(); if (k) return k; }
  try { return JSON.parse(await fs.readFile(FILE_PATH, 'utf8')); } catch { return null; }
}
export async function saveDeviceKey(dk) {
  if (useKeychain() && macKeychainSet(dk)) return 'macOS Keychain';
  await fs.mkdir(path.dirname(FILE_PATH), { recursive: true });
  await fs.writeFile(FILE_PATH, JSON.stringify(dk), { mode: 0o600 });
  await fs.chmod(FILE_PATH, 0o600);
  return FILE_PATH;
}
export async function loadOrCreateDeviceKey() {
  const existing = await loadDeviceKey();
  if (existing) return { dk: existing, created: false, where: useKeychain() ? 'macOS Keychain' : FILE_PATH };
  const dk = await C.generateDeviceKey();
  const where = await saveDeviceKey(dk);
  return { dk, created: true, where };
}
