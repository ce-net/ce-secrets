#!/usr/bin/env node
// ce-secrets — a secrets vault CLI. Generate/rotate/store keys under a NAME without ever
// seeing or printing the value. Your devices (laptop, phone tab) share one encrypted vault;
// apps get access only when you grant it.
//
//   ce-secrets init [--label L]          create the vault on this (first) device
//   ce-secrets pair  [--label L]         enroll THIS device: prints a code to approve elsewhere
//   ce-secrets device ls|pending|approve <code>|approve-all|revoke <id>
//   ce-secrets gen <name> --type T [--length N]   generate + store (never prints the value)
//   ce-secrets put <name> [--type T]     store an EXISTING secret (read with no echo / from stdin)
//   ce-secrets ls                        list names + type + fingerprint (never values)
//   ce-secrets info <name>               metadata + public half (for keypairs)
//   ce-secrets rotate <name>             generate a new value, bump version
//   ce-secrets fingerprint <name>        print only a safe SHA-256 fingerprint
//   ce-secrets use <name…> -- <cmd…>     run <cmd> with the secrets injected as env vars
//   ce-secrets rm <name>                 delete a secret
//   ce-secrets whoami                    this device id + vault namespace
//   ce-secrets selftest                  offline crypto+vault roundtrip (no network)
//
// Types: token, password, base64, uuid, aes-256, ed25519, x25519, rsa-2048, rsa-4096.
// Flags: --hub <url>  --type <t>  --length <n>  --label <l>  --env <NAME>

import { spawn } from 'node:child_process';
import * as C from '../src/crypto.mjs';
import * as V from '../src/vault.mjs';
import * as S from '../src/store.mjs';
import * as A from '../src/auth.mjs';

const argv = process.argv.slice(2);
const opts = { _: [] };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--') { opts._.push('--', ...argv.slice(i + 1)); break; }
  else if (a.startsWith('--')) { const k = a.slice(2); if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) opts[k] = argv[++i]; else opts[k] = true; }
  else opts._.push(a);
}
const cmd = opts._[0];
const die = (m) => { console.error('error:', m); process.exit(1); };
const envName = (name) => (opts.env && typeof opts.env === 'string' ? opts.env : name.toUpperCase().replace(/[^A-Z0-9]+/g, '_'));

async function ctx() {
  const { dk, created, where } = await S.loadOrCreateDeviceKey();
  if (created) console.error(`(generated this device's key in ${where})`);
  const ns = await S.vaultNamespace();
  const hub = (typeof opts.hub === 'string' && opts.hub) || undefined;
  return { device: dk, store: S.hubStore(ns, hub), ns, deviceWhere: where };
}

// Read a secret with no echo (TTY) or from a pipe.
function readSecretNoEcho(prompt) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) { let d = ''; process.stdin.on('data', (c) => (d += c)); process.stdin.on('end', () => resolve(d.replace(/\r?\n$/, ''))); return; }
    process.stderr.write(prompt);
    process.stdin.setRawMode(true); process.stdin.resume();
    let buf = '';
    const onData = (ch) => {
      const code = ch[0];
      if (code === 0x0d || code === 0x0a) { process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.off('data', onData); process.stderr.write('\n'); resolve(buf); }
      else if (code === 0x03) { process.stdin.setRawMode(false); process.stderr.write('\n'); process.exit(130); }
      else if (code === 0x7f || code === 0x08) { buf = buf.slice(0, -1); }
      else buf += ch.toString('utf8');
    };
    process.stdin.on('data', onData);
  });
}

async function main() {
  switch (cmd) {
    case 'selftest': return selftest();

    case 'whoami': {
      const c = await ctx();
      console.log(`device: ${c.device.id}  (key in ${c.deviceWhere})`);
      console.log(`vault:  ${c.ns}`);
      console.log(`enrolled: ${(await V.isEnrolled(c)) ? 'yes' : 'no — run `ce-secrets pair`'}`);
      return;
    }

    case 'init': {
      const c = await ctx();
      const made = await V.initVault(c, opts.label);
      if (made) console.log(`vault created. this device (${c.device.id}) is enrolled.`);
      else if (await V.isEnrolled(c)) console.log(`vault already exists; this device is already enrolled.`);
      else console.log(`a vault already exists. run \`ce-secrets pair\` here, then approve it from a trusted device.`);
      return;
    }

    case 'pair': {
      const c = await ctx();
      if (await V.isEnrolled(c)) return console.log('this device is already enrolled.');
      const code = await V.requestPairing(c, opts.label || hostLabel());
      console.log(`pairing code: ${code}`);
      console.log(`on a trusted device run:  ce-secrets device approve ${code}`);
      return;
    }

    case 'pair-url': {
      const c = await ctx();
      const prefix = c.ns.replace(/^vault-/, '');
      const hub = (typeof opts.hub === 'string' && opts.hub) || 'https://ce-net.com';
      const appHost = (typeof opts.app === 'string' && opts.app) || `https://vault-${prefix}.ce-net.com`;
      const url = `${appHost}/#ns=${encodeURIComponent(c.ns)}&hub=${encodeURIComponent(hub)}`;
      console.log('Open this on your phone to enroll it as a device:');
      console.log('  ' + url);
      console.log('Then it shows a code; approve it here with:  ce-secrets device approve <code>');
      return;
    }

    case 'device': {
      const c = await ctx();
      const sub = opts._[1];
      if (sub === 'ls') { for (const d of await V.listDevices(c)) console.log(`${d.self ? '*' : ' '} ${d.id}  ${d.label}  ${d.addedAt || ''}`); return; }
      if (sub === 'pending') {
        const ps = await V.listPairing(c);
        if (!ps.length) return console.log('(no pending pairing requests)');
        for (const p of ps) console.log(`${p.code}  ${p.label || 'new device'}  ${p.ts || ''}`);
        return;
      }
      if (sub === 'approve') { const id = await V.approvePairing(c, opts._[2] || die('need a pairing code')); console.log(`approved device ${id}.`); return; }
      if (sub === 'approve-all') {
        // No code to copy: approve every pending pairing (e.g. a browser tab that just requested it).
        // Run this on an already-enrolled device; it wraps the master to each waiting device.
        const ps = await V.listPairing(c);
        if (!ps.length) return console.log('(nothing to approve)');
        for (const p of ps) { const id = await V.approvePairing(c, p.code); console.log(`approved ${id}  (${p.label || 'new device'})`); }
        return;
      }
      if (sub === 'revoke') { await V.revokeDevice(c, opts._[2] || die('need a device id')); console.log('revoked. rotate secrets it held: `ce-secrets rotate <name>`.'); return; }
      return die('device ls|pending|approve <code>|approve-all|revoke <id>');
    }

    case 'gen': {
      const name = opts._[1] || die('name required');
      const c = await enrolledCtx();
      const r = await V.generateSecret(c, name, opts.type || 'token', { length: opts.length ? +opts.length : undefined });
      console.log(`stored ${name}  type=${r.type}  v${r.version}  fp=${r.fp}${r.public ? `  public=${r.public.slice(0, 24)}…` : ''}`);
      console.log('(the value was never displayed.)');
      return;
    }

    case 'put': case 'import': {
      const name = opts._[1] || die('name required');
      const c = await enrolledCtx();
      const val = await readSecretNoEcho(`paste value for "${name}" (hidden): `);
      if (!val) die('empty value');
      const r = await V.putSecret(c, name, C.enc.utf8.enc(val), opts.type || 'opaque');
      console.log(`stored ${name}  v${r.version}  fp=${r.fp}  (not displayed)`);
      return;
    }

    case 'rotate': {
      const name = opts._[1] || die('name required');
      const c = await enrolledCtx();
      const r = await V.rotateSecret(c, name);
      console.log(`rotated ${name} -> v${r.version}  fp=${r.fp}  (not displayed)`);
      return;
    }

    case 'ls': {
      const c = await ctx();
      const list = await V.listSecrets(c);
      if (!list.length) return console.log('(no secrets yet — `ce-secrets gen <name> --type token`)');
      for (const s of list) console.log(`${s.name.padEnd(24)} ${String(s.type).padEnd(12)} v${s.version}  fp=${s.fp}`);
      return;
    }

    case 'info': {
      const c = await ctx();
      const m = await V.secretMeta(c, opts._[1] || die('name required'));
      if (!m) return die('no such secret');
      console.log(JSON.stringify(m, null, 2));
      return;
    }

    case 'fingerprint': case 'fp': {
      const c = await ctx();
      const m = await V.secretMeta(c, opts._[1] || die('name required'));
      if (!m) return die('no such secret');
      console.log(m.fp);
      return;
    }

    case 'rm': case 'delete': {
      const c = await ctx();
      await V.deleteSecret(c, opts._[1] || die('name required'));
      console.log('deleted.');
      return;
    }

    case 'use': case 'run': {
      const dashIdx = opts._.indexOf('--');
      if (dashIdx < 0) return die('usage: ce-secrets use <name…> -- <command…>');
      const names = opts._.slice(1, dashIdx);
      const command = opts._.slice(dashIdx + 1);
      if (!names.length || !command.length) return die('need at least one <name> and a command after --');
      const c = await enrolledCtx();
      const env = { ...process.env };
      for (const name of names) { const { bytes } = await V.revealSecret(c, name); env[envName(name)] = C.enc.utf8.dec(bytes); }
      const child = spawn(command[0], command.slice(1), { stdio: 'inherit', env });
      child.on('exit', (code) => process.exit(code ?? 0));
      return;
    }

    case 'grant': {
      const audience = opts._[1] || die('usage: ce-secrets grant <app/audience> --read <name,name> [--expires 30d]');
      const c = await enrolledCtx();
      const read = String(opts.read || '').split(',').map((s) => s.trim()).filter(Boolean);
      if (!read.length) die('--read <name,name> required');
      const { id, token } = await V.issueGrant(c, audience, { read, expires: opts.expires });
      console.log(`granted ${audience}: read ${read.join(', ')}${opts.expires ? ` (expires ${opts.expires})` : ''}`);
      console.log(`grant id: ${id}`);
      console.log(`token (give this to the app):\n${token}`);
      return;
    }
    case 'grants': {
      const c = await ctx();
      const gs = await V.listGrants(c);
      if (opts.json) { console.log(JSON.stringify(gs, null, 2)); return; }
      if (!gs.length) return console.log('(no grants)');
      for (const g of gs) console.log(`${g.id}  ${g.audience.padEnd(16)} ${g.abilities.join(',')}  ${g.expires ? 'exp ' + g.expires : 'no-expiry'}`);
      return;
    }
    case 'revoke-grant': {
      const c = await ctx();
      await V.revokeGrant(c, opts._[1] || die('need a grant id'));
      console.log('grant revoked.');
      return;
    }

    case 'prove': {
      // Sign a challenge for an audience and print the AuthProof JSON (for scripting).
      // The nonce comes from --nonce; if absent, a fresh random base64url one is generated.
      const aud = opts._[1] || die('usage: ce-secrets prove <aud> [--nonce <b64url>] [--ts <iso>]');
      const c = await enrolledCtx();
      const nonce = (typeof opts.nonce === 'string' && opts.nonce) || C.enc.b64.enc(C.randomBytes(32));
      const ts = (typeof opts.ts === 'string' && opts.ts) || A.nowISO();
      const proof = await V.signChallenge(c, aud, nonce, ts);
      console.log(JSON.stringify(proof));
      return;
    }

    case 'login': {
      // Fetch a challenge from a relying party, sign it, submit the proof. The RP is expected to
      // expose GET <rp>/challenge -> {nonce[,ts]} and accept the proof at POST <rp>/login.
      const aud = opts._[1] || die('usage: ce-secrets login <aud> --rp <url>');
      const rpBase = (typeof opts.rp === 'string' && opts.rp) || die('--rp <url> required');
      const c = await enrolledCtx();
      const chRes = await fetch(`${rpBase.replace(/\/+$/, '')}/challenge?aud=${encodeURIComponent(aud)}`, { headers: { Connection: 'close' } });
      if (!chRes.ok) die(`challenge failed: ${chRes.status}`);
      const ch = await chRes.json();
      const proof = await V.signChallenge(c, aud, ch.nonce, ch.ts);
      const subRes = await fetch(`${rpBase.replace(/\/+$/, '')}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Connection: 'close' }, body: JSON.stringify(proof) });
      const text = await subRes.text();
      if (!subRes.ok) die(`login rejected: ${subRes.status} ${text}`);
      console.log(text);
      return;
    }

    default:
      console.log(`ce-secrets — secrets vault + auth. Commands:
  init, pair, pair-url, device ls|approve|revoke
  gen <name> --type T, put <name>, rotate <name>, ls, info, fingerprint, use <name..> -- cmd, rm
  grant <app> --read a,b [--expires 30d], grants, revoke-grant <id>
  prove <aud> [--nonce b64url], login <aud> --rp <url>
  whoami, selftest
No secret value is ever printed. Programmatic access: import { openVault } from 'ce-secrets'.`);
      return;
  }
}

async function enrolledCtx() {
  const c = await ctx();
  if (!(await V.isEnrolled(c))) {
    if (!(await V.vaultExists(c))) die('no vault yet — run `ce-secrets init`');
    die('this device is not enrolled — run `ce-secrets pair`, then approve it from a trusted device');
  }
  return c;
}

function hostLabel() { try { return `${process.env.USER || 'user'}@${(process.env.HOSTNAME || '').split('.')[0] || 'host'}`; } catch { return 'device'; } }

// In-memory store so selftest needs no network.
function memStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? JSON.parse(m.get(k)) : null; },
    async put(k, v) { m.set(k, JSON.stringify(v)); },
    async del(k) { m.delete(k); },
    async list(p) { return [...m.entries()].filter(([k]) => k.startsWith(p)).map(([k, v]) => ({ key: k, value: JSON.parse(v) })); },
  };
}
async function selftest() {
  const store = memStore();
  const laptop = { device: await C.generateDeviceKey(), store };
  const ok = (b, m) => { console.log(`${b ? 'ok ' : 'FAIL'}: ${m}`); if (!b) process.exitCode = 1; };

  ok(await V.initVault(laptop, 'laptop'), 'init vault on first device');
  await V.generateSecret(laptop, 'yt-key', 'token', { length: 24 });
  await V.generateSecret(laptop, 'db-pass', 'password', { length: 20 });
  const ls = await V.listSecrets(laptop);
  ok(ls.length === 2 && ls.every((s) => !('sealed' in s)), 'ls shows 2 secrets, no ciphertext leaked');

  // phone enrolls via pairing, then reads the SAME secret value
  const phone = { device: await C.generateDeviceKey(), store };
  const code = await V.requestPairing(phone, 'phone');
  await V.approvePairing(laptop, code);
  ok(await V.isEnrolled(phone), 'phone enrolled after laptop approval');
  const a = await V.revealSecret(laptop, 'yt-key');
  const b = await V.revealSecret(phone, 'yt-key');
  ok(C.enc.utf8.dec(a.bytes) === C.enc.utf8.dec(b.bytes), 'phone reads the SAME secret value as laptop');

  // an un-enrolled device cannot read
  const intruder = { device: await C.generateDeviceKey(), store };
  let denied = false; try { await V.revealSecret(intruder, 'yt-key'); } catch (e) { denied = e.code === 'NOT_ENROLLED'; }
  ok(denied, 'un-enrolled device is refused (NOT_ENROLLED)');

  // rotation changes the value
  const before = C.enc.utf8.dec((await V.revealSecret(laptop, 'yt-key')).bytes);
  await V.rotateSecret(laptop, 'yt-key');
  const after = C.enc.utf8.dec((await V.revealSecret(laptop, 'yt-key')).bytes);
  ok(before !== after, 'rotate produces a new value');

  console.log(process.exitCode ? '\nSELFTEST FAILED' : '\nSELFTEST PASSED');
}

main()
  .then(() => { if (cmd !== 'use' && cmd !== 'run') process.exit(0); })  // don't let undici keep us alive
  .catch((e) => die(e.message || String(e)));
