// ce-secrets standalone app — manage your vault from any device. Uses the browser SDK.
import { Vault } from './client.js';

const $ = (s) => document.querySelector(s);
const msg = (text, kind = '') => { const e = $('#msg'); e.textContent = text; e.dataset.k = kind; };
const pairMsg = (text, kind = '') => { const e = $('#pairMsg'); e.textContent = text; e.dataset.k = kind; };

let vault;

async function boot() {
  try { vault = await Vault.open(); }
  catch (e) { msg(String(e.message || e), 'err'); return; }
  $('#ns').textContent = vault.namespace;
  $('#devid').textContent = 'device ' + vault.deviceId;
  await refreshEnroll();
}

async function refreshEnroll() {
  const enrolled = await vault.enrolled().catch(() => false);
  $('#enroll').textContent = enrolled ? 'enrolled' : 'not enrolled';
  $('#enroll').dataset.on = String(enrolled);
  $('#pairBox').classList.toggle('hidden', enrolled);
  // hide management cards until enrolled (can't decrypt/manage otherwise)
  for (const id of ['#secretsCard', '#devicesCard', '#grantsCard']) $(id).classList.toggle('hidden', !enrolled);
  if (enrolled) { await Promise.all([loadSecrets(), loadDevices(), loadGrants()]); }
  else {
    const exists = await vault.exists().catch(() => false);
    pairMsg(exists ? 'Tap to get a code, then approve it on a trusted device.' : 'No vault yet — run `ce-secrets init` on your laptop first.');
  }
}

// ---- pairing ----
$('#pairBtn').addEventListener('click', async () => {
  $('#pairBtn').disabled = true;
  try {
    const code = await vault.pair(navigator.userAgent.includes('iPhone') ? 'iphone' : 'browser');
    if (!code) { await refreshEnroll(); return; }
    pairMsg(`On a trusted device run:  ce-secrets device approve ${code}  — waiting…`);
    const ok = await vault.waitEnrolled();
    pairMsg(ok ? '✓ Paired.' : 'Timed out — tap to retry.', ok ? 'ok' : 'err');
    if (ok) await refreshEnroll();
  } catch (e) { pairMsg(String(e.message || e), 'err'); }
  finally { $('#pairBtn').disabled = false; }
});

// ---- secrets ----
async function loadSecrets() {
  const list = await vault.list();
  const el = $('#secrets'); el.innerHTML = '';
  if (!list.length) { el.innerHTML = '<p class="hint">No secrets yet.</p>'; return; }
  for (const s of list) {
    const row = document.createElement('div'); row.className = 'item';
    row.innerHTML = `<span class="name"></span><span class="meta"></span><span class="sp">
      <button data-act="rotate">rotate</button><button data-act="rm">delete</button></span>`;
    row.querySelector('.name').textContent = s.name;
    row.querySelector('.meta').textContent = `${s.type} · v${s.version} · ${s.fp}`;
    row.querySelector('[data-act="rotate"]').onclick = async () => { try { await vault.rotate(s.name); msg(`rotated ${s.name}`, 'ok'); loadSecrets(); } catch (e) { msg(e.message, 'err'); } };
    row.querySelector('[data-act="rm"]').onclick = async () => { if (!confirm(`Delete ${s.name}?`)) return; try { await vault.remove(s.name); msg(`deleted ${s.name}`, 'ok'); loadSecrets(); } catch (e) { msg(e.message, 'err'); } };
    el.appendChild(row);
  }
}
$('#genBtn').addEventListener('click', async () => {
  const name = $('#newName').value.trim(); const type = $('#newType').value;
  if (!name) return msg('name required', 'err');
  try { const r = await vault.gen(name, { type }); msg(`stored ${name} (${r.type} v${r.version}) — value not shown`, 'ok'); $('#newName').value = ''; loadSecrets(); }
  catch (e) { msg(String(e.message || e), 'err'); }
});

// ---- devices ----
async function loadDevices() {
  const devs = await vault.devices();
  const el = $('#devices'); el.innerHTML = '';
  for (const d of devs) {
    const row = document.createElement('div'); row.className = 'item';
    row.innerHTML = `<span class="name"></span><span class="meta"></span><span class="sp"></span>`;
    row.querySelector('.name').textContent = d.label + (d.self ? ' (this)' : '');
    row.querySelector('.meta').textContent = d.id;
    if (!d.self) { const b = document.createElement('button'); b.textContent = 'revoke'; b.onclick = async () => { if (!confirm(`Revoke ${d.label}?`)) return; try { await vault.revokeDevice(d.id); msg(`revoked ${d.label}`, 'ok'); loadDevices(); } catch (e) { msg(e.message, 'err'); } }; row.querySelector('.sp').appendChild(b); }
    el.appendChild(row);
  }
}
$('#approveBtn').addEventListener('click', async () => {
  const code = $('#approveCode').value.trim().toUpperCase();
  if (!code) return msg('enter a pairing code', 'err');
  try { const id = await vault.approve(code); msg(`approved device ${id}`, 'ok'); $('#approveCode').value = ''; loadDevices(); }
  catch (e) { msg(String(e.message || e), 'err'); }
});

// ---- grants ----
async function loadGrants() {
  const gs = await vault.listGrants();
  const el = $('#grants'); el.innerHTML = '';
  if (!gs.length) { el.innerHTML = '<p class="hint">No grants.</p>'; return; }
  for (const g of gs) {
    const row = document.createElement('div'); row.className = 'item';
    row.innerHTML = `<span class="name"></span><span class="meta"></span><span class="sp"><button>revoke</button></span>`;
    row.querySelector('.name').textContent = g.audience;
    row.querySelector('.meta').textContent = `${g.abilities.join(', ')}${g.expires ? ' · exp ' + g.expires.slice(0, 10) : ''}`;
    row.querySelector('button').onclick = async () => { try { await vault.revokeGrant(g.id); msg('grant revoked', 'ok'); loadGrants(); } catch (e) { msg(e.message, 'err'); } };
    el.appendChild(row);
  }
}
$('#grantBtn').addEventListener('click', async () => {
  const aud = $('#grantAud').value.trim();
  const read = $('#grantRead').value.split(',').map((s) => s.trim()).filter(Boolean);
  const expires = $('#grantExp').value.trim() || undefined;
  if (!aud || !read.length) return msg('audience and at least one secret required', 'err');
  try {
    const { token } = await vault.grant(aud, { read, expires });
    const t = $('#grantToken'); t.value = token; t.classList.remove('hidden');
    msg(`granted ${aud}`, 'ok'); loadGrants();
  } catch (e) { msg(String(e.message || e), 'err'); }
});

boot();
