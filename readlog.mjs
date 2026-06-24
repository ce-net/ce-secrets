// Read phone logs shipped to the hub. Usage: node readlog.mjs [prefix] [sinceSeconds]
const NS = 'celog-' + (process.argv[2] || 'c0be11e0ce');
const since = process.argv[3] ? Date.now() - (+process.argv[3] * 1000) : 0;
const r = await fetch(`https://ce-net.com/db/${NS}?limit=1000`, { headers: { Connection: 'close' } });
const { items = [] } = await r.json();
const lines = [];
for (const it of items) {
  const v = it.value || {};
  for (const ln of (v.lines || [])) if ((ln.ts || 0) >= since) lines.push({ ts: ln.ts || 0, dev: (v.dev || '-').slice(0, 6), l: ln.l, m: ln.m });
}
lines.sort((a, b) => a.ts - b.ts);
if (!lines.length) console.log(`(no log lines in ${NS}${since ? ' in window' : ''})`);
for (const ln of lines) console.log(`${new Date(ln.ts).toISOString().slice(11, 23)} [${ln.dev}] ${String(ln.l).toUpperCase().padEnd(5)} ${ln.m}`);
