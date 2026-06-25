// One-shot: copy a vault's records from the deprecated hub /db store into the mesh ce-kv store, so
// the mesh-native vault has the existing enrollment + master key + secrets (not an empty new vault).
// Run: CE_KV_NODE=<relay-node-id> node migrate-hub-to-mesh.mjs [vault-ns]
import * as S from "./src/store.mjs";

const ns = process.argv[2] || (await S.vaultNamespace());
const hub = S.hubStore(ns);
const mesh = S.meshStore(ns);

const h = await hub.list("");
const m = await mesh.list("");
console.log("  hub keys :", h.map((e) => e.key).sort().join(", ") || "(empty)");
console.log("  mesh keys:", m.map((e) => e.key).sort().join(", ") || "(empty)");

const have = new Set(m.map((e) => e.key));
let n = 0;
for (const { key, value } of h) {
  if (!have.has(key)) {
    await mesh.put(key, value);
    n++;
  }
}
console.log(`  migrated ${n} record(s) hub -> mesh`);
const after = await mesh.list("");
console.log("  mesh now :", after.map((e) => e.key).sort().join(", "));
