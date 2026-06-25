# ce-secrets — identity, vaults, and why "this machine has access" can still fail

This documents a real failure we hit, its root cause, the fix, and the design for making browser +
local identities share a vault automatically.

## The model

- **A vault is a hub-stored, encrypted KV** at `https://ce-net.com/db/<vault-ns>/…` (see
  `src/store.mjs` `hubStore`). Every record is encrypted under a **master key**; the master is
  **wrapped to each enrolled device's public key**. The hub never sees plaintext.
- **The vault namespace is `vault-<nodeprefix>`** — the first 10 hex of your **CE node id**
  (`vaultNamespace()` → `nodePrefix()`). This is deliberate: it ties the vault to the *same*
  identity `ce-app` uses for your app domain, so the CLI, the local node, and browser tabs all land
  on **one** vault.
- **A device** is one key in one place: the CLI key lives in the **macOS Keychain** (or a chmod-600
  file on Linux), a browser tab's key lives in **IndexedDB/localStorage**. These are *different
  devices* with *different keys* — they cannot share a key store. They are meant to share the
  **vault** (same namespace) and enroll each other via **pairing**.
- **Pairing**: a new device publishes a request (`p.<code>`); an already-enrolled device approves it
  (`approvePairing`), which wraps the master to the new device's pubkey. After that, both read the
  same secrets.

## The failure we hit (and why it's confusing)

Symptom: `ce-secrets ls` showed "(no secrets yet)" and `whoami` said `enrolled: no`, on a machine
whose **browser** vault clearly worked — "this Mac does have access, why doesn't it have access?"

Root cause: the namespace came out **wrong**. `nodePrefix()` read `~/.ce/id` as the source of truth,
and on this machine `~/.ce/id` held a **throwaway generated id** (`d9148f2327…`) — not the real CE
node id (`c0be11e0ce…`). So:

- the CLI talked to `vault-d9148f2327` — an **empty** namespace,
- while the secrets (and this device's own enrollment record `d.4ddb9926…`) lived in
  `vault-c0be11e0ce`, where the browser tabs had set them.

The device was **enrolled the whole time** — just in a vault the CLI never looked at. The
generate-fallback in `nodePrefix()` had written a random id into `~/.ce/id` once, and from then on
that stale cache **shadowed** the real node id forever. A cache silently overriding the source of
truth is the bug.

## The fix

`src/store.mjs`:

- **The real CE node id is the source of truth**, not a cache. `nodeId()` resolves it from `ce id`
  (authoritative) or the on-disk node identity.
- `~/.ce/id` is now only a **self-healing cache**: whenever the real node id is found it is written
  back, so a poisoned/throwaway cache repairs itself on the next run.
- A generated id is used **only** when there is genuinely no CE node on the machine, and it prints a
  warning that this is an isolated local vault.

Verified: poisoning `~/.ce/id` with garbage, the next `whoami` self-heals back to `vault-c0be11e0ce`
and the secrets reappear. `selftest` passes.

## Pairing without copying a code (toward automatic)

Browser tabs and the CLI are different devices, so a fresh one still needs approval. Two CLI
additions make that frictionless from an already-enrolled device:

```
ce-secrets device pending       # list pairing requests waiting for approval (e.g. a browser tab)
ce-secrets device approve-all   # approve every pending request — no code to copy/paste
```

Flow: open the vault in a browser → it requests pairing → on your enrolled laptop run
`ce-secrets device approve-all` → the tab is enrolled. No code transcription.

## Design: browser ⇄ local auto-enroll ("ideally they are the same thing")

The remaining manual step is approval. The intended end state, when a browser is **co-located with a
local CE node** (served same-origin with a `/ce` proxy, or reachable on localhost):

1. The browser detects the local node (it already speaks to it through the same-origin `/ce` proxy).
2. It resolves the **same vault namespace** from the node id (now guaranteed identical to the CLI,
   post-fix) and publishes a pairing request.
3. An enrolled local agent **auto-approves requests that prove same-machine origin** — e.g. the
   browser presents a short-lived token minted by the local node (proof of co-location), and the
   enrolled CLI/daemon approves only requests bearing a valid local-node proof.

This keeps the trust model intact (the master is still only ever wrapped to keys the operator's own
machine vouches for) while removing the code-copy step entirely. `device approve-all` is the manual
precursor; the auto path adds the co-location proof + a watcher. The namespace-unification fix above
is the prerequisite — without it, the browser and CLI were computing different vault ids and could
never have auto-paired.
