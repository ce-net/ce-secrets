# ce-secrets

A secrets vault for CE. You tell it what key you need; it generates and stores it under a
**name** — you never see or paste the value. Every one of your devices (laptop, and your phone
even though it's just a browser tab) shares one **encrypted** vault. Apps get access only when
you grant it.

```
ce-secrets gen youtube-key --type token      # generated + stored; value never printed
ce-secrets ls                                 # names + fingerprints, never values
ce-secrets use youtube-key -- ./publish.sh    # runs publish.sh with $YOUTUBE_KEY in its env
```

## How it stays safe

- **One master key** (random 32 bytes) encrypts every secret with AES-256-GCM.
- The master is **wrapped** to each authorized device's public key (ECDH P-256 → HKDF → AES-GCM).
  A device decrypts secrets only by unwrapping *its own* copy. That is how all your devices share
  the keys without the keys ever travelling in the clear.
- Records are **signed** (ECDSA P-256) by the writing device, so tampering is detectable.
- Storage is the CE hub KV at `/db/vault-<your-node-prefix>/…` — encrypted blobs only. The hub
  operator sees ciphertext, never plaintext.
- The CLI **never prints a secret value.** To use one, inject it into a process (`use`), never echo it.

This is **isomorphic**: the Node CLI and the browser (phone) client run the *same* `src/crypto.mjs`
and `src/vault.mjs`. Only the storage (OS Keychain vs IndexedDB) differs.

## Install

```bash
npm i -g ~/ce-net/ce-secrets      # provides the `ce-secrets` command
# or run directly: node ~/ce-net/ce-secrets/bin/ce-secrets.mjs <cmd>
```

Your device's private key lives in the **macOS Keychain** (service `ce-secrets-device`); on Linux
/ the relay set `CE_SECRETS_KEYSTORE=file` to store it at `~/.ce/secrets/device.json` (chmod 600).

## Commands

| Command | What it does |
|---|---|
| `init [--label L]` | Create the vault on this first device (mints the master, enrolls you). |
| `pair [--label L]` | Enroll THIS device — prints a code to approve from a trusted device. |
| `device ls` / `approve <code>` / `revoke <id>` | Manage devices (your phone shows up here). |
| `gen <name> --type T [--length N]` | Generate + store. **Never prints the value.** |
| `put <name> [--type T]` | Store an EXISTING secret (read with no echo, or piped from stdin). |
| `rotate <name>` | Generate a new value, bump the version. |
| `ls` / `info <name>` / `fingerprint <name>` | Inspect names, metadata, public halves, fingerprints. |
| `use <name…> -- <cmd…>` | Run `<cmd>` with each secret injected as an env var (UPPER_SNAKE of the name). |
| `rm <name>` / `whoami` / `selftest` | Delete, identify this device, offline self-check. |

**Types:** `token`, `password`, `base64`, `uuid`, `aes-256`, `ed25519`, `x25519`, `rsa-2048`,
`rsa-4096`. Asymmetric types store the private key (base64 PKCS#8) and expose the public half.

## Add your phone as a device

The phone is a browser tab that becomes a real device:

1. On the laptop: `ce-secrets pair-url` prints/QRs a link carrying the vault namespace.
2. On the phone: open it → it generates a device key (kept in IndexedDB) and shows a pairing code.
3. On the laptop: `ce-secrets device approve <code>`.

Now the phone can read the secrets you allow — e.g. ce-cast's publish key flows to it with no paste.

## Grant an app access

An app reads a secret only when an enrolled device grants it. A grant is a signed, expiring
authorization (issuer device, audience, abilities, expiry — the shape of a `@ce-net/cap`
capability, so it can converge with that later):

```bash
ce-secrets grant ce-cast-relay --read youtube-key,kick-key --expires 30d
# prints a token; the app calls vault.verifyGrant(token, 'ce-cast-relay', 'read', 'youtube-key')
ce-secrets grants                 # list
ce-secrets revoke-grant <id>      # revoke (deletes the grant record)
```

`verifyGrant` proves the grant was issued by a device enrolled in THIS vault and isn't
revoked/expired — the authorization decision. (Today reading the ciphertext still needs the
master key, so grants gate the policy/audit layer; per-secret key-wrapping that makes a grant
*cryptographically* unable to exceed its scope is the next step.)

## Node SDK

```js
import { openVault } from 'ce-secrets';

const vault = await openVault();                 // node-id namespace, Keychain device key
await vault.gen('stripe-key', { type: 'token' });
const key = await vault.get('stripe-key');       // SDK callers may read the value
await vault.use(['stripe-key'], async (env) => { /* env.STRIPE_KEY is set */ });
const { token } = await vault.grant('billing-worker', { read: ['stripe-key'], expires: '7d' });
```

On a server (no Keychain), set `CE_SECRETS_KEYSTORE=file` so the device key persists to
`~/.ce/secrets/device.json` (0600). Enroll the server with `ce-secrets pair` + approve it.

## Browser SDK

```js
import { Vault } from 'ce-secrets/client';
const v = await Vault.open({ namespace: 'vault-<prefix>' });   // or auto-derive from the app URL
if (!(await v.enrolled())) { const code = await v.pair('my phone'); /* show code to approve */ }
const key = await v.get('some-secret');
```

Device key lives in IndexedDB + localStorage (durable across iOS tab closes). This is the same
core ce-cast uses to pull its publish key without a paste.

## Standalone app

A full management UI (secrets, devices, pairing, grants) deploys as its own CE app:

```bash
npm run app:deploy        # -> https://vault-<prefix>.ce-net.com
```

Open it on any device, pair it once (`ce-secrets device approve <code>`), and manage the vault
from the browser. Same vault as the CLI.
