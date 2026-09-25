# Secure signing & secret handling

You decide where your signing key lives. Recovered secrets never reach logs.

| Posture | The key lives | Use when |
|---|---|---|
| **Bring your own signer** | in your HSM, cloud KMS, wallet, or remote signing service — never in the SDK's address space | production, and anywhere a key compromise would be expensive. **Recommended.** |
| **`apiKey`** | in your process, inside a hardened container the SDK provides | CI jobs, agents, ephemeral workers, single-file scripts — anywhere a client has to be built from one string |

Both are first-class constructors. Pick by where you can keep the key.

## The seam: signatures, not keys

The SDK produces canonical bytes; your signer turns them into a signature.

```
SDK  ──"sign these exact bytes"──►  your signer (HSM / KMS / wallet / remote / apiKey)
SDK  ◄────── signature ────────────
```

The bytes come from the shared core, so every binding signs exactly what the committee
verifies.

## Which trait do I implement?

| | You provide | The SDK derives | Implement it when |
|---|---|---|---|
| `KeySigner` | an account id and `sign(bytes)` | `/partial-decrypt` auth **and** extrinsic signatures | almost always — an HSM/KMS adapter is two methods |
| `Signer` | the finished auth fields for one request | nothing | you own the framing, e.g. the Ethereum/EIP-712 path, which has no 32-byte substrate account id and signs structured typed data |

- **Rust:** implement the three methods and pass the signer to
  `MatterClient::connect_with_signer` in an `Arc`. `partial_decrypt_auth` does the SCALE
  `MultiSignature` framing. This example is compiled by
  [`tests/guide_examples.rs`](../crates/matter-sdk/tests/guide_examples.rs):

```rust
use std::sync::Arc;

use matter_sdk::chain::{MatterClient, MatterConfig, Network};
use matter_sdk::{AccountId, KeyError, KeyScheme, KeySigner};

/// An HSM-backed signer: the key never leaves the device.
struct HsmSigner {
    public_key: [u8; 32],
    session: HsmSession, // your PKCS#11 or KMS client
}

impl KeySigner for HsmSigner {
    fn scheme(&self) -> KeyScheme {
        KeyScheme::Sr25519
    }

    fn account_id(&self) -> AccountId {
        AccountId(self.public_key)
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], KeyError> {
        self.session.sign_sr25519(message)
    }
}

async fn connect(signer: HsmSigner) -> matter_sdk::Result<MatterClient> {
    let config = MatterConfig::for_network(Network::Testnet);
    MatterClient::connect_with_signer(config, Arc::new(signer)).await
}
```

- **TypeScript:** the chain client takes a plain `{ accountId, sign }` object
  (`MatterClient.connectWithSigner`). A committee decrypt takes a `Signer`: wrap the same
  pair with `keySigner({ accountId, sign })`, or use `substrateSigner(accountId, sign)`.
  `sign` may be async.
- **Go:** `ConnectWithSigner` takes an `ExtrinsicSigner` (account id plus
  `SignExtrinsic`).
- **Python:** takes an in-process keypair (`connect_with_keypair`); the
  key-never-in-process posture is not yet reachable from Python.

`sign` may fail. In Rust it is synchronous, so a signer doing network I/O should block;
this keeps the trait object-safe, so read-only, `apiKey`, and HSM clients are one type.

## Patterns by key location

| Key lives in | How to wire it |
|---|---|
| Cloud KMS (AWS/GCP/Azure) | `sign` calls the KMS sign API. The KMS must support the curve; for sr25519, use a signing service or a KMS-sealed seed loaded into an enclave. |
| HSM (PKCS#11) | `sign` calls `C_Sign`. The key is non-exportable. |
| Hardware / browser wallet | `sign` triggers the wallet prompt (e.g. `eth_signTypedData_v4` for the Ethereum path, or a Substrate extension). |
| Remote signer service | `sign` makes an authenticated RPC to your signer; the key never reaches the app host. |

Your callback produces only the 64-byte sr25519 signature. The SDK frames it as a SCALE
`MultiSignature` (`0x01 ‖ sig`) with a 32-byte `AccountId`.

## The `apiKey` path

An OpenMatter API key is an sr25519 secret in one of three encodings: a `0x` 32-byte
mini-secret, a BIP39 mnemonic, or a SURI with derivation junctions, optionally prefixed
with its scheme (`sr25519:…`). `testvectors/api_keys.json` pins all three across bindings.

```
MATTER_API_KEY=0xfac7…479e   # never in argv, never in source
```

### What you are trading

An `apiKey` is a private key your process holds. Anything that can read the process (a
core dump, a debugger, a malicious transitive dependency, a crash-reporter heap snapshot,
`root` reading `/proc`) can read it, and whoever holds it can act with it until you revoke
it. A KMS- or HSM-backed signer gives a compromised process *use* of the key only while
it holds the process, never *possession*. That is why bring-your-own-signer is the
recommendation.

A leak is bounded by the key's `ScopeSet` (see [Scoped keys](#scoped-keys)): a key scoped
`deployments:w` cannot move a token, touch staking, vote, read a secret, or mint another
key. Revocation is one extrinsic and takes effect on the next request.

`apiKey` exists so workloads that must build a client from one string get a hardened
container instead of hand-rolling a signer with no zeroization and a `Debug` or `toJSON`
that leaks the key. It is a supported path, not a blessed default.

### The guardrails

Each row is a property of the type in all four bindings:

| Guardrail | What it does |
|---|---|
| **Zeroized** | The mini-secret and every intermediate derivation live in zeroizing buffers and wipe on drop. No hex or SURI copy of the seed is left in freed heap. |
| **Redacted** | No formatting path prints the key, including from inside a struct, slice, or map: `toString`, `repr`, `String()`, `%v`, and `%+v` render `ApiKey(sr25519, 0x…, <redacted>)`, and Rust's `Debug` renders the struct form with `material: "<redacted>"`. |
| **Non-serializable** | No `Serialize` in Rust, no pickle/copy in Python. Go's `MarshalJSON` *errors* rather than emitting a placeholder. TypeScript's `toJSON` yields only the redacted display string, so `JSON.stringify` never sees the key. |
| **No secret accessor** | No method returns the key bytes; the only outputs are the public account id and signatures. In TypeScript and Go the material never leaves Rust memory. |
| **Not clonable** | Rust's `ApiKey` is not `Clone`; share one with `Arc`. One key, one place to wipe. |
| **Errors never echo the key** | A rejection names *what* was wrong, never any part of the input. Upstream parser errors are never forwarded, because they can disclose characters of the secret and their offsets. |
| **Testnet by default, mainnet by consent** | A *signing* client refuses mainnet without `MATTER_CONFIRM=yes` or `confirm_mainnet`, checked against what the endpoint actually serves. An accidental production submit takes two mistakes. |
| **No implicit dev account** | A phrase-less URI like `//Alice` is **rejected**; most SURI parsers substitute the public development phrase, which would turn an unset variable into a globally-controlled signer. |

Guardrails constrain accidents, not attackers. None help once the process is compromised.

### Operating an apiKey safely

1. **Scope it narrowly.** Read and Write are independent bits: a deployment agent wants
   `deployments:w`, not `deployments:rw`.
2. **Rotate it** with `keys.authorize` for the new key and `keys.revoke` for the old. No
   re-encryption: ciphertext is bound to the committee's joint key, not yours. A key
   holding `secrets:w` can `grantAccess` **to itself**, and those grants **survive
   revocation**: revoke, sweep the key's `User` grants over the member's secrets, then
   rotate.
3. **Treat it as a bearer credential.** It can leak by screenshot, paste, a committed
   `.env`, or a CI job printing its environment. Rotate on suspicion, not on proof.
4. **One key per workload.** A leak of a shared key forces revoking it for every workload
   that uses it.
5. **Read it from the environment or a secret manager, never argv**, to keep it out of
   shell history and `ps` output.

## Scoped keys

Requires runtime spec ≥ 322. A key is a raw sr25519 keypair registered by the **member
it acts for**, as a `pallet_proxy` definition of type `Scoped(ScopeSet)` on that
member's account. Every call is dispatched as `proxy.proxy(member, null, call)` and runs
**as the member**: ownership and role checks evaluate against them, gas is paid by their
billing org or by them, and the runtime admits the call only if the key's set covers it.

- **The key's own account has no authority and no balance.** A direct call from it is
  refused for want of fees, so the SDK checks scopes locally and names the missing one.
- **The member is accountable for the key.** `deployments:w` commits their balance to
  compute settlement; `organization:w` is Admin-equivalent. There is no per-key spend cap
  on chain.
- **Of the Read bits, only `secrets:r` is enforced on chain.** `SecretsApi_is_authorized`
  answers for a key as for its member, so a key with `secrets:r` needs no per-secret grant
  to decrypt. Other Read bits are advisory until the serving service enforces them.

The client logs the resolved principal and scopes at connect; see
[Keys and scopes](client-guide.md#keys-and-scopes) for the accessors and for minting and
revoking keys.

Legacy project-tied keys (`orgs().authorize_secrets_agent`) keep working. To migrate:
revoke the legacy key, mint a member-tied one.

## Dev-only local keys

- Rust: `Sr25519Signer::from_seed_insecure_dev_only(&seed)` (raw 32-byte seed) or
  `Sr25519Signer::from_uri_insecure_dev_only(uri)` (`0x`-hex seed, BIP39 mnemonic, or SURI)

These take raw material from an ordinary, non-zeroizing buffer and give none of the
`apiKey` guarantees. They exist for tests, doctests, and offline demos, emit a runtime
warning, and a CI check fails any release target that depends on them. **If a key will
live in your process, put it in an `apiKey`.**

## Secret hygiene rules

1. **A signing key is the highest-value secret in the system.** Prefer a signer you own;
   for an `apiKey`, follow [Operating an apiKey safely](#operating-an-apikey-safely).
2. **Recovered plaintext is sensitive.** Rust returns a zeroizing `Plaintext` that wipes
   on drop and redacts its `Debug`. TypeScript, Python, and Go wipe the core's copy and
   return a mutable buffer: keep it short-lived, don't copy it, and call `wipe`
   (`mattersdk.Wipe`, `matter_sdk.wipe`) when done.
3. **Never log secrets.** The SDK never logs plaintext, keys, or signatures. Don't add
   logging that does.
4. **Use the AAD registry.** Seal and store with the same `Aad` tag; a mismatch is a
   silent decrypt failure.
5. **Freshness and recipient are enforced.** The request binds a recent `block_hash`
   (and, on the Ethereum path, `valid_until`) plus the responding node's `dkg_index`, so
   a captured request can't be replayed at another secret, another node, or after its
   window. The SDK signs once per node.

## Threat boundaries

See [`SECURITY.md`](../SECURITY.md) for the full threat model. In one line: a stolen
ciphertext or a single compromised committee node reveals nothing; a quorum of colluding
nodes, or a stolen signer, does. Pick `t`/`n` and protect your signer accordingly.
