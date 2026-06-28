# MatterSDK

**Client SDKs for [MatterVault](https://openmatter.network) — threshold secret management on the matter-kgc committee.**

MatterVault lets you **seal a secret** (API keys, database URLs, env vars) under a
distributed committee's joint public key, store the ciphertext on-chain, and later
**recover it** only with the cooperation of a `t`-of-`n` quorum of committee nodes.
No single party — not even the committee operators — can decrypt your secret alone.

> Status: **early access.** All four bindings — Rust, TypeScript, Python, and Go —
> work end-to-end and have each been verified against the live testnet. See
> [Language support](#language-support).

```
                   ┌──────────────────────────────────────────────┐
   your app  ──►   │  MatterSDK (Rust │ TypeScript │ Python │ Go)  │
                   └───────────────┬───────────────┬──────────────┘
            encrypt() locally      │               │   decrypt(): collect t partials,
            (seal under joint pk)   │               │   verify + aggregate + AEAD-open
                   ┌────────────────▼──┐      ┌──────▼───────────────────┐
                   │ matter chain      │      │ matter-kgc committee      │
                   │ (store ciphertext)│      │ POST /partial-decrypt ×t  │
                   └───────────────────┘      └──────────────────────────┘
```

## Why a committee?

A normal secrets manager has a master key — steal it and you have every secret.
MatterVault has **no master key**. The decryption key exists only as Shamir shares
split across `n` independent committee nodes; recovering a secret needs `t` of them
to each compute a *partial decryption* that your client aggregates locally. The
cryptography is RLWE/BGV threshold decryption with zero-knowledge proofs at every
step (implemented in [`matter-crypto`](https://github.com/openmatter-network/matter-crypto));
this SDK is the safe, ergonomic way to use it.

## Architecture: one core, four shells

The novel cryptography lives in **one** audited Rust crate and is shared by every
language binding through FFI — it is never re-implemented per language (that would
be four chances to get lattice crypto subtly wrong).

| Layer | What it is | Where |
|---|---|---|
| **Core** | Pure, non-networked crypto + wire contract: `encrypt`, `open_secret`, signing payload, Lagrange, proof verify. | `crates/matter-vault-core` |
| **Rust SDK** | Committee HTTP client, quorum + retry, `Signer`, call builders. | `crates/matter-vault` |
| **wasm binding** | `wasm-bindgen` over the core; drives the TS package. | `bindings/wasm` |
| **TypeScript SDK** | Ergonomic TS over wasm + the orchestration shell. | `packages/typescript` |
| **Python / Go** | PyO3 + cgo bindings over the same core. | `bindings/python`, `packages/go` |

Networking, the quorum loop, and **signing** are idiomatic per language; only the
cryptography is shared. A [conformance vector suite](testvectors/) generated from
the core guarantees every binding agrees byte-for-byte. See [`docs/architecture.md`](docs/architecture.md).

## What the SDK does and does not do

- **Does:** encrypt/seal, orchestrate threshold decryption (health-probe → quorum →
  signed `/partial-decrypt` → verify + aggregate + open), and build the *call data*
  for the `store` / `rotate` / `grant` extrinsics.
- **Does not:** submit transactions or hold your keys. You submit the built call with
  your own Substrate client (subxt / @polkadot / py-substrate / GSRPC), and you sign
  with **your** signer (HSM, KMS, wallet, or a local dev key). See
  [Secure signing](#secure-signing).

## Language support

| Language | Encrypt | Decrypt | Call builders | Status |
|---|---|---|---|---|
| Rust (`matter-vault`) | ✅ | ✅ | ✅ | working |
| TypeScript (`@openmatter-network/matter-vault`) | ✅ | ✅ | ✅ | working |
| Python (`matter-vault`) | ✅ | ✅ | ✅ | working |
| Go (`mattervault`) | ✅ | ✅ | ✅ | working |

Per-language guides: [Rust](examples/rust/README.md) ·
[TypeScript](packages/typescript/README.md) · [Python](bindings/python/README.md) ·
[Go](packages/go/mattervault/README.md). Status detail: [`docs/parity.md`](docs/parity.md).

## Secure signing

Your private key never enters the SDK. Every operation that needs a signature takes a
`Signer` you provide; the SDK hands it the exact canonical bytes to sign and gets back
a signature. This means an HSM, a cloud KMS, a hardware wallet, or a remote signing
service all plug in the same way. Recovered plaintext is returned in a zeroizing buffer
and is never logged.

Read **[`SECURITY.md`](SECURITY.md)** and **[`docs/secure-signing.md`](docs/secure-signing.md)**
before integrating. There are local "load a key from a seed" helpers for examples and
tests — they are named to shame (`..._insecure_dev_only`) and must never ship.

## Security FAQ

Short, practical answers for engineers integrating MatterVault. Each has a **Read
deeper** you can expand.

**Q: Who can actually decrypt my secret?**

Only a **quorum** — `t` of the `n` committee nodes, cooperating. No single node can,
the operators can't, and neither can any group smaller than `t`. Below the threshold
your data is mathematically unrecoverable: there is no master key anywhere to steal.

<details><summary>Read deeper</summary>

The decryption key never exists in one place — it's split into shares, one per node.
Recovering a secret needs `t` nodes to each return a verified *partial decryption*,
which your client checks and combines locally. See [Why a committee?](#why-a-committee).
</details>

**Q: The committee isn't fixed — can it grow, shrink, or swap members?**

Yes. It's a **dynamic `t`-of-`n` group**: nodes can be added or removed and the
threshold can change over time. You don't track who's in it — the SDK reads the live
committee from the chain for you at decrypt time.

**Q: If the committee changes, do I have to re-encrypt my data?**

**No — and this is the part most systems get wrong.** When membership rotates, the
**public key stays the same**. Ciphertext you already stored keeps working unchanged.

```ts
// Encrypt once, today.
const sealed = encrypt(jointPk, epoch, secret, Aad.EnvV1);
await /* store the ciphertext on-chain */ storeSecret(...);

// …months later the committee has rotated members several times…
const plaintext = await decrypt(transport, signer, { /* … */ }); // still just works
```

<details><summary>Read deeper: how the key survives rotation</summary>

The public key is tied to the underlying secret, **not** to which nodes currently
hold shares. A rotation reshares that same secret to the new committee — refreshing
every share without ever rebuilding the full key — so the public key is unchanged.
Each stored ciphertext is also stamped with the **epoch** it was sealed under, so data
encrypted before a rotation stays decryptable after it.
</details>

**Q: How does rotating members make things *more* secure, not less?**

Rotation runs a **proactive refresh**: members periodically replace their shares with
brand-new ones and hand fresh shares to the incoming committee — without the full key
ever being assembled. Old shares become useless. So an attacker who breaks into nodes
slowly, one at a time, is reset at every rotation: they'd have to compromise `t`
members *within a single rotation window* to learn anything. Steal `t-1` shares over a
year and you still have nothing.

**Q: Is this quantum-safe? How does it line up with NIST's post-quantum standards?**

MatterVault's encryption is **lattice-based** — the same hard-problem family NIST chose
for the post-quantum era (NIST's ML-KEM / FIPS 203 is a close relative). It is designed
to target the **~128-bit, post-quantum security range** NIST aligns to, which means it
resists **"Harvest-Now-Decrypt-Later"**: data an adversary records today cannot be
unsealed by a future quantum computer.

<details><summary>Read deeper</summary>

Unlike a key-exchange primitive such as ML-KEM, MatterVault uses a lattice scheme that
*also* supports threshold decryption — so the post-quantum guarantee and the "no single
key" guarantee come from the same construction. MatterVault is early-access; see
[`SECURITY.md`](SECURITY.md) for the current security posture and assumptions before
relying on it for production secrets.
</details>

**Q: How is this different from a KMS, an HSM, or just encrypting with a key?**

| | Key in your app | KMS / HSM | MatterVault |
|---|---|---|---|
| Where the decryption key lives | one place | one box / one provider | split across `n` nodes; never assembled |
| Single point of compromise | yes | yes | **no** — need `t` nodes at once |
| Who sees plaintext at decrypt time | whoever holds the key | the KMS / HSM | **no one** — nodes return verified partials; your client combines them |
| Survives key-holder rotation without re-encrypting | n/a | usually re-key | **yes** — the public key is stable across membership changes |
| Quantum-safe | depends on cipher | usually classical (RSA / ECC) | **yes** — lattice / post-quantum |

The short version: a KMS still has *a key in a place*. MatterVault has no such place —
and even during decryption, no node ever sees your secret.

## Building from source

This repo currently builds against sibling checkouts of the private core crates.
Clone them next to `matter-sdk`:

```
your-code/
  matter-sdk/        ← this repo
  matter-crypto/     ← github.com/openmatter-network/matter-crypto
  matter-kgc/        ← github.com/openmatter-network/matter-kgc
```

```bash
cargo test -p matter-vault-core   # crypto core + roundtrip
cargo test -p matter-vault        # Rust SDK
```

(At release these become pinned git-tag / registry dependencies; see the top of
`Cargo.toml`.)

### Live end-to-end test

Each binding has a live harness that runs the full path — encrypt →
`secrets.storeSecret` → read back → threshold-decrypt — against a real node using a
**funded** account you provide. This is the one path the offline tests can't cover
(that the committee accepts the SDK's signature on-chain):
[Rust](examples/rust-e2e) · [TypeScript](examples/e2e) ([README](examples/e2e/README.md)) ·
[Python](examples/python-e2e) · [Go](examples/go-e2e). They share env vars —
`MATTER_RPC_URL` (defaults to testnet) and `MATTER_SIGNER_SEED` (a funded sr25519 seed;
`TEST_KEY` also accepted). A no-gas [`preflight.ts`](examples/e2e/preflight.ts) checks
funding + committee health first.

## License

Apache-2.0 © Open Matter. See [`LICENSE`](LICENSE).
