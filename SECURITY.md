# Security Policy

## Reporting a vulnerability

Email **security@openmatter.network** with details and, if possible, a reproduction. Do
**not** open a public issue. We aim to acknowledge within 3 business days.

## Threat model

What MatterSDK protects:

- **A stolen ciphertext is useless.** The on-chain `EncryptedSecret` envelope reveals
  nothing without a `t`-of-`n` committee quorum. Anyone can read the chain.
- **No single committee node can decrypt.** Each node holds only a Shamir share; its
  partial decryption is useless on its own.
- **A captured `/partial-decrypt` request can't be replayed elsewhere.** The signature
  binds `(secret_id, subset, block_hash, recipient_node)` (and `valid_until` on the
  Ethereum path), and each node verifies it against its own `dkg_index`. A recorded
  request can't be re-aimed at another secret, replayed past its freshness window, or
  replayed by one in-subset node to its peers to harvest a quorum.
- **An EIP-712 meta-transaction signature is bound to the exact call it authorises.**
- **Only authorized accounts can request decryption.** Each node checks the resolved
  signer against the on-chain authorization list before serving a partial.

What it does **not** protect against, by design:

- A quorum of **colluding committee nodes** (≥ `t`) can recover secrets they are asked to
  decrypt. Choose `t`/`n` and node operators accordingly.
- Plaintext **after** `decrypt()` returns it. The SDK wipes its own copies, never logs
  it, and hands you a buffer you can wipe; protecting it from then on is your job.
- A compromised **signer**. A stolen signing key can request decryption of every secret
  it is authorized for. Keep keys in an HSM/KMS.

## How the SDK handles secrets

- **Recovered plaintext is zeroized.** Rust returns a buffer that wipes itself on drop
  and redacts `Debug`/`Display`. Go, Python, and TypeScript wipe the core's copy before
  it is freed and return a mutable buffer with a `wipe` helper (`mattersdk.Wipe`,
  `matter_sdk.wipe`, `wipe`) for the host language's copy.
- **Nothing secret is logged.** Secret material is never part of any log line, error
  message, panic, or `Debug` output.
- **Inputs are validated at the boundary.** Wrong-length ids, oversized envelopes, and
  malformed hex are rejected with typed errors, never coerced. Everything decoded from
  the chain or a committee node is size-bounded and must decode exactly, with no trailing
  bytes. The core derives every Lagrange coefficient itself and rejects a repeated or
  zero node index.
- **The C ABI fails closed.** No panic unwinds across it (`MSDK_ERR_INTERNAL`),
  out-parameters are cleared on every error path, `msdk_free` wipes buffers, and a null
  pointer with a non-zero length is an error.
- **No single node can deny or monopolise a decrypt.** Each decrypt picks its quorum at
  random from the healthy nodes, drops a node that fails, speaks another protocol
  version, or serves a stray epoch, and names each dropped node in the error. Every
  committee request has a deadline and a response-size cap.

## Key-holding paths

**`KeySigner` — recommended.** You implement it; the SDK hands it canonical bytes and
receives a signature, so the key stays in an HSM, cloud KMS, hardware wallet, or remote
signer and never enters the SDK's address space. Patterns:
[`docs/secure-signing.md`](docs/secure-signing.md).

**`ApiKey` — supported, hardened.** For CI jobs and agents that build a client from one
string. It parses the encodings the OpenMatter dashboard mints and holds the key in a
zeroizing buffer (a seed never passes through an un-zeroized temporary) with redacted
`Debug`/`toString`/`%v`, no serialization, and no accessor for the material. It refuses
to connect a signing client to mainnet without explicit confirmation, and rejects a phrase-less URI such as `//Alice`, which most SURI parsers
resolve to the public development phrase. Anything that can read the process can read
the key ([the trade-off](docs/secure-signing.md#what-you-are-trading)).

**`*_insecure_dev_only` — unsupported.** Helpers such as
`Sr25519Signer::from_seed_insecure_dev_only` load a signer from raw material with none of
the `ApiKey` guarantees. They emit a runtime warning, and a CI check fails the build if
shipped library code references them; only their definition site, tests, and examples
may. **Do not use them outside development.**

## Supported versions

Security fixes go to the latest release of the current major version, across every
binding at once (one tag releases them all). Earlier majors are not maintained. See
[`CHANGELOG.md`](CHANGELOG.md).
