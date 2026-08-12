# Security Policy

MatterVault is a tool for protecting secrets. We hold its own security to a high bar.

## Reporting a vulnerability

Email **security@openmatter.network** with details and, if possible, a reproduction.
Please do **not** open a public issue for a suspected vulnerability. We aim to
acknowledge within 3 business days. Coordinated disclosure is appreciated.

## Threat model

What MatterVault protects, and against whom:

- **A stolen ciphertext is useless.** The on-chain `EncryptedSecret` envelope reveals
  nothing without a `t`-of-`n` committee quorum. Anyone can read the chain.
- **No single committee node can decrypt.** Each node holds only a Shamir share; a node
  (or anyone who compromises one) computes a partial decryption that is useless on its
  own. You need `t` cooperating nodes.
- **A captured `/partial-decrypt` request can't be replayed elsewhere.** The signature
  binds `(secret_id, subset, block_hash, recipient_node)` (and `valid_until` on the
  Ethereum path), so a recorded request can't be re-aimed at another secret, **replayed
  to a different committee node in the same subset**, or replayed past its freshness
  window. The requester signs once per node; each node verifies the signature against its
  own `dkg_index`. This is what stops one in-subset node from replaying a user's request
  to its peers and harvesting a full quorum of partials alone (MV-C1).
- **Only authorized accounts can request decryption.** Each node checks the resolved
  signer against the on-chain authorization list before serving a partial.

What it does **not** protect against, by design:

- A quorum of **colluding committee nodes** (≥ `t`) can recover secrets they are asked to
  decrypt. The committee's trust is distributed, not eliminated — choose `t`/`n` and node
  operators accordingly.
- Plaintext **after** you decrypt it. Once `decrypt()` returns the secret to your process,
  protecting it (memory, logs, downstream services) is your responsibility. The SDK
  returns a zeroizing buffer and never logs it; don't copy it somewhere unprotected.
- A compromised **signer**. If your signing key is stolen, an attacker can request
  decryption of every secret you're authorized for. Keep keys in an HSM/KMS — see below.

## How the SDK handles secrets

- **You choose where your signing key lives; the SDK does not decide for you.** The
  recommended posture is a `KeySigner` you implement: the SDK gives it canonical bytes
  and receives a signature, so the key stays in an HSM, cloud KMS, hardware wallet, or
  remote signer and never enters the SDK's address space. The SDK also supports an
  `apiKey` it holds in process, for CI jobs and agents that must build a client from one
  string; that container is zeroizing, redacted, non-serializable, and mainnet-gated,
  but anything that can read the process can read the key. The trade is spelled out in
  [`docs/secure-signing.md`](docs/secure-signing.md#what-you-are-trading).
- **Recovered plaintext is zeroized.** It is returned in a buffer that wipes itself on
  drop and refuses to print its contents (`Debug`/`Display` are redacted).
- **Nothing secret is logged.** The SDK follows a quiet-success / loud-typed-failure
  policy; secret material is never part of any log line, error message, or panic.
- **Inputs are validated at the boundary.** Wrong-length ids, oversized envelopes, and
  malformed hex are rejected with precise typed errors rather than silently coerced.

## Key-holding paths

Two exist, and they are not equivalent.

**`ApiKey` — supported, hardened.** Parses the encodings the OpenMatter dashboard mints
and holds the key in process behind real guarantees: zeroizing buffers, a redacted
`Debug`/`toString`/`%v`, no serialization of key material, no accessor for the material, and a refusal to
connect a signing client to mainnet without explicit confirmation. It also rejects a
phrase-less URI such as `//Alice`, which most SURI parsers silently resolve to the public
well-known development phrase. Use it when a key must live in the process anyway.

**`*_insecure_dev_only` — unsupported.** For examples and tests, the SDK ships helpers
that load a signer from raw material the caller already holds (e.g.
`Sr25519Signer::from_seed_insecure_dev_only`). They:

- carry `insecure`/`dev_only` in the name,
- emit a runtime warning,
- and are intended to be absent from production builds.

The name is about custody, not location: these give a key none of the container
guarantees above. If a key is going to live in your process, it should live in an
`ApiKey`.

A CI check fails the build if they are referenced anywhere in shipped library code —
only their definition site, tests, and the examples may use them. **Do not use them
outside development.** See [`docs/secure-signing.md`](docs/secure-signing.md) for the
HSM/KMS integration patterns you should use instead.

## Supported versions

During early access, only the latest `0.x` release receives security fixes.
