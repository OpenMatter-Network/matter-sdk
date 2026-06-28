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
  binds `(secret_id, subset, block_hash)` (and `valid_until` on the Ethereum path), so a
  recorded request can't be re-aimed at another secret or replayed past its freshness
  window.
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

- **Your signing key never enters the SDK.** The primary API takes a `Signer` interface;
  the SDK gives it canonical bytes and receives a signature. Keys can stay in an HSM,
  cloud KMS, hardware wallet, or remote signer.
- **Recovered plaintext is zeroized.** It is returned in a buffer that wipes itself on
  drop and refuses to print its contents (`Debug`/`Display` are redacted).
- **Nothing secret is logged.** The SDK follows a quiet-success / loud-typed-failure
  policy; secret material is never part of any log line, error message, or panic.
- **Inputs are validated at the boundary.** Wrong-length ids, oversized envelopes, and
  malformed hex are rejected with precise typed errors rather than silently coerced.

## Local key helpers

For examples and tests, the SDK ships helpers that load a signer from a raw seed (e.g.
`Signer::from_seed_insecure_dev_only`). They:

- carry `insecure`/`dev_only` in the name,
- emit a runtime warning,
- and are intended to be absent from production builds.

A CI check fails the build if a production target depends on them. **Do not use them
outside development.** See [`docs/secure-signing.md`](docs/secure-signing.md) for the
HSM/KMS integration patterns you should use instead.

## Supported versions

During early access, only the latest `0.x` release receives security fixes.
