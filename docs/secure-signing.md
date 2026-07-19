# Secure signing & secret handling

MatterVault is built so that **your signing key never enters the SDK** and recovered
**secrets never leak into logs**. This page is the integration guide for keeping it
that way.

## The model: bring your own signer

Decryption requires a signature proving you're authorized for the secret. The SDK
never asks for your key — it asks for a *signer*: something that, given the canonical
payload bytes, returns a signature. The key stays wherever you keep it.

```
SDK  ──"sign these exact bytes"──►  your Signer (HSM / KMS / wallet / remote)
SDK  ◄────── signature ────────────  key never moves
```

- **Rust:** implement the `Signer` trait. `authorize(&SigningRequest)` receives the
  request and returns the auth fields.
- **TypeScript:** pass `substrateSigner(accountId, sign)`, where `sign(payload)` is
  your callback — a `@polkadot/keyring` pair, a browser wallet, or a KMS adapter.

The canonical bytes come from the core's `signingPayload`, so every binding signs
exactly what the committee verifies — no transcript drift.

## Patterns by key location

| Key lives in | How to wire it |
|---|---|
| Cloud KMS (AWS/GCP/Azure) | Implement `Signer`/`sign` to call the KMS sign API. KMS must support the curve; for sr25519, use a signing service or a KMS-sealed seed loaded into an enclave. |
| HSM (PKCS#11) | `sign` calls `C_Sign`. The key is non-exportable. |
| Hardware / browser wallet | `sign` triggers the wallet prompt (e.g. `eth_signTypedData_v4` for the Ethereum path, or a Substrate extension). |
| Remote signer service | `sign` makes an authenticated RPC to your signer; the key never reaches the app host. |

> The substrate auth path wraps an sr25519 signature as a SCALE `MultiSignature`
> (`0x01 ‖ sig`) and the account as a 32-byte `AccountId`. The SDK does that framing;
> your callback only produces the 64-byte sr25519 signature.

## Dev-only local keys

For examples and tests the SDK offers local helpers that load a key into memory:

- Rust: `Sr25519Signer::from_seed_insecure_dev_only(&seed)` (raw 32-byte seed) or
  `Sr25519Signer::from_uri_insecure_dev_only(uri)` (`0x`-hex seed, BIP39 mnemonic, or SURI)

They carry `insecure`/`dev_only` in the name and print a runtime warning. **Never use
them in production**, and keep them out of production builds. CI fails if a release
target depends on them.

## Secret hygiene rules

1. **Recovered plaintext is sensitive.** Rust returns it as a zeroizing `Plaintext`
   that wipes on drop and redacts its `Debug`. wasm/Python/Go return raw bytes (the
   runtime has no zeroizing buffer) — keep them short-lived, don't copy them around,
   and overwrite when done.
2. **Never log secrets.** The SDK never logs plaintext, keys, or signatures. Don't add
   logging that does. Follow quiet-success / loud-typed-failure.
3. **Use the AAD registry.** Seal and store with the same `Aad` tag; a mismatch is a
   silent decrypt failure. The enum makes a typo a compile error.
4. **Freshness and recipient are enforced.** The request binds a recent `block_hash`
   (and, on the Ethereum path, `valid_until`) plus the responding node's `dkg_index`, so
   a captured request can't be replayed at another secret, at a different committee node,
   or after its window. The SDK signs once per node — each node verifies against its own
   index (MV-C1).

## Threat boundaries

See [`SECURITY.md`](../SECURITY.md) for the full threat model. In one line: a stolen
ciphertext or a single compromised committee node reveals nothing; a quorum of
colluding nodes, or a stolen signer, does. Pick `t`/`n` and protect your signer
accordingly.
