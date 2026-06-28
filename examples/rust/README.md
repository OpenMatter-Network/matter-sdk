# Rust example

A runnable, self-contained demo of the MatterVault Rust SDK.

```bash
cargo run -p matter-vault-example
```

It seals a secret, prints the `secrets.storeSecret` call you would submit, then
recovers the secret from a **throwaway in-process committee** — so it runs with no
network or live chain.

## What's real vs. demo

- **Real:** `encrypt`, `StoreSecret`, the `Signer` abstraction, and `decrypt` — the
  exact calls your app makes.
- **Demo only:** the `LocalCommittee` at the bottom of `src/main.rs`. In production the
  committee nodes run elsewhere; you reach them with `ReqwestTransport` and supply
  `joint_pk`, `shared_a`, the per-node `share_commitment`s, the threshold, and the node
  endpoints from chain via your own Substrate client.

## Going to production

1. Replace `LocalCommittee` with `ReqwestTransport::new()`.
2. Replace `Sr25519Signer::from_seed_insecure_dev_only` with a `Signer` backed by your
   HSM/KMS — see [`docs/secure-signing.md`](../../docs/secure-signing.md).
3. Fetch `joint_pk` / `shared_a` / nodes / commitments from chain, and submit the
   `StoreSecret` args with subxt.
