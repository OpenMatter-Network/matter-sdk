# Rust example

```bash
cargo run -p matter-sdk-example
```

Seals a secret, prints the `secrets.storeSecret` call you would submit, then recovers
the secret from a **throwaway in-process committee**. No network or chain needed.

`encrypt`, `StoreSecret`, `Signer`, and `decrypt` are the exact calls your app makes.
Only `LocalCommittee` (bottom of `src/main.rs`) is demo scaffolding.

## Going to production

1. Replace `LocalCommittee` with `ReqwestTransport::new()`.
2. Replace `Sr25519Signer::from_seed_insecure_dev_only` with a `Signer` backed by your
   HSM/KMS — see [`docs/secure-signing.md`](../../docs/secure-signing.md).
3. Fetch `joint_pk`, `shared_a`, the threshold, and each node's endpoint and
   `share_commitment` from chain, and submit the `StoreSecret` args with subxt.
