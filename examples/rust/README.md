# Rust: seal and recover, offline

```bash
cargo run -p matter-sdk-example
```

The demo seals a secret and prints the `Secrets.store_secret` call you would submit.
It then recovers the secret from a **throwaway in-process committee**, so it needs no
network and no chain.

The calls `encrypt`, `StoreSecret`, `Signer` and `decrypt` are exactly what your app
makes. Only `LocalCommittee`, at the bottom of `src/main.rs`, is demo scaffolding.

## Moving to production

1. Replace `LocalCommittee` with `ReqwestTransport::new()`.
2. Replace `Sr25519Signer::from_seed_insecure_dev_only` with a signer backed by your HSM
   or KMS. See [Secure signing](../../docs/secure-signing.md).
3. Let the chain client do the rest. With the `chain` feature,
   `client.secrets().store(...)` submits the call, and `client.secrets().recover(id, aad)`
   reads the committee and runs the decrypt. See [Threshold secrets](../../docs/secrets.md).
