# Language parity

MatterSDK ships one cryptographic core (`crates/matter-vault-core`, wrapping
`matter-crypto`) behind per-language shells. This table tracks how far each binding
has progressed. "Crypto surface" = the pure core functions (encrypt, signing payload,
Lagrange, proof verify, open). "Orchestration" = committee HTTP client, quorum/retry,
the `Signer` abstraction, and call builders.

| Capability | Rust | TypeScript | Python | Go |
|---|:--:|:--:|:--:|:--:|
| `encrypt` (seal) | ✅ | ✅ | ✅ | ✅ |
| `signingPayload` | ✅ | ✅ | ✅ | ✅ |
| `lagrangeFor` | ✅ | ✅ | ✅ | ✅ |
| `verifyPlaintextProof` | ✅ | ✅ | ✅ | ✅ |
| `openSecret` (verify+aggregate+open) | ✅ | ✅ | ✅ | ✅ |
| Committee HTTP client | ✅ | ✅ | ✅ | ✅ |
| Quorum orchestration (`decrypt`) | ✅ | ✅ | ✅ | ✅ |
| `Signer` abstraction | ✅ | ✅ | ✅ | ✅ |
| Call builders (store/rotate/grant) | ✅ | ✅ | ✅ | ✅ |
| Cross-language conformance vectors | ✅ | ✅ | ✅ | ✅ |
| **Live testnet e2e** (store→gas→decrypt) | ✅ | ✅ | ✅ | ✅ |

✅ implemented & tested. All four bindings now have the full online stack and have
each been verified **end-to-end against the public testnet** — seal → `secrets.storeSecret`
→ read back → threshold-decrypt → round-trip — and each re-decrypts the Rust "golden"
sample (`examples/golden.json`), proving the committee accepts every binding's sr25519
signature and the crypto agrees byte-for-byte.

Live e2e harnesses: [`examples/rust-e2e`](../examples/rust-e2e) ·
[`examples/e2e`](../examples/e2e) (TypeScript) · [`examples/python-e2e`](../examples/python-e2e) ·
[`examples/go-e2e`](../examples/go-e2e). Each reads `MATTER_RPC_URL` (defaults to testnet)
and `MATTER_SIGNER_SEED` (a funded sr25519 account).

## How conformance is guaranteed

The Rust core emits fixtures (`testvectors/*.json`); every binding replays them and
must match byte-for-byte. Rust, TypeScript, Python, and Go all pass today. This is the
mechanism that lets the bindings diverge in *ergonomics* while never diverging in
*cryptography*. Regenerate after any core change:

```bash
cargo test -p matter-vault-core --test roundtrip -- --ignored
```

## Notes & remaining work

**Python / Go online layer.** Python adds a pure-Python shell over the PyO3 crypto
(`substrate-interface` for the chain, stdlib `urllib` for the committee). Go adds the
shell over cgo, with two new C-ABI exports (`mv_verify_plaintext_proof`, `mv_open_secret`)
and a `go-substrate-rpc-client` chain client. Go's `store` hand-assembles the signed
extrinsic because the chain's `CheckMetadataHash` / `WeightReclaim` signed extensions
aren't covered by the library's default signer.

**Ethereum (EIP-712) signer.** Still the one gap: only the Substrate sr25519 signer path
is implemented across bindings; the wire types already carry the Ethereum fields. Porting
the dashboard's EIP-712 typed-data builder is the remaining work.

**Pre-existing: Rust in-process tests/demo vs. the sibling `matter-crypto`.** The Rust
integration tests (`matter-vault-core` `roundtrip`, `matter-vault` `decrypt`) and the
offline `examples/rust` demo compute *real* partials in-process by calling `matter-crypto`
directly, and currently do **not** compile against the checked-out `../matter-crypto`
(its API moved ahead — functions gained arguments and a return type became `Option<…>`).
This predates and is independent of the SDK work above: the libraries, all bindings, and
all four live e2e paths build and run. It also blocks the `roundtrip` regen command above
until those call sites are realigned to the current `matter-crypto` signatures.
