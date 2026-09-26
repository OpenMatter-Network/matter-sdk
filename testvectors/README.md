# Cross-language conformance vectors

These fixtures are emitted by Rust and replayed by every binding. Bindings may differ in
ergonomics, never in bytes: a binding that disagrees with a vector has a bug.

| File | What it pins | Emitted by | Replayed by |
|---|---|---|---|
| `signing_payload.json` | The exact bytes a requester signs for `/partial-decrypt`, including the per-node `recipient_index` | `matter-sdk-core` `roundtrip` | TS core, Python, Go |
| `lagrange.json` | The bincode Lagrange coefficient for a node over a subset | `matter-sdk-core` `roundtrip` | TS core, Python, Go |
| `open_secret.json` | A sealed secret plus a real committee quorum, each partial labelled with its node's `point`. `open_secret` must recover `expected_plaintext_hex`. The core derives every Lagrange coefficient from the points. | `matter-sdk-core` `roundtrip` | Rust (`open_contract`), TS core, Python, Go; also used by `examples/typescript` |
| `seed_formats.json` | One sr25519 secret in both encodings (`0x` mini-secret and BIP39 mnemonic) that must derive `account_id_hex`. The dashboard that mints API keys replays it too. | `matter-sdk` `seed_formats` | TS core, Python, Go |
| `api_keys.json` | The full API-key ingestion contract. `valid` keys must parse to `account_id_hex`, and `invalid` keys must be rejected with the named error kind. | `matter-sdk-key` `parse` | Rust, TS core, Python, Go |
| `facade_calls.json` | The curated façade surface: each `(façade, method)` pair and the `(pallet, call)` or runtime API it maps to, with ordered argument names | `matter-sdk` `facade_calls` | TS, Python, Go, each checked **both ways** |
| `scope_bits.json` | The `ScopeSet` wire contract: bit = `scope * 2 + access`, as a bare `u32`. Also an `is_superset` truth table in which Read and Write are independent. | `matter-sdk` `scope_vectors` | TS, Python, Go |
| `required_scopes.json` | What every call of the ten scoped pallets requires of a delegated key. `required: null` marks a call no key may ever make. | `matter-sdk` `scope_vectors` | TS, Python, Go |
| `networks.json` | The default RPC endpoint per network name (`null` means no default). **Maintained by hand**, not emitted, and it must point at a host that serves public RPC. | — | Rust, TS, Python, Go default-endpoint tests |
| `spec330_metadata.scale` | Runtime metadata, **V15**: what subxt and @polkadot load. Only this version carries runtime-API declarations. | fetched from the chain | Rust `chain` tests, `required_scopes.json` generation |
| `spec330_metadata_v14.scale` | The same runtime as **V14**: what `state_getMetadata` returns, and the only version GSRPC and substrate-interface can decode | fetched from the chain | Go scope tests |

Two cases in `api_keys.json` matter most:

- **Junctions must be applied.** `0x…//hard` derives a *different* account from `0x…`.
  Routing a hex SURI to a raw-seed constructor would silently derive the root account.
- **A SURI with no phrase must be rejected.** Most SURI parsers resolve `//Alice` against
  the public development phrase, so an unset environment variable would become a signer
  anyone controls.

`api_keys.json` is kept separate from `seed_formats.json` because the latter is a
positive-only vector shared with the dashboard.

Each binding checks `facade_calls.json` in both directions: a fixture row with no method
fails, and a method with no row fails. Rust has no reflection, so its emitter test pins the
list, and `fixture_args_match_the_runtime_fields` checks every row's argument names and
arity against the metadata. The same test crate asserts that the guides document every
façade method.

`required_scopes.json` is replayed in one direction only. Each binding classifies every
row, but a call missing from the fixture fails nothing. Completeness comes from
generation instead: CI re-runs the emitter and fails on any diff, and the nightly
`runtime-drift` workflow checks the live chains. The two `arg_sensitive` rows pin only
their name-derived half; each binding tests the argument-dependent part itself.

## Encoding

- **Binary fields are bare lowercase hex:** two lowercase hex digits per byte (`[0-9a-f]`),
  no `0x` prefix, no separators or whitespace. The one exception is the `key` field of
  `api_keys.json`, which holds the literal string as pasted, `0x` prefix and whitespace
  included.
- **`secret_id` is a decimal string** (`u128`).

`open_secret.json` is about 4 MB. That is the real wire size of the RLWE capsules and
zero-knowledge proofs.

## Regenerate

After any change to the cryptographic core, a key format, a façade or the scope table,
regenerate the vectors and re-run every binding's conformance suite:

```bash
cargo test -p matter-sdk-core --test roundtrip -- --ignored              # signing_payload, lagrange, open_secret
cargo test -p matter-sdk --test seed_formats -- --ignored                # seed_formats
cargo test -p matter-sdk-key --test parse -- --ignored                   # api_keys
cargo test -p matter-sdk --features chain --test facade_calls -- --ignored   # facade_calls
cargo test -p matter-sdk --features chain --test scope_vectors -- --ignored  # scope_bits, required_scopes
```

`required_scopes.json` is generated from `spec330_metadata.scale`. When the runtime adds
a call, regenerate both metadata blobs first. The recipe is in
`crates/matter-sdk/src/chain/scopes_table.rs`.
