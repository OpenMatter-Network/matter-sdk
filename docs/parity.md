# Language parity

MatterSDK ships two pure Rust cores — `crates/matter-vault-core` (cryptography, wrapping
`matter-crypto`) and `crates/matter-vault-key` (API-key ingestion and signing) — behind
per-language shells. This table tracks how far each binding has progressed.

- **Crypto surface** — the pure core functions (encrypt, signing payload, Lagrange,
  proof verify, open).
- **Orchestration** — committee HTTP client, quorum/retry, the signer abstraction, call
  builders.
- **Chain client** — API-key ingestion plus the generic metadata-driven surface (`tx`,
  `query`, `runtimeApi`, `constant`) that reaches every pallet the runtime exposes, and
  the curated typed façades layered on it.

| Capability | Rust | TypeScript | Python | Go |
|---|:--:|:--:|:--:|:--:|
| `encrypt` (seal) | ✅ | ✅ | ✅ | ✅ |
| `signingPayload` | ✅ | ✅ | ✅ | ✅ |
| `lagrangeFor` | ✅ | ✅ | ✅ | ✅ |
| `verifyPlaintextProof` | ✅ | ✅ | ✅ | ✅ |
| `openSecret` (verify+aggregate+open) | ✅ | ✅ | ✅ | ✅ |
| Committee HTTP client | ✅ | ✅ | ✅ | ✅ |
| Quorum orchestration (`decrypt`) | ✅ | ✅ | ✅ | ✅ |
| `Signer` / `KeySigner` abstraction | ✅ | ✅ | ✅ | ✅ |
| Call builders (store/rotate/grant) | ✅ | ✅ | ✅ | ✅ |
| Cross-language conformance vectors | ✅ | ✅ | ✅ | ✅ |
| **Live testnet e2e** (store→gas→decrypt) | ✅ | ✅ | ✅ | ✅ |
| `ApiKey` ingestion (`api_keys.json`) | ✅ | ✅ | ✅ | ✅ |
| Signed-extrinsic assembly | ✅ | ✅ | ✅ | ✅ |
| Generic `tx` / `query` / `runtimeApi` | ✅ | ✅ | ✅ | ✅ |
| `MatterClient` + mainnet guard | ✅ | ✅ | ✅ | ✅ |
| Curated typed façades (`facade_calls.json`) | ✅ | ✅ | ✅ | ✅ |
| `ScopeSet` + local scope table (`scope_bits.json`, `required_scopes.json`) | ✅ | ✅ | ✅ | ✅ |
| Delegated-key mode resolution at connect | ✅ | ✅ | ✅ | ✅ |
| `proxy.proxy` wrapping of writes | ✅ | ✅ | ✅ | ✅ |
| `ProxyExecuted` unwrapping (a wrapped failure is not a success) | ✅ | ✅ | ✅ | ✅ |
| `keys` façade (mint / revoke / lookup) | ✅ | ✅ | ✅ | ✅ |
| Pre-322 detection from metadata, never from a failed call | ✅ | ✅ | ✅ | ✅ |
| Pool rejection / `Proxy.NotProxy` → `KeyRevoked` / `Unsponsored` | ✅ | ✅ | ✅ | ✅ |
| Grant re-read after a refused write (a re-scope names the fresh set) | ✅ | ✅ | ✅ | ✅ |
| Argument-sensitive scope rows read the argument | ✅ | ✅ | ✅ | ✅ |
| Diagnostics through the host's logger, not stdout/stderr | ✅ | ✅ | ✅ | ✅ |
| **Live client example** (apiKey → read → dry-run submit) | ✅ | ✅ | ✅ | ✅ |

✅ implemented & tested. **All four bindings drive a member-tied scoped key**: same
generic surface, same six façades, same guards, matching constructors, and one shared
scope contract. One asymmetry remains deliberate and is described below — Python's
bring-your-own-key constructor.

**How that parity is enforced, not just claimed.** Three fixtures, all emitted by Rust
and replayed by every binding:

- `api_keys.json` — one derivation. Rust natively, TypeScript through wasm, Python
  through PyO3, Go through the C ABI, so the four `examples/client-*` programs print
  the *same account id* for the same key.
- `facade_calls.json` — one façade surface, checked **both ways** in TypeScript,
  Python, and Go: a fixture row without a method fails, and a method without a row
  fails. Rust has no reflection, so its emitter test pins the same list instead —
  which is also why its two typed grant conveniences (`grant_to_user`,
  `grant_to_deployment`, thin wrappers over `grant`) sit outside the fixture.
- `scope_bits.json` and `required_scopes.json` — the `ScopeSet` bit layout and what
  each of the 155 calls of the ten scoped pallets requires. Replayed both ways, like
  the façade fixture. They are fixtures rather than shared code on purpose: a scope set
  is not cryptography, so it does not belong behind `matter-vault-ffi`, and the two
  `arg_sensitive` rows must read call arguments *before* anything is encoded, which
  could not cross that boundary without shipping the whole argument tree. Porting the
  table found a real divergence the moment TypeScript replayed it — TS had conflated
  "argument absent" with "argument is `None`", which quietly inverted the fail-safe
  direction for one row.
- the live-metadata test — every curated `(pallet, call)` must exist on chain
  (`cargo test -p matter-vault --features chain --test live_chain -- --ignored`).

**Where the languages still differ, deliberately.** Rust's chain client is behind a
default-off `chain` cargo feature and TypeScript's is a separate package
(`@openmatter-network/matter-client`) — the same opt-out expressed two ways, because a
cargo feature that is off is genuinely not compiled while npm installs any declared
dependency. Python's is the optional `[sdk]` extra. Go's is always present, since cgo
already binds the core.

**How each binding wraps.** Rust nests through subxt's own `DefaultPayload::into_value`,
which exists for exactly this; TypeScript hands `api.tx.proxy.proxy` the inner call
object; Python nests one `compose_call` inside another; Go passes the inner `types.Call`
as an argument, which works because `types.Call` has no custom `Encode` and the generic
reflection encoder emits `pallet ++ call ++ args` — correct, but correct *by accident*,
so `scopes_test.go` pins the bytes rather than trusting it.

**One trap per binding, worth knowing.** substrate-interface's `receipt.is_success`
reports **true** when the wrapped call failed, because it only special-cases
`System.ExtrinsicSuccess`/`ExtrinsicFailed`; Python therefore scans
`triggered_events` itself. @polkadot's `result.dispatchError` likewise sees only the
*outer* extrinsic. And Python must resolve the mode from `connect_with_keypair` as well
as `connect_with_api_key`, since that is its only bring-your-own-key path.

**Go used to be the exception here, and no longer is.** `Tx` stays non-blocking by
design — it returns a transaction hash — but `TxAndWait` follows the extrinsic to
finalization and raises on a wrapped failure like the other three. It locates the
extrinsic by matching the exact bytes it submitted, which sidesteps decoding a signed
extrinsic whose extension list this binding hand-assembles.

The decode underneath it changed too, and the reason is worth recording. `ProxyFailure`
previously read GSRPC's *rendered* event field and looked for `"Err"`. That registry
discards variant names, so `Ok(())` and `Err(Other)` both arrive as a bare byte 0 and
neither renders as either string: the check reported "no failure" for every input,
including real ones. It is now decoded from the SCALE bytes, where the order of a
`Result<(), DispatchError>` is the wire contract rather than a rendering detail.

Go also reads a call's arguments now. `Tx` receives an already-encoded `types.Call`, so
the two argument-sensitive rows decode it against metadata rather than judging by name
— narrowing **only** when the field decodes to exactly `Option::None`, and taking the
wider set for anything unreadable. That is still the fail-safe direction, and it is
asserted rather than assumed.

**Signed-extrinsic assembly** is ✅ everywhere but by different means. Rust uses subxt,
TypeScript `@polkadot/api`, and Python `substrate-interface`; only Go hand-assembles, so
its layout is pinned by synthetic-metadata unit tests rather than a cross-language vector
(a vector would have exactly one consumer). Go's assembler walks the extensions the
runtime *declares* and **refuses to sign** one it cannot account for, rather than
hardcoding the 2026 layout.

The crypto and orchestration rows are unchanged: all four bindings have the full online
stack and have
each been verified **end-to-end against the public testnet** — seal → `secrets.storeSecret`
→ read back → threshold-decrypt → round-trip — and each re-decrypts the Rust "golden"
sample (`examples/golden.json`), proving the committee accepts every binding's sr25519
signature and the crypto agrees byte-for-byte.

Live e2e harnesses: [`examples/rust-e2e`](../examples/rust-e2e) ·
[`examples/e2e`](../examples/e2e) (TypeScript) · [`examples/python-e2e`](../examples/python-e2e) ·
[`examples/go-e2e`](../examples/go-e2e). Each reads `MATTER_RPC_URL` (defaults to testnet)
and `MATTER_SIGNER_SEED` (a funded sr25519 account, as a `0x`-hex seed or a BIP39 mnemonic).

## How conformance is guaranteed

The Rust core emits fixtures (`testvectors/*.json`); every binding replays them and
must match byte-for-byte. Rust, TypeScript, Python, and Go all pass today. This is the
mechanism that lets the bindings diverge in *ergonomics* while never diverging in
*cryptography*. Regenerate after any core change:

```bash
cargo test -p matter-vault-core --test roundtrip -- --ignored
cargo test -p matter-vault --test seed_formats -- --ignored
cargo test -p matter-vault-key --test parse -- --ignored
cargo test -p matter-vault --features chain --test facade_calls -- --ignored
```

The same mechanism now covers two non-cryptographic contracts:

- **`api_keys.json`** — what parses, what is rejected, and which account each key
  derives. Two cases carry most of the weight: a `0x…//hard` SURI must derive a
  *different* account than `0x…` (a binding that drops junctions silently returns the
  **root** account), and a phrase-less `//Alice` must be **rejected** (most SURI parsers
  substitute the public development phrase, so an unset environment variable would
  otherwise mint a globally-known signer).
- **`facade_calls.json`** — the curated façade surface: which `(façade, method)` pairs
  exist and which `(pallet, call)` each maps to. Replayed **both ways** in TypeScript,
  Python, and Go, so a fixture row without an implementation fails *and* an
  implementation without a row fails; Rust pins the emitter list instead.

## Notes & remaining work

**Python / Go online layer.** Python adds a pure-Python shell over the PyO3 core
(`substrate-interface` for the chain, stdlib `urllib` for the committee). Go adds the
shell over cgo, with the C-ABI exports for proof verification, secret opening, and API-key
ingestion. Go's submit path hand-assembles the signed extrinsic because the chain's
`CheckMetadataHash` / `WeightReclaim` signed extensions aren't covered by the library's
default signer; it now does so from the extension list the metadata *declares*, and
refuses to sign an extension it cannot account for.

**Python's second derivation path.** `substrate-interface` needs its own `Keypair` to
build a signed extrinsic, and `create_from_uri` cannot derive a **hex** phrase with
derivation junctions at all — it feeds the phrase to bip39. `ApiKeySigner` therefore
adapts an `ApiKey` into something keypair-shaped that delegates to the shared core, so
there is one derivation and nothing to diverge. `ChainClient.keypair_from_seed` remains
for callers who need a real `Keypair`, and now raises rather than silently dropping
junctions.

**`Secrets::recover` is Rust-only.** It composes the chain reads a committee decrypt
needs — the secret's payload and its stored epoch, and `KgcApi`'s committee at that epoch —
with `recover_secret`, returning the zeroizing plaintext. Its consumer is QuantumGuard's
`zkfw-policyd`, a Rust binary; the other bindings keep the primitive
(`open_secret`/`recover_secret`) and the reads, and grow the composition when a
non-Rust caller needs it. Not in `facade_calls.json` because it submits nothing.

**Remaining.** The Ethereum/EIP-712 path is the one signer gap, and it is reserved
rather than missing: only the Substrate sr25519 path is implemented across bindings,
but `ApiKey` carries a scheme discriminant (a `secp256k1:` key reports "unsupported
scheme" instead of failing to parse) and the wire types already carry the Ethereum
fields — so the remaining work, porting the dashboard's EIP-712 typed-data builder,
will not be a breaking change. `pallet-eth-signing` and `pallet-staking-gateway` are
the on-chain counterparts, deliberately left out of the staking façade until that
scheme lands.

Mainnet's genesis hash is also still unpinned — its RPC endpoint did not answer when
this was written — so the mainnet guard falls back to the token symbol. Pin
`MAINNET_GENESIS` from `chain_getBlockHash(0)` when the endpoint is reachable.

Python's remote-signer seam is the other gap: its bring-your-own-key path takes an
in-process keypair (`connect_with_keypair`) rather than a `connect_with_signer`
callback, so the key-never-in-process posture is not yet reachable from Python.
