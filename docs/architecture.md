# Architecture

The cryptography exists once.

## One core, many shells

<p align="center">
  <img src="assets/core-shells.svg" alt="One pure core, crates/matter-sdk-core with crates/matter-sdk-key, is shared through four bindings: native Rust, wasm-bindgen to TypeScript, a C ABI to Go, and PyO3 to Python. Every shell adds the same idiomatic committee client, quorum, Signer and chain client" width="900">
</p>

The **core** (`crates/matter-sdk-core`) does only the cryptography that must never
diverge: `encrypt`, `verifyPlaintextProof`, `lagrangeFor`, the request `signingPayload`,
and `openSecret` (verify → aggregate → AEAD-open). It is pure and synchronous (no
sockets, no async, no key handling), so it compiles unchanged to native, `wasm32`, and a
C ABI. API-key parsing and signing (`crates/matter-sdk-key`) is shared the same way,
because key derivation is a cross-language contract too.

The **shells** add the non-cryptographic, per-ecosystem parts: the committee HTTP
client, random quorum selection + retry, the `Signer` abstraction, the chain client, and
the call builders.

Re-porting RLWE/BGV lattice cryptography per language would mean four chances to get
constant-time behaviour, rejection sampling, or transcript binding wrong. Never do it;
bindings call the core.

## Cross-language conformance

The Rust core emits fixtures into [`testvectors/`](../testvectors/README.md) (signing
payloads, Lagrange coefficients, a full sealed secret with real committee partials) and
every binding replays them. The same mechanism pins key derivation, the façade surface,
the scope table, and the default endpoints.

## Data flow

<p align="center">
  <img src="assets/data-flow.svg" alt="SEAL offline with encrypt(), STORE through the SDK chain client, DECRYPT through the SDK: health-probe, pick a random t-of-n quorum, sign per node, POST /partial-decrypt to t nodes, then verify, aggregate and open locally to plaintext" width="900">
</p>

The chain client submits extrinsics and reads the committee state decrypt needs
(`joint_pk`, `shared_a`, roster, per-node share commitments, threshold). The call
builders (`StoreSecret`/`RotateSecret`/`GrantAccess`/`RevokeAccess`/`DeleteSecret`)
remain for callers who submit with their own Substrate client.

## Key rotation

The committee is a **dynamic `t`-of-`n` group**: members can be added, removed, or
swapped and the threshold can change. Through **proactive resharing** the committee
periodically reshares the *same* secret to the next epoch, giving every node a new share
without reconstructing the full key.

<p align="center">
  <img src="assets/rotation-refresh.svg" alt="On rotation the committee reshares the same secret to the next epoch, refreshing every node's share without rebuilding the full key. The joint public key is unchanged so stored ciphertext still decrypts, while the old shares become useless" width="860">
</p>

The joint public key is tied to the secret, not to which nodes hold shares, so it is
**unchanged across rotations**. Each ciphertext is stamped with the **epoch** it was
sealed under and stays decryptable after a rotation; you never re-encrypt. The SDK reads
the live committee state from the chain at decrypt time. If a `threshold` of nodes report
a newer `served_epoch` mid-request, the client raises `SdkError::EpochRotated`; refetch
the state and retry (see [`committee.rs`](../crates/matter-sdk/src/committee.rs)).

> Committee key rotation is distinct from the `RotateSecret` call, which re-seals *your
> secret's value* under the current epoch (see [`calls.rs`](../crates/matter-sdk/src/calls.rs)).

### Surviving a compromised node

A reshare replaces every share, so **old shares become useless** once a rotation
completes. To recover anything an attacker must hold `t` valid shares at once, meaning
breach `t` nodes **within a single rotation window**. `t-1` shares stolen over a year
yield nothing.

<p align="center">
  <img src="assets/rotation-compromise.svg" alt="An attacker who compromises one node per rotation window never accumulates the t shares needed to decrypt: each rotation refreshes every share and makes previously stolen shares useless, so the usable-stolen-share count stays below the threshold" width="860">
</p>

## Crate / package map

| Path | Role |
|---|---|
| `crates/matter-sdk-core` | pure crypto + wire types + AAD registry; the source of truth |
| `crates/matter-sdk-key` | API-key ingestion + `KeySigner`; wasm-clean, one derivation for every binding |
| `crates/matter-sdk` | Rust SDK: `decrypt`, `Signer`, `calls`; `chain::MatterClient` + façades behind the `chain` feature |
| `crates/matter-sdk-ffi` | C ABI over the core (foundation for Go/cgo) |
| `bindings/wasm` | wasm-bindgen binding (drives the TS package) |
| `bindings/python` | PyO3 binding (`matter_sdk` extension) |
| `packages/typescript-core` | TS SDK over the wasm core + orchestration (zero runtime deps) |
| `packages/typescript` | TS chain client over `@polkadot/api` |
| `packages/go/mattersdk` | Go binding over the C ABI |
| `testvectors/` | conformance fixtures generated by the core |
| `examples/` | offline demos, `client-*` read-only clients, and live e2e harnesses in all four languages |
