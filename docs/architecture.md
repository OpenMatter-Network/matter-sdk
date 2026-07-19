# Architecture

MatterSDK is a polyglot SDK with a single rule: **the cryptography exists once.**

## One core, many shells

<p align="center">
  <img src="assets/core-shells.svg" alt="A single pure crypto core, crates/matter-vault-core, is shared through four bindings: native Rust, wasm-bindgen to TypeScript, a C ABI to Go, and PyO3 to Python. Every shell adds the same idiomatic committee client, quorum, Signer and call builders" width="900">
</p>

The **core** does only the cryptography that must never diverge: `encrypt`,
`verifyPlaintextProof`, `lagrangeFor`, the request `signingPayload`, and
`openSecret` (verify → aggregate → AEAD-open). It is pure and synchronous — no
sockets, no async, no key handling — so it compiles unchanged to native, `wasm32`,
and a C ABI.

The **shells** add what is genuinely idiomatic per ecosystem: the HTTP committee
client, quorum selection + retry, the bring-your-own-`Signer` abstraction, and the
on-chain call builders. This is ~300 lines of *non-cryptographic* glue — the same
split the underlying `matter-crypto`/wasm boundary already uses.

### Why not re-implement per language?

Re-porting novel RLWE/BGV lattice cryptography into Python, JS, and Go would be four
chances to get constant-time behaviour, rejection sampling, or transcript binding
subtly wrong — and a classic differential-environment hazard (the "reference in
tests, optimised in prod" trap). One audited implementation, shared by FFI, removes
that entire class of risk.

## Cross-language conformance

Because the bindings share the core, they must agree byte-for-byte. The Rust core
emits fixtures into [`testvectors/`](../testvectors); every binding replays them:

- `signing_payload.json` — the exact request bytes a signer signs.
- `lagrange.json` — the per-node Lagrange coefficient.
- `open_secret.json` — a full sealed secret + committee partials; each binding's
  `openSecret` must recover the known plaintext.

Rust, TypeScript, and Python pass these today (Go's test is written, gated on its
toolchain in CI). This is what lets ergonomics differ while cryptography cannot.

## Data flow

<p align="center">
  <img src="assets/data-flow.svg" alt="SEAL offline with encrypt(), STORE via your own Substrate client, DECRYPT through the SDK: health-probe, pick a t-of-n quorum, sign once, POST /partial-decrypt to t nodes, then verify, aggregate and open locally to plaintext" width="900">
</p>

The SDK owns the first and third columns. The middle column — submitting the
extrinsic and reading chain state (`joint_pk`, `shared_a`, committee roster, per-node
share commitments, threshold) — stays with your own Substrate client. The SDK gives
you ready-to-sign call arguments (`StoreSecret`/`RotateSecret`/`GrantAccess`) for it.

## Key rotation

The committee is a **dynamic `t`-of-`n` group**: members can be added, removed, or
swapped and the threshold can change over time. It keeps its key healthy through
**proactive resharing** — periodically the committee reshares the *same* secret to the
next epoch, handing every node a brand-new share without the full key ever being
reconstructed.

<p align="center">
  <img src="assets/rotation-refresh.svg" alt="On rotation the committee reshares the same secret to the next epoch, refreshing every node's share without rebuilding the full key. The joint public key is unchanged so stored ciphertext still decrypts, while the old shares become useless" width="860">
</p>

The joint public key is tied to the underlying secret, **not** to which nodes hold
shares, so it is **unchanged across rotations**. Each stored ciphertext is stamped with
the **epoch** it was sealed under, so a secret encrypted before a rotation stays
decryptable after it — you never re-encrypt. Resharing advances the committee's epoch;
the SDK reads the live committee state (`joint_pk`, `shared_a`, roster, per-node share
commitments, threshold) from the chain at decrypt time. If a `threshold` of nodes report
a newer `served_epoch` mid-request, the client raises `SdkError::EpochRotated` so the
caller refetches that state and retries — see
[`committee.rs`](../crates/matter-vault/src/committee.rs).

> This is committee-side **key** rotation. It is distinct from the `RotateSecret` call,
> which re-seals *your secret's value* in place under the current epoch — see
> [`calls.rs`](../crates/matter-vault/src/calls.rs).

### Surviving a compromised node

Because a reshare replaces every share, **old shares become useless** the moment a
rotation completes. An attacker who compromises nodes slowly — one at a time — is reset
at every rotation: to recover anything they must hold `t` valid shares *at once*, which
means breaching `t` nodes **within a single rotation window**. Stealing `t-1` shares
spread over a year yields nothing.

<p align="center">
  <img src="assets/rotation-compromise.svg" alt="An attacker who compromises one node per rotation window never accumulates the t shares needed to decrypt: each rotation refreshes every share and makes previously stolen shares useless, so the usable-stolen-share count stays below the threshold" width="860">
</p>

## Crate / package map

| Path | Role |
|---|---|
| `crates/matter-vault-core` | pure crypto + wire types + AAD registry; the source of truth |
| `crates/matter-vault` | Rust SDK: `CommitteeClient`, `decrypt`, `Signer`, `calls` |
| `crates/matter-vault-ffi` | C ABI over the core (foundation for Go/cgo) |
| `bindings/wasm` | wasm-bindgen binding (drives the TS package) |
| `bindings/python` | PyO3 binding (`matter_vault` extension) |
| `packages/typescript` | TS SDK over the wasm core + orchestration |
| `packages/go/mattervault` | Go binding over the C ABI |
| `testvectors/` | conformance fixtures generated by the core |
| `examples/` | runnable demos (Rust, TypeScript) |

See [`docs/parity.md`](parity.md) for per-language status and
[`docs/secure-signing.md`](secure-signing.md) for the signing/secret model.
