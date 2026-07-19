# LOW and INFORMATIONAL findings

> Scope tags as in `high.md`. Each cites exact `file:line`.

## LOW

### MV-L1 — Recovered secret copied into non-zeroizing host buffers; FFI free path doesn't wipe **[ffi / bindings]**
The core holds plaintext in a `Zeroizing` buffer (`crates/matter-vault-core/src/types.rs:32-55`),
but every binding copies it out un-wiped: FFI `mv_open_secret` → `into_buf(pt.expose().to_vec())`
(`crates/matter-vault-ffi/src/lib.rs:336`), and `mv_free` (`:67-72`) drops **without** zeroizing,
so the secret persists in the freed Rust allocation; wasm `Uint8Array::from(...)`
(`bindings/wasm/src/lib.rs:170`); Python `PyBytes::new` (`bindings/python/src/lib.rs:106`); Go
`C.GoBytes` into GC heap (`packages/go/mattervault/mattervault.go:207`). The host-language copies
are an unavoidable, documented residual. **The Rust-owned FFI copy is fixable**: zeroize the
returned buffer in `mv_free` (use the `zeroize` crate — a naive `memset` is dead-store-eliminated),
or add a dedicated `mv_secret_free` that wipes and have Go use it for the `mv_open_secret` output.
Lens: *zeroize-audit*.

### MV-L2 — No input size caps on untrusted decode (DoS, mitigated) **[core]**
`open_secret` / `verify_plaintext_proof` pass arbitrary `&[u8]` into bincode 1.3.3
(`crates/matter-vault-core/src/decrypt.rs:40-45,80-86,122-150`); the on-chain `MAX_ENCRYPTED_SECRET_*`
bounds are enforced only on **encode** (`encrypt.rs:91-93`), never on decode. **Mitigated in
practice** (empirically verified): serde 1.0.228's `size_hint::cautious` caps bincode
preallocation at ~1 MB and the matter-crypto ring types reject any length != `CYCLOTOMIC_DEGREE`,
so the classic "tiny blob → giant allocation" DoS does not fire — residual is only wasted CPU on
oversized input. Fix for symmetry / early reject: cap each decode input at its `MAX_*` bound
before bincode. Lens: *rule-of-robustness*.

### MV-L3 — Version tag binds version but not artifact type; bincode allows trailing bytes **[core / config]**
`matter_kgc_config::wire::decode_tagged` correctly rejects untagged blobs (`BlobError::Untagged`)
and version mismatches (`VersionMismatch`) — that binding is present and sufficient
(`../matter-kgc/config-contract/src/protocol.rs:66-92`). Residual: the tag carries a **version
only, no type discriminant**, and the same `MKGC/v2` tag is reused for the ZKPoPlaintext proof and
the DKG round-1 bundle, so cross-type confusion is caught only downstream by structure mismatch +
proof verify, not by the tag. Also `bincode::deserialize` uses the legacy `AllowTrailing` default,
so a correctly-tagged proof with appended bytes still decodes (non-canonical/malleable encoding).
Fix: add a 1-byte artifact-type discriminant to the tag; use `bincode::options().reject_trailing_bytes()`.
Lens: *rule-of-robustness* (be strict in what you accept).

### MV-L4 — `commit_bytes` lacks a domain-separation tag **[matter-crypto, adjacent]**
`../matter-crypto/crypto/src/commitment/mod.rs:36-42` computes `SHA256(data ‖ nonce)` with no DST,
inconsistent with the crate's otherwise-thorough DST discipline. Not exploitable today (the
32-byte nonce is fixed-length so the split is unambiguous, and every other SHA-256 sink is
domain-separated), but add a `b"matter-crypto/commit/v1"` tag + length-prefix as defense-in-depth.

### MV-L5 — Shell never asserts distinct node indices / `len == t` before aggregation **[shell]**
`crates/matter-vault/src/committee.rs:86-88` selects the subset but never dedups `node.index`. A
repeated index in `req.nodes` (chain-data or caller error) would put a duplicate interpolation
point into `subset`, making `lagrange_for` mathematically invalid and double-counting a node
toward `t`. Not attacker-reachable under the "chain is trusted" model (so Low), but a one-line
`debug_assert`/check (distinct, sorted, `len == t`) is cheap insurance. Lens: *design-by-contract*.

### MV-L6 — `crypto_protocol_version` never checked client-side **[shell]**
`crates/matter-vault/src/transport.rs:24` and the response field are ignored; a
transcript-incompatible/malicious node's partial flows straight into `verify_aggregate_open`.
Safety then rests entirely on the core binding the version into the proof transcript; worst case
is an aggregation-failure DoS, not a leak. Missed defense-in-depth check.

### MV-L7 — FFI null-ptr + nonzero-len treated as empty (inconsistent) **[ffi]**
`mv_signing_payload` (`crates/matter-vault-ffi/src/lib.rs:129-133`) and `mv_lagrange_for`
(`:152-156`) silently treat a null `subset` with `subset_len > 0` as empty, rather than rejecting
— inconsistent with `as_slice`'s null+nonzero → `None`/`INVALID_ARG` behavior (`:98-104`).
Memory-safe, but a *rule-of-least-surprise* footgun; also `#![allow(clippy::missing_safety_doc)]`
(`:21`) means no `# Safety` sections document the caller's `(ptr,len)` obligations. Fix: make
null+nonzero-len a consistent `MV_ERR_INVALID_ARG`; add `# Safety` docs. Lens: *sharp-edges*.

### MV-L8 — Go `goBytesAndFree` truncates `size_t` → `C.int` **[bindings]**
`packages/go/mattervault/mattervault.go:62` casts `buf.len` to `C.int`; a >2 GB output would
overflow. Only `SigningPayload` has attacker-influenced output size (via a giant `subset`); not
corruption, at worst a Go-side panic. Low.

### MV-L9 — Go `secret_id` is `uint64`, cannot address ids ≥ 2⁶⁴ **[bindings]**
`packages/go/mattervault/committee.go:20` (and chain encoders) model `secret_id` as `uint64`,
while the protocol/TS/Python use the full `u128`. Self-consistent (no endianness bug), but a
**functional/parity** gap: the Go binding cannot reach high secret ids. Fix: widen to a 16-byte /
`big.Int` id type. Low/functional.

### MV-L10 — EIP-712 cross-pallet separation relies solely on the struct `typeHash` **[proto, adjacent]**
The KGC `PartialDecrypt` EIP-712 path reuses the generic `"Matter Network"` domain `name`
(`../matter-kgc/config-contract/src/eip712.rs:27`) — the same name as the arbitrary-call
meta-transaction pallet — although matter-node's own convention says to use a distinct domain
`name` per flow (`../matter-node/common/src/eth_signing.rs:67-69`). Separation between message
types therefore rests *only* on the distinct struct `typeHash`. Cryptographically sound today
(distinct type strings ⇒ distinct digests; no feasible collision) so **not exploitable**, but it
removes a deliberate redundant layer and is fragile to a future "Matter Network" message type.

### MV-L12 — No one-time-decryption cap + fresh per-call smudge (averaging considered; infeasible) **[matter-crypto / service, adjacent]**
The smudge is sampled fresh from `thread_rng` on every partial decryption
(`../matter-crypto/crypto/src/zkp/partial_decrypt.rs:102-107`), and nothing caps how many times a
capsule is decrypted (the service applies no nonce/rate-limit on `/partial-decrypt`). The code
comment (`secret.rs:131-133`) scopes security to "one honest decryption … not adaptive queries."
Repeated decryption yields `d_i^{(k)} = c₁·λ·SK_i + e'^{(k)}` with fresh noise — so an attacker
could *try* to average the noise away. **Independently quantified and found infeasible:** with the
production parameters (N≈4098, q≈2¹⁰⁹, smudge ≈2⁸⁰), exact ring-inversion recovery needs the
residual driven to ~0 (any nonzero residual amplifies mod-q to full scale), i.e. Q ≈ 2¹⁶²
queries; BDD/lattice recovery in dimension 4098 is impractical until the error is near-zero. So
this is **Low** on its own — but it contradicts the code's own stated assumption and removes the
defense-in-depth that would otherwise blunt MV-H4's per-proof leak. Fix: enforce a bounded
decryption count per `(capsule, epoch)`, or derive the smudge deterministically per
`(ciphertext, share)` so repetition adds no independent samples.

### MV-L13 — Variable-time secret-dependent operations re-enter scope under the wasm/co-located model **[matter-crypto, adjacent]**
`matter-crypto` documents timing as out of scope under a "no co-located adversary" assumption
(`../matter-crypto/crypto/src/lib.rs:24-37`). The SDK compiles the core to `wasm32` and runs it in a
browser, where co-located adversarial JS / microarchitectural timing exists — re-including the
channel. Concrete secret-dependent variable-time sites: μ-dependent rounding in `aggregate_core`
(`shr_vartime`/residue subtraction, `../matter-crypto/crypto/src/threshold/aggregate.rs:144-159`) on
the client; the Fiat–Shamir rejection-loop iteration count and `pow_usize_vartime` on the node
(`../matter-crypto/crypto/src/zkp/partial_decrypt.rs:167-252`, `zkp/mod.rs:355`). Disclaimed by the
crate, but the SDK's wasm target is exactly the excluded scenario — surface it to downstream users
and consider constant-time treatment for the wasm build. Lens: *constant-time-analysis*.

### MV-L11 — Request freshness comment says "finalized" but the lookup accepts any known block **[service, adjacent]**
`../matter-kgc/service/src/server.rs:624` describes a "recent **finalized** block", but
`ChainClient::block_number` resolves any block the node knows by hash (`chain.rs:396-401`), not
only canonical/finalized ones. An attacker could anchor on a recent non-finalized/fork block whose
number is within the 10-block window. Stays inside the bounded window (does not escalate beyond
MV-C1's replay), so Low.

---

## INFORMATIONAL

### MV-I1 — No supply-chain gate in CI; aging/duplicated dependencies **[deps / CI]**
No `deny.toml` / `audit.toml`, no `cargo-deny`/`cargo-audit` step in either `.github/` workflow,
while every untrusted committee/chain blob is bincode-deserialized. Notable pins (root
`Cargo.lock`): `bincode 1.3.3` (the 1.x line is effectively unmaintained), a duplicate `sha2 0.9.9`
dragged in via the `subxt-signer` sr25519 path, and an unusual `rand 0.8.6` pin (the public 0.8
line tops out at 0.8.5 — confirm provenance). No *known-critical* RUSTSEC at these versions, but
the structural gap should be closed: add `cargo-deny` + `cargo-audit` to CI; track a bincode 2.x
migration. Lens: *security-awareness*, *broken-windows*.

### MV-I2 — CI gating excludes the binding crates **[CI]**
The gating `rust` job runs `cargo build --workspace`, which **excludes** `bindings/wasm` and
`bindings/python` (workspace-excluded, `Cargo.toml:34`); the wasm step builds only
`-p matter-vault-core`, not the `matter-vault-wasm` crate; and the `python`/`go` jobs are
`continue-on-error: true`. A break confined to a binding crate can therefore ship green. (The
compile break that prompted this audit was in test targets, which `cargo test --workspace` *does*
gate — so CI was correctly red for it.) Fix: build/test the binding crates in a gating job. Lens:
*broken-windows*, *tracer-bullet* (the gate should exercise every shipped artifact).

### MV-I3 — Version-pin comment drift (FIXED in this change) **[Cargo.toml]**
The workspace `matter-crypto` "Release form" comment pinned `tag = "v0.6.0"` while the local
sibling crate had advanced to `0.8.0` — the drift that made the compile break confusing. Corrected
to `v0.8.0` in `Cargo.toml:48-50` as part of this work. (matter-kgc's `v0.7.1` comment was already
accurate.) Lens: *broken-windows*, *DRY* (one source of truth for the version).

### MV-I4 — e2e demos print recovered plaintext to stdout **[examples]**
`examples/go-e2e/main.go:157`, `examples/e2e/run.ts:336`, `examples/python-e2e/run.py:114` print
the recovered secret as explicit round-trip verification. Fine for a demo, but worth a one-line
"do not copy into production logging" note.
