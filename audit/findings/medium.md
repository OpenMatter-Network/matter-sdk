# MEDIUM severity findings

> Scope tags as in `high.md`. Each finding cites exact `file:line`.

---

## MV-M1 — `open_secret` trusts caller-supplied λ and commitment (unenforced security precondition) **[core]**

- **Location:** `crates/matter-vault-core/src/decrypt.rs:140-150` (decode), `:152-174`
  (passed to `verify_aggregate_open`); the `PartialInput` contract `crates/matter-vault-core/src/types.rs:71-80`.

### Description
`open_secret` decodes the per-partial `lambda` and `commitment` straight from caller bytes
(`decrypt.rs:147,146`) and feeds them into `matter_crypto::secret::verify_aggregate_open`. It
never recomputes λ from the subset, nor checks `commitment` against the trusted on-chain
Feldman commitment for the node's point. The contract comment (`:100-105`) and the
`PartialInput` docs assume the caller supplies trusted values, but the **core API does not
enforce it** — its security rests entirely on every caller doing the right thing.

### Impact / attack
A caller that (mistakenly) wired a committee node's **response-supplied** commitment or λ into
`open_secret` would let a single malicious node submit a self-consistent
`(λ_wrong / commitment_wrong, partial, proof)` that *verifies* yet corrupts the aggregate.
Because the ZKPoPartDec proof would still verify, the bad node is **not** flagged
`ProofRejected`, defeating the "identify the faulty node in one round" property — a stealthy,
unattributable denial of service. Confidentiality is **not** broken (Shamir secrecy + the
AEAD backstop mean a corrupted aggregate yields `OpenError::Aead`, never a wrong-but-accepted
plaintext). **All current callers are safe** — the Rust shell (`committee.rs:130-131`) and the
TS/Python/Go bindings all source `commitment` from the trusted on-chain
`share_commitment` and locally recompute λ via `lagrange_for` — so this is a latent
**sharp edge**, not an exploited bug. Severity would rise to High for any future binding that
trusts node-supplied values.

### Recommendation
Make the core enforce its own precondition: have `open_secret` take a trusted commitment
vector keyed by node point (and look up `g_i` by point), and recompute λ in-core from the
agreed subset rather than accepting `PartialInput.lambda`. Lens: *design-by-contract*,
*sharp-edges* ("the pit of success" — the safe call should be the only call), *crash-early*.

---

## MV-M2 — Deterministic lowest-index quorum selection amplifies single-node attacks **[shell]**

- **Location:** `crates/matter-vault/src/committee.rs:86-87`
  (`active.sort_by_key(|n| n.index); … take(req.threshold)`).

### Description
The decrypting subset is always the `t` lowest-index healthy nodes. A fixed malicious node at
a low index (e.g. index 1) is therefore in **nearly every** quorum for **every** secret any
user decrypts.

### Impact / attack
Not a cryptographic break by itself, but it is the amplifier that turns the Critical replay
(MV-C1) into reliable passive harvesting of *every* decrypted secret, and turns MV-H2 into a
permanent denial. Standalone severity Medium.

### Recommendation
Randomize subset selection per request (shuffle active nodes before `take(t)`) so no single
node is guaranteed inclusion. Lens: *rule-of-least-surprise* / threat-modeling (avoid
predictable victim selection).

---

## MV-M3 — sr25519 seed copied into un-zeroized `String` temporaries **[shell]**

- **Location:** `crates/matter-vault/src/signer.rs:101`
  (`SecretUri::from_str(&format!("0x{}", hex::encode(seed)))`).

### Description
`hex::encode(seed)` allocates a `String` holding the full 32-byte seed in hex, and `format!`
allocates a second — both plain `String`s dropped **without zeroization**, leaving the private
seed in freed heap until overwritten.

### Mitigating facts (verified)
The long-lived key is handled well: `SecretUri.phrase` is a zeroizing `SecretString`, and the
stored `subxt_signer::sr25519::Keypair` (schnorrkel) wipes its secret on drop
(`schnorrkel … impl Drop for Keypair`). No seed leak via `Debug` (none derived on
`Sr25519Signer`) or error messages (`Error::InvalidSeed` is a static string). The only gap is
the two transient hex `String`s.

### Impact / honest severity
This is the explicitly named `from_seed_insecure_dev_only` constructor (it prints a stderr
warning). But `Sr25519Signer` is a **public, production-exported** type and the crate doctest
uses it, so production misuse is plausible — were this a sanctioned production path it would be
High. As-is: Medium key-in-memory hygiene.

### Recommendation
Build the hex into a `Zeroizing<String>` (or feed seed bytes to a constructor that avoids the
hex round-trip) so the temporaries are wiped. Lens: *zeroize-audit*.

---

## MV-M4 — Panics can unwind across the C FFI boundary (no `catch_unwind`, no `panic = "abort"`) **[ffi]**

- **Location:** all `extern "C"` fns in `crates/matter-vault-ffi/src/lib.rs`; the only
  `[profile.release]` (`Cargo.toml:71-72`) sets `opt-level` only.

### Description
No `catch_unwind` exists anywhere, and no profile sets `panic = "abort"`. A panic inside the
core or `matter-crypto` would unwind toward the `extern "C"` frame — **undefined behavior by
the language contract** (on rustc 1.93 it is a defined process abort, but relying on that is
fragile; it also converts a recoverable error into an uncatchable process kill with no
conversion to `MV_ERR_CRYPTO`, and wipes no in-flight secret).

### Honest severity
**No currently-reachable panic was found** — the crypto core is hardened against the obvious
triggers: `PowerPoly`/`CrtPoly` deserialization enforces `CYCLOTOMIC_DEGREE`, the ZK verifiers
length-check their vectors and use `try_rejection_bound` for attacker-controlled `smudge_bits`,
`verify_and_aggregate` rejects empty/bad partials before any `assert`, `protocol::untag`
length-checks first, and the length-guarded `.unwrap()`s at `lib.rs:134,135,311` are airtight.
So this is a **Medium** defense-in-depth / robustness gap: the no-panic property depends
entirely on three external crates never regressing, with no boundary backstop.

### Recommendation
Wrap each `extern "C"` body in `std::panic::catch_unwind` returning `MV_ERR_CRYPTO` (and
re-establishing empty out-params), and/or set `panic = "abort"` in the release profile with a
documented rationale. Lens: *crash-early* (a controlled error return at the boundary, not an
unwind across FFI), *sharp-edges*.

---

## MV-M5 — Chunked-volume AEAD uses random-nonce GCM under a single long-lived DEK **[matter-crypto, adjacent]**

- **Location:** `../matter-crypto/crypto/src/aead.rs:248-280` (`seal_chunk`, nonce at `:263`).
- **Scope note:** This is in `matter-crypto`, and `seal_chunk` is **not** on
  `matter-vault-core`'s seal/open path (the SDK uses `seal_secret`, which is sound — see the
  AEAD review). Flagged as an adjacent/inherited risk for whoever uses the volume API.

### Description
`seal_chunk` encrypts every volume chunk under one fixed 32-byte `VolumeDekV1` DEK with a
fresh random 96-bit nonce. Unlike the per-secret path (where the key `k_d` changes every seal
because μ is fresh), the key here is constant across encryptions. Random 96-bit nonces under a
fixed key hit the birthday bound: collision probability ≈ q²/2⁹⁷, so NIST SP 800-38D caps
random-nonce GCM at ~2³² invocations per key. A re-encrypting backup system can plausibly
approach that; a nonce collision under one DEK leaks the XOR of two plaintexts and enables
GCM auth-key (H) recovery → forgery. The in-code comment correctly rejects a *counter* nonce
but does not address the random-nonce birthday/invocation limit.

### Recommendation (trade-offs)
(a) **AES-GCM-SIV** (nonce-misuse-resistant) — smallest change, safe even under accidental
reuse; extra dependency + small perf hit. Best fit for a re-encrypting backup system.
(b) DEK rotation / invocation cap (~2³²) with persisted state — no new crypto dep, adds
key-management. (c) Extended-nonce (XAES-256-GCM) — removes the birthday bound; depends on
library availability. Lens: *insecure-defaults* / cryptographic nonce hygiene.

---

## MV-M6 — Smudge-noise floor is not enforced on the production proof path **[matter-crypto, adjacent]**

- **Location:** `../matter-crypto/crypto/src/secret.rs:138-182` (`produce_proven_partial`),
  `../matter-crypto/crypto/src/zkp/partial_decrypt.rs:81-140` (`partial_decrypt_with_witness`);
  the safe newtype `../matter-crypto/crypto/src/threshold/partial_decrypt.rs:43-76` (`SmudgeParams`).

### Description
`SmudgeParams` is the type that *cannot be constructed below the `zkp_aware_smudge_bits` floor* —
but it only guards `partial_decrypt_secure`. The actual production entry points that emit proofs
take a **raw `smudge_bits: usize`** and never check the floor:
`produce_proven_partial(.., smudge_bits, ..) → partial_decrypt_with_witness(.., smudge_bits, ..)`.
A consumer that passes a small — or `0` — `smudge_bits` ships partials with little/no statistical
mask, leaking `λ_i·SK_i` directly, with no type-level protection. The safe newtype exists but is
wired to the wrong (non-proof) path.

### Impact / severity
Sharp edge: **Critical-if-misused**, latent today (the matter-kgc service computes the smudge via
`zkp_aware_smudge_bits` — the audited callers are safe), but the API invites a catastrophic
caller mistake. Rated Medium because no current caller misuses it.

### Recommendation
Make `produce_proven_partial` / `partial_decrypt_with_witness` take `SmudgeParams` (or recompute
and `assert!(smudge_bits ≥ zkp_aware_smudge_bits::<P>(committee_size))` before touching the share),
so the floor cannot be bypassed. Lens: *sharp-edges* ("make the safe path the only path"),
*design-by-contract*.
