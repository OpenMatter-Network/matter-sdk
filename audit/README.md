# MatterSDK security audit — Rust crypto core & FFI (+ directed scope expansion)

**Date:** 2026-06-29 · **Subject commit:** `main` (matter-sdk) with sibling checkouts
`../matter-crypto` (0.8.0), `../matter-kgc` (0.7.1), `../matter-node`.

This directory documents (1) the fix that restored compilation, and (2) a security audit that
began at the requested **Core + FFI** scope and was then **deliberately widened** across the
matter ecosystem (shell, bindings, proto/config, the committee service, the on-chain pallets,
and the crypto primitives) to chase genuine critical findings to ground.

Findings are categorized by criticality, one file per severity:
- [`findings/critical.md`](findings/critical.md) — 3
- [`findings/high.md`](findings/high.md) — 6
- [`findings/medium.md`](findings/medium.md) — 6
- [`findings/low-and-informational.md`](findings/low-and-informational.md) — 13 low + 4 informational

---

## Executive summary

**The codebase is, in its audited core, well-engineered and visibly remediated** — the SDK crypto
core, the AEAD/seal construction, the ZK transcript binding, the signature/authorization checks,
the committee-membership access control, and the language bindings are all sound, with a clear
history of prior fixes (commit-before-reveal, HIGH-04 anti-oracle gate, length-framed
domain-separated hashing, etc.). The serious problems are **not** in the cryptographic primitives;
they are in **orchestration and integration trust boundaries** — exactly where threshold systems
tend to fail.

Three **Critical** findings, each independently breaking the product's central guarantee (no
sub-threshold / unauthorized party recovers a secret), all verified against source:

| ID | Title | Where the guarantee breaks |
|----|-------|----------------------------|
| **MV-C1** | `/partial-decrypt` request is a replayable, non-recipient-bound bearer token | One in-subset malicious node replays a user's authorized request to peers and recovers any actively-decrypted secret alone — t-of-n → 1-of-n. |
| **MV-C2** | EIP-712 meta-tx blind-signing → `secrets.grant_access` dispatched as the victim | One phished signature over benign-looking text grants the attacker standing decrypt rights (and enables fund transfers). |
| **MV-C3** | Rogue joint-PK substitution at DKG output (first-writer-trusted, no reconciliation) | One sub-threshold member seats a public key it controls; clients encrypt to it; it decrypts the whole epoch. |

MV-C1 touches the SDK directly (its request-signing payload); MV-C2 and MV-C3 live in
`matter-node` / `matter-kgc` and were found during the directed scope expansion — recorded here
because they are the most severe issues affecting this SDK's users.

The **compile break is unrelated and fully fixed** (see below): it was `matter-crypto` API drift
(0.6 → 0.8), confined to test/example harnesses; the shipped libraries and bindings always built.

### Counts by severity
| Severity | Count | IDs |
|----------|-------|-----|
| Critical | 3 | MV-C1, MV-C2, MV-C3 |
| High | 6 | MV-H1 (ffi wild-free), MV-H2 (epoch DoS), MV-H3 (transport DoS), MV-H4 (ZK margin → share leak), MV-H5 (reshare g_j first-writer), MV-H6 (no proactive security) |
| Medium | 6 | MV-M1 (caller-trusted λ/commitment), MV-M2 (deterministic quorum), MV-M3 (seed→String), MV-M4 (panic across FFI), MV-M5 (AEAD chunk nonce), MV-M6 (smudge floor) |
| Low | 13 | MV-L1 … MV-L13 |
| Informational | 4 | MV-I1 … MV-I4 |

### In-scope vs expanded
- **Original Core + FFI scope** (`matter-vault-core`, `matter-vault-ffi`): MV-C1 (signing payload),
  MV-H1, MV-M1, MV-M4, MV-L1, MV-L2, MV-L3, MV-L7, MV-I1–I3. Net: the FFI wild-free (MV-H1) is the
  most actionable in-scope defect; the core is otherwise sound, with one notable API sharp edge
  (MV-M1).
- **Expanded scope** (shell, bindings, matter-crypto, matter-kgc, matter-node): everything else,
  including MV-C2, MV-C3 and the crypto-primitive findings — surfaced because the directive was to
  keep widening until genuine criticals were either found or scope was exhausted.

---

## Threat model

- t-of-n threshold decryption (`matter-crypto` RLWE/BGV). Default committee `(t=3, n=5)`, so the
  system must tolerate up to **t-1 = 2** malicious *seated* committee members.
- Attacker-controlled / influenceable inputs: committee HTTP responses (up to t-1 malicious nodes),
  on-chain blobs an owner published, and any caller bytes crossing the FFI/binding boundary.
- Trusted: the chain state (joint PK, per-node Feldman commitments, authorization records) — though
  MV-C3 shows the chain *records* a value it never *validates*.
- The wasm build runs in a browser → a co-located adversary exists for that target (relevant to
  MV-L13 / the variable-time disclaimer).

## Severity definitions (tailored to a threshold secrets vault)
- **Critical** — a party below the threshold, or an unauthorized party, recovers a secret;
  signing/committee-key compromise; or remote memory corruption with code-exec potential.
- **High** — single-node/condition-gated confidentiality or integrity weakening; reliable remote
  DoS of decryption; key-material-in-memory exposure; a cryptographic ZK/soundness defect that
  leaks secret material under reachable conditions.
- **Medium** — an unenforced security precondition (sharp edge) that is safe in all current callers
  but catastrophic if misused; defense-in-depth gaps with real impact.
- **Low / Informational** — hardening, hygiene, footguns without a demonstrated exploit, parity
  bugs, and process gaps.

## Methodology
Context was built bottom-up, then probed adversarially. Eleven focused sub-analyses covered:
compile diagnosis; the core crypto map; the FFI/boundary map; threshold/aggregation soundness;
the AEAD/seal construction; FFI memory safety; the wire/proto/replay layer; signature &
authorization; the language bindings; the shell orchestration & signer; the crypto primitives
(smudge/ZK/timing); the committee node's oracle gate & on-chain authorization; the EIP-712 meta-tx
blind-signing path; and the DKG/reshare key lifecycle. Lenses applied (loaded skills): *mpc-audit*,
*constant-time-analysis*, *zeroize-audit*, *sharp-edges*, *insecure-defaults*, plus the pragmatic
practices (*design-by-contract*, *crash-early*, *prove-don't-assume*, *listen-to-nagging-doubts*,
*fix-the-problem-not-the-blame*, *dry-audit*, *broken-windows*). **All three Criticals and the FFI
wild-free were independently re-verified against source** before write-up; one candidate critical
(smudge-noise averaging) was quantified and **honestly rejected** as infeasible (≈2¹⁶² queries —
MV-L12).

---

## The compile fix (Part 1 — done & verified)

**Root cause:** `matter-crypto` advanced from the API the SDK was written against (0.6.x) to **0.8.0**,
breaking only the in-tree committee/DKG-*simulation* harnesses; all three libraries and the
bindings always compiled. Two functions changed signature, adding **security-binding** parameters:
- `produce_proven_partial` gained `pk`, `capsule_proof`, `binding_id` and now returns `Option`
  (the HIGH-04 anti-oracle gate: a node verifies the capsule's ZKPoPlaintext before
  partial-decrypting).
- `process_contributions` gained `prior_commitments` and `ssid` (commit-before-reveal / session
  binding).

**Fix:** updated the three call sites — `crates/matter-vault-core/tests/roundtrip.rs`,
`crates/matter-vault/tests/decrypt.rs`, `examples/rust/src/main.rs` — to thread the **real** values
(decoding the on-chain tagged proof via `decode_tagged`, the real `binding_id`, a per-session
`ssid`, and real round-1 commitments via `commit_to_contribution`), **not** stubs — stubbing would
have either failed the gate or blessed an unbound transcript in the cross-language conformance
vectors. Also added `matter-kgc-config` to the example's deps and corrected the stale
`matter-crypto v0.6.0` version-pin comment to `v0.8.0` (MV-I3). The new params feed only the gate /
commit-check (not share or proof byte derivation), so the committed `testvectors/*.json` remain
valid — no regeneration was forced.

### Verification (reproduce)
```
cargo check --workspace --all-targets          # clean
cargo clippy --workspace --all-targets          # clean (CI denies clippy::all)
cargo test -p matter-vault-core --test roundtrip # 3 passed (full seal→open round-trip)
cargo test -p matter-vault --test decrypt        # 2 passed (shell orchestration + quorum-unavailable)
```
All pass (the ZKP round-trip tests take ~30 s of real proving — not hangs). `cargo fmt --check`
showed diffs only in the pre-existing, untouched `examples/rust-e2e/src/main.rs`; the edited files
are clean.

---

## Recommended remediation order
1. **MV-C3** then **MV-C1** then **MV-C2** — the three Criticals; each is a standalone secret-exposure
   path. C3 and C1 both reduce to "validate/bind what you currently trust"; C2 needs the runtime to
   tie wallet display to the decoded call.
2. **MV-H1** (FFI wild-free — trivial in-scope fix), **MV-H4** (re-derive the ZK witness margin or
   constrain eval points), **MV-H2/H3** (per-node fault handling + transport timeouts/body caps),
   **MV-H6** (rotate-don't-reshare for retirement + zeroize old shares).
3. Mediums (notably **MV-M1/M6** — make the safe crypto path the only path) and the Low/Info
   hardening (add `cargo-deny`/`cargo-audit`, gate the binding crates in CI).
