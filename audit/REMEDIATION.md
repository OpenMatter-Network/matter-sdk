# Remediation status

Fixes applied for the highest-criticality findings, each **built and tested**. Commands were run
from the relevant repo root; matter-node crates build incrementally in seconds here.

| Finding | Sev | Status | Where | Verification |
|---|---|---|---|---|
| MV-C2 | Critical | **Fixed** | matter-node (eth-signing) | pallet tests (19) + runtime build |
| MV-C3 | Critical | **Fixed** | matter-node (pallet-kgc) | pallet tests (67) + benchmarks + runtime build |
| MV-H1 | High | **Fixed** | matter-sdk (ffi) | `cargo test -p matter-vault-ffi` |
| MV-H2 | High | **Fixed** | matter-sdk (shell) | `cargo test -p matter-vault --test decrypt` |
| MV-H3 | High | **Fixed** | matter-sdk (shell) | `cargo clippy --workspace --all-targets` |
| MV-C1 | Critical | **Fixed** | proto + sdk + service (all bindings) | replay + conformance tests, both repos (see below) |

---

## MV-C2 — Bind the meta-tx advisory to the actual call *(Fixed)*
`pallet-eth-signing` now rejects a meta-transaction whose wallet-displayed `pallet`/`method`
don't match the decoded call's own metadata, so a relayer can no longer show benign text while
the signed `callHash` carries a sensitive call (e.g. `Secrets::grant_access`). Covers **all**
pallets (also closes the Balances/Assets blind-sign fund-theft variant), not just secrets.

- `…/pallets/eth-signing/src/lib.rs`: added `GetCallMetadata` to the `RuntimeCall` bound; new
  `Error::AdvisoryMismatch`; in `dispatch_eth_signed`, `ensure!` the advisory `pallet`/`method`
  equal `call.get_call_metadata()` before dispatch (`summary` stays free-text).
- Tests: updated the 5 tests whose placeholder advisory no longer matched; added
  `mislabelled_advisory_is_rejected` proving the guard fires. **19 pass.** Runtime builds.
- Note: off-chain meta-tx builders (dashboard/relayer) must now set `advisory.pallet`/`method`
  to the exact runtime names — which is the point (the displayed call must be truthful).

## MV-C3 — Require threshold agreement to finalize a DKG output *(Fixed)*
`pallet-kgc::submit_dkg_output` no longer trusts the first writer. It tallies votes for the
candidate `(joint_pk, shared_a, share_commitments)` (hashed over its canonical encoding) and
finalizes only once `threshold` **distinct** committee members submit the identical output. A
lone sub-threshold member submitting a `pk*` it controls can never reach the threshold; its
divergent submission only accrues its own tally.

- `…/pallets/kgc/src/lib.rs`: new `DkgOutputVotes` / `DkgOutputVoter` storage; rewrote the
  finalize path (one vote per member, finalize at `Self::threshold()` agreers, idempotent
  matching follow-ups still accepted).
- Tests: updated `finalises_*` / `idempotent` / `mismatched_resubmission` for the quorum
  semantics; added `single_member_cannot_substitute_dkg_output` proving the rogue key is never
  seated. **67 pass.** Benchmarks + runtime build.
- The honest committee already submits once per node, so a valid committee (`n ≥ 2t-1`) reaches
  the threshold without any driver change. (Operationally, the matter-kgc `dkg.rs` Stage-8
  wait-for-`joint_pk` loop now resolves at quorum rather than first-write — confirm its
  `STAGE_TIMEOUT` comfortably covers `t` nodes submitting; no code change required.)

## MV-H1 — `mv_encrypt` clears its out-param on error *(Fixed)*
`crates/matter-vault-ffi/src/lib.rs`: `*out = MvEnvelope::empty()` immediately after the null
check (added `MvEnvelope::empty()`), matching every sibling entry point. Regression test
`mv_encrypt_clears_out_on_error` (fails without the fix) — **passes**.

## MV-H2 — Quorum tolerates a single faulting/divergent node *(Fixed)*
`crates/matter-vault/src/committee.rs`: `decrypt` now drops a node that errors or serves a
divergent `served_epoch` and re-forms the subset from the remaining nodes (re-signing for the
new subset); a *genuine* rotation still surfaces once a `threshold` of nodes agree on a new
epoch. New test `decrypt_excludes_a_node_serving_a_wrong_epoch` — **passes** (all 3 decrypt
tests green).

## MV-H3 — Transport timeouts + response-body cap *(Fixed)*
`crates/matter-vault/src/transport.rs`: `ReqwestTransport::new()` builds a client with a 30s
request timeout + 10s connect timeout; responses are read through a 1 MiB-capped streaming
reader before JSON decode (no more unbounded `.json()`), so one hostile node can neither hang
nor OOM the client. Corrected the misleading "default timeouts" comment.

---

## MV-C1 — Recipient-bind the `/partial-decrypt` request *(Fixed — Option A)*
The attack: the signed request bound only `(secret_id, subset, block_hash)`, so a malicious
in-subset node could replay a user's authorized request to the other nodes and harvest their
partials — collapsing t-of-n to 1-of-n. The fix folds the **responding node's `dkg_index`** into
the signed payload, so a signature made for node `j` is not valid bytes at any other node. The
requester now signs **once per node** in the quorum; each node reconstructs the payload with its
*own* index and rejects anything else — it never trusts a recipient identity from the wire. The
domain separator is bumped `v1 → v2`, so a pre-fix (non-node-bound) signature can't be replayed
across the upgrade.

**Chosen: Option A** (per-node signature binding) over Option B (encrypt each partial to the
requester). B(ii)'s one-prompt wallet UX was the only real draw, but A keeps the HSM/`Signer`
model strictly sign-only (B would have made it *decrypt*), needs no new HPKE/sealed-box
primitive, and the sr25519 SDK path signs `t` times cheaply. The EIP-712 path pays `t` wallet
prompts per decrypt — accepted, as that flow is rare/automated here.

Cross-language change (the payload is regenerated and verified by every binding):
- `matter-kgc/kgc-proto`: `partial_decrypt_signing_payload` gains `recipient_index: u64`
  (trailing big-endian, after the length-framed subset and block hash); domain → `…/v2/`.
- `matter-kgc/service`: the Substrate verifier reconstructs the payload with `our_index`
  (`serving.dkg_index` for the *served* epoch); the Ethereum path binds `nodeIndex` into the
  EIP-712 digest via `authenticate_eth_request(..., our_index, …)`.
- `matter-kgc/wasm`: `partialDecryptSigningPayload` gains the `recipientIndex` argument.
- matter-sdk: `matter-vault-core::signing_payload`, the shell `SigningRequest.recipient_index`
  (the fan-out in `committee.rs` now signs inside the per-node loop), the FFI
  `mv_signing_payload` (+ header), and the wasm/TS/Python/Go bindings — all thread the index.
- `testvectors/signing_payload.json` regenerated (adds `recipient_index`, v2 payloads).

**Verification.**
- matter-sdk `tests/mvc1_replay.rs` — reproduces the replay with **real `matter-crypto`**: a v1
  committee is robbed by one replayed signature; a v2 committee rejects it at every peer so the
  attacker stays below threshold; the honest per-node path still opens the secret. **Passes.**
- matter-sdk `tests/recipient_binding.rs` — asserts `decrypt` signs once per node with that
  node's index and each node gets a distinct signature. `per_node_signatures_differ` +
  `signing_payload_is_deterministic_and_binds_inputs` cover the payload itself. **Pass.**
- matter-kgc: `cargo test` green (60 service tests incl. `eth_auth::rejects_replay_to_other_node`;
  proto `recipient_binding_defeats_replay`). matter-sdk workspace builds; TS conformance (7) green
  against the regenerated vector.
