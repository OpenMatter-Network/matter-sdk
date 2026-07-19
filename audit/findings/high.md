# HIGH severity findings

> Scope tags: **[core]** / **[ffi]** = the originally-requested Core+FFI scope.
> **[shell]**, **[bindings]**, **[matter-crypto]**, **[matter-node]**, **[service]** =
> surfaced during the directed scope expansion. Each finding cites exact `file:line`.

---

## MV-H1 — `mv_encrypt` leaves its out-param uninitialized on every error path → wild `free()` **[ffi]**

- **Location:** `crates/matter-vault-ffi/src/lib.rs:169-210` (the missing init between the
  null-check at `:182-184` and the first fallible use at `:185`).
- **Class:** CWE-457 (use of uninitialized variable) → CWE-824 (access of uninitialized
  pointer) → heap corruption. Verified with a segfaulting PoC.

### Description
The module contract states (`lib.rs:17-19`): *"On error, any out-params are left as empty
`MvBuf`s (`ptr == null`, `len == 0`)."* Every sibling entry point honors it by zeroing the
out-param immediately after the null check — `mv_signing_payload` (`:122`), `mv_lagrange_for`
(`:151`), `mv_verify_plaintext_proof` (`:230`), `mv_open_secret` (`:297`). **`mv_encrypt` is
the lone exception:** after `if out.is_null() { return … }` it proceeds directly to argument
decoding, and all three error returns (`:190` invalid-arg, `:207` empty/decode, `:208` other
crypto error) leave `*out` **completely untouched**.

### Impact / attack
A C consumer that follows the documented contract — reading the envelope or calling
`mv_envelope_free(out)` after a non-`MV_OK` return because the contract says `out` is empty —
operates on uninitialized stack. `mv_envelope_free` → `mv_free` →
`Box::from_raw(slice_from_raw_parts_mut(garbage_ptr, garbage_len))` → `free()` of an
uninitialized pointer value = heap corruption / crash. Trivially triggered by passing a
malformed `joint_pk` (fails bincode → `CoreError::Decode` → `MV_ERR_INVALID_ARG` with `out`
never written), or an empty `secrets`, oversized `binding_id`, or a null+nonzero-len arg.

**PoC** (built against the committed `libmatter_vault_ffi.a`): a caller fills `MvEnvelope`
with a `0xAB` sentinel, calls `mv_encrypt` with a bad `joint_pk`, observes `rc = -1` with all
four `MvBuf` fields unchanged (`ptr = 0xabab…`), then `mv_envelope_free(env)` →
`Segmentation fault (exit 139)`.

### Reachability / honest severity
The **shipped Go binding is safe**: `packages/go/mattervault/mattervault.go:106` declares
`var out C.MvEnvelope` (Go zero-initializes), and `Encrypt` returns on a non-nil error
*before* reading or freeing `out` (`:115-117`). So this is **not** reachable from the bundled
Go consumer (Medium, latent, there). It is a genuine **HIGH** for any other C-ABI consumer —
which the crate description and `include/matter_vault.h` explicitly invite.

### Recommendation
Mirror the siblings — immediately after the null check:
```rust
*out = MvEnvelope { binding_id: MvBuf::empty(), capsule: MvBuf::empty(),
                    proof: MvBuf::empty(), ct: MvBuf::empty() };
```
(Compose with MV-M4: a `catch_unwind` wrapper would also re-establish the empty out-param on
any internal panic.) Lens: *crash-early*, *sharp-edges* (the contract is a footgun the API
must honor itself), *design-by-contract*.

---

## MV-H2 — A single in-subset node forces a permanent decrypt failure via `served_epoch` **[shell]**

- **Location:** `crates/matter-vault/src/committee.rs:120-125`; amplified by the deterministic
  subset selection at `:86-87` (see MV-M2).

### Description
Any per-node response with `served_epoch != 0 && served_epoch != req.epoch` aborts the
**entire** decrypt with `SdkError::EpochRotated` — before the other partials are even
considered. A malicious in-subset node simply returns `served_epoch = req.epoch + 1` (or any
wrong nonzero value) and the whole quorum fails, though no rotation occurred.

### Impact / attack
The caller is told to "refetch and retry," but a refetch returns the same (unchanged) epoch,
and because subset selection is deterministic (MV-M2) the retry re-selects the same malicious
node → **infinite fail loop**. The `EpochRotated` error carries only the epoch numbers, not
the offending endpoint/index, so the caller cannot identify or evict the bad node. One
malicious committee member (well within the t-of-n trust model) can therefore deny decryption
of any secret indefinitely. (`served_epoch == 0` is the inverse and benign: it bypasses the
guard but only leads to a downstream aggregation/AEAD failure — DoS, not leakage.)

### Recommendation
Treat a divergent `served_epoch` as a **per-node fault** (drop that node, try the next subset
member / next subset) rather than aborting the whole decrypt; require agreement from a quorum
before concluding a real rotation; and include the offending node index in the error so the
caller can evict it. Lens: *rule-of-robustness*, *crash-early* (fail the node, not the
operation).

---

## MV-H3 — Committee transport has no timeouts and reads response bodies unbounded **[shell]**

- **Location:** `crates/matter-vault/src/transport.rs:57-60` (client construction), `:95-97`
  and `:115-117` (`.json::<…>()` calls). Insecure default; the comment at `:56` ("A transport
  with default timeouts") is factually wrong.

### Description
`ReqwestTransport::new()` builds `reqwest::Client::new()`, which sets `timeout: None`,
`connect_timeout: None`, `read_timeout: None`. The quorum flow is **sequential**
(`committee.rs:71-77` health loop, `:101-133` partial loop), so a single stalling/slowloris
node hangs `decrypt` **forever**. Separately, `.json::<Health>()` / `.json::<PartialDecryptResponse>()`
buffer the **entire** body into memory with no size cap — a malicious node returns a
multi-gigabyte body to exhaust client memory (the genuinely-unbounded allocation on the
decrypt path; cf. MV-L2, where bincode is mitigated).

### Impact / attack
A single malicious or compromised committee node (within the trust model) causes a reliable
client-side hang or OOM — denial of service of all decryption. `with_client` lets a caller
inject a hardened client, but the **default** path (`new()` / `Default`) is unsafe, and the
misleading comment actively discourages callers from fixing it.

### Recommendation
Set sane `timeout` / `connect_timeout` / `read_timeout` defaults in `new()`; cap the response
body (bounded reader, or reject on `Content-Length` / streamed size) before `.json()`; correct
the comment. Lens: *insecure-defaults* (fail-open default + misleading doc), *rule-of-robustness*.

---

## MV-H4 — ZKPoPartDec witness-shift margin ignores the real share norm `B_s` → statistical-ZK break → `SK_i` leakage **[matter-crypto, adjacent]**

- **Location:** `../matter-crypto/crypto/src/zkp/mod.rs:205-224` (`partdec_beta_bits`), `:93-95`
  (`beta_shift_bits`); constants `:26` (`B_MASK_BITS=63`), `../matter-crypto/crypto/src/threshold/shamir.rs:15`
  (`MAX_EVAL_POINT=1024`), `../matter-crypto/crypto/src/dkg/mod.rs:178`.
- **Conditional:** does **not** trigger for the default `(t=3, n=5)` committee (points 1–5);
  triggers for committees / reshares that assign evaluation points above a per-threshold limit
  (t=5 → point ≥ 23, t=4 → ≥ 64, t=3 → ≥ 512 — all inside the allowed `[1,1024]`). Rated **High**
  because it is a concrete cryptographic leak of secret-share material and the trigger is
  reachable; effectively **Critical** for any deployment that uses large eval points.

### Description
Statistical-ZK of the Fiat–Shamir-with-aborts proof requires the witness-shift margin
`β_shift = KAPPA_BITS + max_witness_bits` to cover every witness, including the share `SK_i`:
`2^β_shift ≥ ‖c·SK_i‖_∞`. `partdec_beta_bits` sets `max_witness_bits = max(smudge_bits + t_bits,
FLOOR) ≈ 81` and its comment **asserts the smudge dominates the share bound `B_s` — which is
provably false**. Production shares `SK_i = Σ c_l·x_i^l` have `‖c_l‖ ≤ 2^63`, so `B_s ≈
2^63·Σ x_i^l`; for the eval points above, `log2(B_s) > 81` and `‖c·SK‖` reaches ~2^89 while
`β_shift = 2^87`. The rejection loop still terminates (~98% accept), but the accepted `z_sk` box
is **truncated** on one edge for the over-margin coefficients, so an observer learns the
sign/magnitude of `(c·SK)_j`. Because `c` is the public Fiat–Shamir challenge and `SK_i` is
linear, collecting these across decryptions yields linear constraints on `SK_i`.

### Impact
The ZKPoPartDec is the *sole* protection of `SK_i` in each released partial; this degrades its
zero-knowledge and leaks share bits for committees/reshares using large eval points → share, then
joint-key, recovery (compounded by the absence of a decryption cap — see MV-L12).

### Recommendation
Size `max_witness_bits` from the actual share bound: `max(smudge_bits + t_bits, log2(B_s),
FLOOR)` with `B_s = B_MASK_BITS + ⌈(t-1)·log2(MAX_EVAL_POINT)⌉`. Note this pushes `β_dec` past the
`q_bits-2` soundness ceiling for large points — i.e. the parameters genuinely cannot support both
large eval points and an 80-bit smudge; constrain eval points (e.g. small `1..=n`) and/or
re-derive parameters. Lens: *mpc-audit* (witness domain / ZK), *prove-don't-assume* (the false
guiding comment).

---

## MV-H5 — Reshare output share-commitment map is first-writer-trusted **[matter-node pallet-kgc]**

- **Location:** `../matter-node/pallets/kgc/src/lib.rs:1007-1062` (`submit_reshare_output`).

### Description
Reshare correctly carries the source epoch's `joint_pk`/`shared_a` forward from chain (`:1038`),
so the MV-C3 key-substitution does **not** apply to `joint_pk` on reshare. But the per-node
`ShareCommitments` `g_j` map is still taken from the **first writer** with no recomputation
against the dealer contributions: a malicious recipient that writes first can post a `g_j` map
with `n` valid member ids and arbitrary commitment bytes; honest recipients then fail with
`OutputMismatch`.

### Impact
`g_j` is the public commitment that `partial_decrypt` / ZKPoPartDec verify against, so a wrong map
causes honest partial decryptions for that epoch to be rejected chain-wide (**decryption DoS**)
and poisons the epoch's integrity anchor. Not a direct key compromise (real capsules still only
open under real shares) → High, not Critical.

### Recommendation
Derive/verify `g_j` on-chain from the reshare dealer inputs (`derive_reshared_commitment`), or have
nodes assert the on-chain map equals their locally derived one before serving. Lens: *prove-don't-assume*.

---

## MV-H6 — Resharing provides no proactive security: superseded shares are kept (and never zeroized) → every historical committee is a standing reconstruction set **[matter-kgc service + matter-crypto]**

- **Location:** `../matter-kgc/service/src/state.rs` (`save_epoch` archives, never deletes old
  shares; only `delete_pending_contribution` removes in-flight state, `:319`);
  `../matter-node/pallets/kgc/src/lib.rs:1307` ("per-epoch ShareCommitments are historical; leave
  them in place"); `../matter-crypto/crypto/src/.../reshare.rs:180-187` (rotated-out dealer keeps
  its prior `finalised` state). No `zeroize`/secure-wipe of superseded shares anywhere.

### Description
Reshares preserve the master secret `sk` (same `joint_pk` across epochs, by design), and old-epoch
shares are retained indefinitely (on disk) to serve old capsules. Therefore **every past epoch's
share set remains fully reconstructive of the still-current `sk`**: any `t` shares of *any*
historical epoch reconstruct it. A node deliberately rotated **out** (e.g. because it is suspected
compromised) keeps a valid share that, with `t-1` other ex-members of that same epoch, reconstructs
the current secret.

### Impact
Resharing here is **not** proactive refresh — it does not render old shares useless, contradicting
the "only the legitimately-selected committee holds shares" guarantee. It is a `t`-collusion break
(hence High, not Critical) that converts every historical committee into a permanent reconstruction
set; combined with the no-erasure gap, retired/compromised nodes never lose their capability. Also
a *zeroize-audit* failure: superseded secret shares are never wiped.

### Recommendation
Rotate the master secret (fresh DKG) — not merely reshare — when retiring suspect members; and
securely `zeroize` superseded shares once their epoch's capsules have been re-encrypted under the
current epoch. If reshare-without-rotation is intentional, document explicitly that reshare ≠
proactive refresh and that ex-members retain reconstruction capability. Lens: *zeroize-audit*,
*mpc-audit* (proactive security / erasures).
