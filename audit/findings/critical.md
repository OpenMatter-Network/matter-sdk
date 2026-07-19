# CRITICAL severity findings

All three were verified against source (cited `file:line`). Each independently breaks the
product's crown-jewel guarantee — *no party below the threshold, and no unauthorized party, ever
recovers a secret*. They are **distinct root causes**, not three views of one bug.

> **Scope note.** The originally-requested audit scope was Core+FFI (`matter-vault-core`,
> `matter-vault-ffi`). MV-C1 touches the SDK directly (its request-signing payload). MV-C2 and
> MV-C3 were found during the **directed scope expansion** into the wider matter ecosystem
> (`matter-kgc`, `matter-node`) and are recorded here because they are the most severe issues
> affecting the SDK's users; they are owned by those sibling repos, not by `matter-vault-core`.

---

## MV-C1 — `/partial-decrypt` request is a replayable, non-recipient-bound bearer token → one in-subset node defeats the threshold **[sdk signing-payload + shell + proto]**

- **Severity:** Critical · **Confidentiality** (sub-threshold secret recovery).
- **Locations:** signed payload `../matter-kgc/kgc-proto/src/lib.rs:73-88` (re-exported and used by the
  SDK at `crates/matter-vault-core/src/decrypt.rs:51-53`); shell signs-once / fans-out
  `crates/matter-vault/src/committee.rs:92-97` and `:101-114`; deterministic subset
  `:86-87` (MV-M2 amplifier).

### Description
`partial_decrypt_signing_payload` binds **only** `domain ‖ secret_id ‖ len(subset) ‖ subset ‖
block_hash`. It binds neither the responding node's identity nor a single-use nonce. The shell
signs the request **once** (`committee.rs:92-97`) and sends the *identical* `requester` +
`signature` to every node in the subset (`:107-109`); the only per-node field, `lagrange_coeff`,
is public and **unsigned**.

### Attack (verified from source)
A malicious committee node — within the t-of-n trust model, which is meant to tolerate up to
`t-1` of them — receives a legitimate, authorized request when a user decrypts. Because the
signature covers nothing node-specific, the node **replays that same signature to every other
node in the subset**, computing each peer's public `lagrange_for(j, subset)` itself. Each peer
verifies the (unchanged) signature, confirms the genuine requester is on-chain authorized, and
returns its partial *to whoever holds the connection*. The malicious node thereby collects all
`t` partials and calls `open_secret` alone — recovering the plaintext below threshold, as an
unauthorized aggregator. The freshness window (~10 blocks) is ample to issue `t-1` HTTP calls.
Deterministic lowest-index subset selection (see MV-M2) means a fixed low-index
malicious node is in essentially every quorum, so it passively harvests **every** secret any
user ever decrypts.

### Impact
The entire `t-of-n` confidentiality guarantee collapses to **a single malicious node** for any
secret in active use — the product's central security property, broken during normal operation.

### Recommendation
Make the signed request recipient-bound and/or single-use: fold the responding node's
`dkg_index` (or account) into `partial_decrypt_signing_payload` and have each node verify it is
the named recipient (i.e. sign **per node**, not once per subset); or return each partial
encrypted to the requester's key so a replaying peer cannot read it; or add a server-deduped
single-use nonce to the signed payload. A shell-only change is insufficient — the binding must
be enforced node-side. Lens: *mpc-audit* (context binding / recipient binding), *design-by-contract*.

---

## MV-C2 — EIP-712 meta-transaction blind-signing → `secrets.grant_access` (and fund transfers) dispatched as the victim → unauthorized decrypt **[matter-node]**

- **Severity:** Critical · **Authorization bypass** (unauthorized decrypt; also asset theft).
- **Locations:** digest `../matter-node/pallets/eth-signing/src/lib.rs:390-410`; dispatch-as-victim
  `:288-296`; CallFilter allow-set `../matter-node/runtime/src/configs/matter.rs:689-712`;
  `grant_access` + `is_authorized` `../matter-node/pallets/secrets/src/lib.rs:322-347, 434-452`.

### Description (mechanism corrected during the audit)
The EIP-712 `MatterTx` digest **does** bind the real `callHash` (`eth-signing/lib.rs:398-402`) —
so the dispatched call cannot be swapped after signing. The flaw is that the human-readable
`pallet` / `method` / `summary` fields shown to the signer by their wallet are **never checked
against the actual call**; the runtime comment states outright that "the runtime never parses or
trusts them … they exist so MetaMask/Rabby can show a meaningful prompt." Classic
what-you-see-is-not-what-you-sign: the wallet renders attacker-chosen strings while the opaque
`callHash` carries the real authority.

### Attack (verified from source)
1. The `EthSigningCallFilter` is a **deny-list** (`matter.rs:692-710`) that does **not** include
   `RuntimeCall::Secrets(_)` (nor `Balances`/`Assets`) — so `Secrets::grant_access` is reachable.
2. `dispatch_eth_signed` runs the inner call as `RawOrigin::Signed(victim)`
   (`eth-signing/lib.rs:288-296`).
3. `grant_access(secret_id, target)` owner-checks the **caller** only (`secrets/lib.rs:330-331`)
   and inserts the fully attacker-controlled `target: GrantTarget::User(attacker)`
   (`:328, :342`); `is_authorized` then returns `true` for that grantee (`:434-452`) — the single
   source of truth the committee consults before issuing partials.

So an attacker's phishing dApp builds a `MatterTx` whose `call = Secrets::grant_access(victim_secret,
User(attacker))` but whose advisory reads e.g. *"Balances · transfer · Send 0.01 MTR"*; the wallet
shows the benign text; the victim signs once; the attacker submits it; the chain dispatches it as
the victim/owner; the attacker now holds a standing decrypt grant and **decrypts the victim's
secret**. The same primitive grants `Balances`/`Assets` transfers (direct fund theft) and
`delete_secret`/`rotate_secret` (destruction/tamper).

### Impact
A single phished signature over benign-looking text yields standing unauthorized decrypt access
to a victim's secrets (full secrets-ACL bypass) — and, via the same path, asset theft. The
present mitigations (call-hash binding, nonce, 1-hour validity, chainId/genesis domain) make the
malicious call **reliable**, not harder.

### Recommendation
Bind display to call on-chain: have the runtime derive the human-readable name from the *decoded
call* (call index → name table) and ignore or `ensure!`-match the supplied advisory; and/or
exclude authorization-mutating `secrets` calls from the meta-tx CallFilter, routing them through
a path with explicit per-call typed data. Wallet-side decoding alone is insufficient (the
attacker controls the dApp). Lens: *sharp-edges* (WYSINWYS footgun), *insecure-defaults*.

---

## MV-C3 — Rogue joint-public-key substitution at DKG output: chain trusts the first writer, honest nodes never reconcile → one sub-threshold member decrypts the whole epoch **[matter-node pallet-kgc + matter-kgc service]**

- **Severity:** Critical · **Confidentiality** (key-establishment integrity → sub-threshold recovery).
- **Locations:** `../matter-node/pallets/kgc/src/lib.rs:881-940` (`submit_dkg_output`);
  honest driver `../matter-kgc/service/src/dkg.rs:451-491`.

### Description (verified from source)
`submit_dkg_output` records the epoch's `joint_pk`/`shared_a` from **whichever seated member
writes first** (`lib.rs:911-921`). Its only validation is: caller is a `KgcNode`,
`DkgRound1Count == n`, and the `n` `share_commitments` entries name committee members. **It never
recomputes `joint_pk = Σ g_{i,0}` from the on-chain Round-1 transcript** (`DkgRound1`/`DkgCommits`
are stored but never read here). Later writers can only match-or-`OutputMismatch` (`:923-936`).
The honest driver does **not** reconcile: it checks `already_complete` (`dkg.rs:454`), logs
"skipping submit" (`:469`), and Stage 8 simply waits for *any* on-chain `joint_pk` and goes
Active (`:473-491`) without ever comparing it to its own `persistent.joint_pk`.

### Attack
A single malicious seated member (1 < `t` = 3 default) participates through Round-1 reveal, then
the instant `DkgRound1Count == n` races `submit_dkg_output(joint_pk = pk*, shared_a = a*,
share_commitments = <n member ids, garbage g_j>)` where `(pk*, sk*)` is a keypair it generated
and knows. It wins the race trivially — honest nodes are still doing off-chain share exchange and
`process_contributions`. `DkgComplete` fires for `pk*`; honest nodes see `already_complete`, skip,
and go Active without comparing.

### Impact
Clients/providers fetch the joint key straight from chain and encrypt under it with no transcript
validation (`matter-sdk/packages/typescript/src/crypto.ts:13,19-26`;
`matter-node/provider/src/crypto.rs:74-79`). Every secret sealed that epoch is encrypted to `pk*`,
which the **single** malicious member decrypts alone with `sk*`. The honest committee — holding
shares of the real `sk` — cannot decrypt those capsules, so the breach is silent until after the
attacker has harvested. The t-of-n committee is bypassed by one sub-threshold member. Distinct
from MV-C1/MV-C2: this is a key-establishment-integrity failure.

### Recommendation
Make the DKG output a function of the committed transcript, not of a submitter's say-so:
(a, robust) have the pallet recompute `joint_pk = Σ g_{i,0}` and each `g_j` from the on-chain
`DkgRound1` commitments and reject any `submit_dkg_output` that disagrees; and (b, at minimum)
require every honest node in `dkg.rs` Stage 8 to assert `chain.joint_pk_bytes() ==
persistent.joint_pk` and refuse to go Active (halt + alarm) on mismatch. Lens: *mpc-audit*
(adaptive inputs / output integrity), *prove-don't-assume* (validate the transcript, don't trust
the writer), *crash-early*.
