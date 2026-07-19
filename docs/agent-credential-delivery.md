# Data Marketplace: data-source credential delivery via MatterVault

Status: **Design — approved for implementation** (2026-07-18)
Feature: OpenMatter Data Marketplace · Companion docs: `matter-node/docs/data-marketplace-datasets.md`,
`matter-org-meta/docs/dataset-public-blobs.md`, `matter-ml/docs/data-source-connectors.md`,
`datavisor_v2/docs/data-marketplace-spec.md`

## Use case & system overview

OpenMatter is adding a public data marketplace: users register datasets whose raw data stays
self-custodied on their device via the matter-ml agent; only public metadata is shared, and
datasets are consumed exclusively through Secure Data Collaboration MPC. The agent is gaining
**AWS S3** and **PostgreSQL** connectors, which need credentials (access keys, DB passwords).

Product decision: **credentials are delivered to the agent via the MatterSDK** — i.e. the
sealed-secret flow this SDK exists for, not plaintext HTTP bodies. The dashboard seals the source
config under the KGC committee joint key, stores it on-chain (`pallet-secrets`), grants the
agent's session account decrypt rights, and the agent — becoming a new SDK consumer —
threshold-decrypts it. Plaintext credentials never cross the dashboard↔agent loopback boundary
and are never persisted anywhere.

This maps exactly onto the SDK's built-in model (**seal → store on-chain → grant → recipient
threshold-decrypts**); the SDK deliberately gains **no agent transport**. Changes in this repo
are small and additive.

## What gets added (this repo)

| Piece | Where |
|---|---|
| `Aad::DatasetSourceCredsV1 = "matter-dataset/source-creds/v1"` | `crates/matter-vault-core/src/aad.rs` (enum is `#[non_exhaustive]`/append-only — non-breaking) + TS mirror in `packages/typescript` |
| Documented canonical payload schema for the new AAD (below) | this doc + rustdoc on the variant |
| (Nice-to-have) `recover_secret` one-call helper for embedded Rust consumers | `crates/matter-vault/src/lib.rs`, thin composition over the existing `committee`/`transport`/`open_secret` orchestration |
| Consumer guidance for the matter-ml agent | this doc |

Explicit non-goals: no SDK→agent HTTP client; no transaction submission (apps keep their own
chain clients per the SDK's existing contract); no new crypto (seal/decrypt paths are unchanged).

## Why this shape

- **Reuses the SDK's entire purpose.** Sealing, on-chain storage call-builders
  (`StoreSecret`/`RotateSecret`/`GrantAccess` in `crates/matter-vault/src/calls.rs`), the
  `Signer` abstraction, committee quorum transport, and zeroizing `open_secret` all exist. The
  only genuinely new thing anywhere is *the agent linking the Rust crate* (tracked in the
  matter-ml doc).
- **A dedicated AAD tag** rather than reusing `StorageCredsV1` (`matter-volume/storage-creds/v1`):
  AAD binds ciphertext to its consumer context. Dataset-source credentials have a different
  consumer (the ml-agent) and lifecycle than volume storage creds (providers); conflating them
  would let a ciphertext sealed for one context be replayed into the other. One tag for both S3
  and Postgres — the payload self-describes its kind — keeps the registry small.
- **No signer-type restriction.** Sealing needs no signature; `storeSecret`/`grantAccess` are
  ordinary extrinsics any wallet can sign; *decryption* is performed by the **agent's** key, not
  the user's — so EVM-mapped and extension-wallet users get full functionality (unlike flows that
  require the dashboard's Web3Auth localPair to decrypt).

## Design

### Payload schema (canonical, versioned by the AAD tag)

Sealed plaintext = UTF-8 JSON:

```json
{ "kind": "s3",
  "bucket_name": "…", "region": "…", "object_key": "…",
  "access_key_id": "…", "secret_access_key": "…" }

{ "kind": "postgres",
  "host": "…", "port": 5432, "database": "…",
  "username": "…", "password": "…",
  "table_name": "…", "ssl_enabled": true }
```

Field names are the snake_case mirror of the dashboard's existing `S3Config`/`PostgresConfig`
types (`datavisor_v2/src/lib/collaborate/types.ts`) and the agent's `S3Params`/`PostgresParams`
(matter-ml doc). The **whole config** is sealed — descriptors included — so the ingest request
carries only a `secret_id` and there is no split-brain between sealed and unsealed halves.
Unknown fields must be ignored by consumers (forward compatibility); breaking changes mint a
`…/v2` AAD tag.

### End-to-end flow (who calls what)

1. **Dashboard (TS SDK, existing surface)**: `encrypt(joint_pk, epoch, payload,
   Aad.DatasetSourceCredsV1)` → `storeSecret(payload, epoch, label, aad)` call-builder →
   submit with the user's own signer → `secret_id` from the event.
2. **Dashboard**: read the agent's session identity (`GET /identity` on the agent →
   `sign_pubkey_hex`, an ed25519 key usable as AccountId32) → build
   `GrantAccess(secret_id, agent_account)` → submit.
3. **Dashboard → agent**: `POST /ingest/source { secret_id }` (bearer-authed loopback).
4. **Agent (new Rust consumer)**: fetch `EncryptedSecret` + epoch from `pallet-secrets` storage
   (its existing subxt client) → committee roster/joint-pk **at the secret's stored epoch** →
   quorum `/partial-decrypt` via `ReqwestTransport`, each per-node request signed by the agent's
   session ed25519 key (`MultiSignature::Ed25519`; KGC nodes authorize via
   `SecretsApi::is_authorized`, satisfied by the grant) → `open_secret` → `Zeroizing` plaintext
   → parse → connector → drop.
5. **Dashboard**: `revokeAccess(secret_id, agent_account)` after ingest completes (hygiene —
   the session key is ephemeral, so the grant is dead weight after the agent process exits).
   Later refresh in a new agent run = one fresh grant; credentials themselves are reusable
   indefinitely and rotatable via `RotateSecret`.

### Security posture

- **At rest**: only KGC-sealed ciphertext (on-chain `SecretPayloads`); nothing in localStorage,
  nothing on the agent's disk (it has no disk state).
- **In transit**: ciphertext on-chain; partial decryptions over HTTPS to committee nodes;
  the only plaintext existence is inside the agent process during ingest, in `Zeroizing`
  buffers (`Plaintext` is already a zeroizing, non-printing type in
  `crates/matter-vault-core/src/types.rs`).
- **Authorization**: on-chain grant, auditable; per-request recipient-binding + block-hash
  freshness in `PartialDecryptRequest` (existing MV-C1 anti-replay).
- **What the SDK may persist**: nothing (unchanged — the SDK is stateless).

### Rust consumer helper (nice-to-have)

Embedded consumers (the agent) currently must compose chain-state reads + transport + subset
selection + `open_secret` themselves. A thin

```rust
pub async fn recover_secret(
    committee: &CommitteeInfo, transport: &impl Transport,
    signer: &impl Signer, secret: &EncryptedSecret, aad: Aad,
) -> Result<Plaintext>
```

wrapper (pure composition of existing pieces; no new crypto) would keep the agent's `vault.rs`
to ~a page. Ship if cheap; the agent can inline the composition otherwise.

## Interacts with

| Component | Contract |
|---|---|
| datavisor_v2 | already depends on `@openmatter-network/matter-vault` (seam: `src/lib/kgc/vault.ts`); adds the new `Aad` tag usage + store/grant/revoke calls in the register wizard |
| matter-ml agent | new consumer of the Rust `matter-vault` crate (its side is specced in `matter-ml/docs/data-source-connectors.md`) |
| matter-node | `pallet-secrets` (store/grant/revoke/rotate extrinsics; `SecretsApi::is_authorized` gates KGC partial-decrypts). No `pallet-datasets` coupling in the SDK |
| KGC committee | unchanged transport (`/health`, `/partial-decrypt`) |

## Version-drift caveat (important)

This checkout is `0.1.0` (Rust workspace and TS package), while datavisor pins
`@openmatter-network/matter-vault ^0.9.0` from GitHub Packages — the published line is ahead
of/diverged from this tree. **Before implementing, reconcile**: land the `Aad` addition on
whatever branch actually feeds the published packages, and have the agent depend on the published
crate/tag, not a path to this checkout. The `Aad` registry is append-only, so the addition is
safe on any line.

## Open questions

1. Should the grant target be the agent's *ephemeral* session account (per-run grants, specced
   above) or should the agent grow a persistent identity for standing grants? Ephemeral is
   consistent with the agent's zero-persistence posture; persistent would enable unattended
   scheduled re-ingest later.
2. `recover_secret` helper: ship in this repo or inline in the agent? (Preference: here — a
   second embedded consumer is likely.)
3. Confirm the ed25519 session key is acceptable to the KGC auth path everywhere
   (`MultiSignature::Ed25519` is supported in the wire types; verify node-side verification and
   `is_authorized` account mapping during implementation).
