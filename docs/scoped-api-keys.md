# Scoped API keys: SDK support for runtime spec 322

Status: **Shipped in SDK v1.1.0** (designed 2026-09-07; implemented and verified
against the live testnet 2026-09-08).
Companion (source of truth for the wire contract): `matter-node/docs/api-keys.md`.

Runtime spec 322 is live on testnet, and the dashboard mints member-tied keys
against it. Nothing here is gated on a version number: the client detects support
from metadata — the `BudgetsApi_agent_key` runtime API in Rust and TypeScript,
the `Budgets.authorize_agent_key` call in Python and Go, which read V14 metadata
and cannot see runtime-API declarations. A runtime without them is `Direct` mode,
which is what every pre-322 chain and every human seed still wants.

What was verified against the live runtime, and is re-verified nightly by
`tests/live_chain.rs`: the runtime API and the call both exist, `Proxy.proxy` and
`Proxy.ProxyExecuted` resolve, and every call of all ten scoped pallets is
classified by the local table.

## What changed on chain

An API key is still a raw sr25519 keypair, but its authority moved:

| | Before (spec 287, still live) | After (spec 322) |
|---|---|---|
| Registered by | a project Owner/Admin, on the **project budget** account | the **member** whose account the key acts for, on their own account |
| Proxy type | `ProxyType::Secrets` (secrets calls only, as the budget) | `ProxyType::Scoped(ScopeSet)` — per-group Read/Write bits, as the member |
| Dispatch shape the chain expects | `proxy.proxy(budget, null, secrets.*)` | `proxy.proxy(member, null, call)` for **every** call |
| Who pays gas | the budget | the member's billing org, else the member, never the key |
| Decrypting secrets | the key needs a per-secret `grant_access` to itself | `Secrets:Read` lets the key decrypt whatever the member can |
| Revocation | removes the proxy; existing grants survive | removes the proxy; decrypt cut off on the next request |

The mint/revoke calls are `budgets.authorize_agent_key(key, scopes)` (call
index 23, upsert) and `budgets.revoke_agent_key(key)` (24), signed by the
member. Discovery is the runtime API `BudgetsApi_agent_key(key) ->
Option<(principal, ScopeSet)>`.

## Why the SDK must change

Today `MatterClient::tx` (`crates/matter-vault/src/chain/mod.rs`) builds
`subxt::dynamic::tx(pallet, call, args)` and signs it **as the key's own
account**. It never uses `proxy.proxy`. Under the new model a key's own account
has no authority and no balance: a direct-signed `secrets.store_secret` from a
member-tied key will be rejected in the pool with `Inability to pay some fees`
(the key is balance-less by design) and, even if funded, would store a secret
the key owns rather than the member.

So the client has to learn who it acts for and wrap every write. That is the
whole feature from the SDK's point of view; everything else is consequence.

## Required changes

### 1. Client mode: `Delegated` vs `Direct`

On `connect_with_api_key` / `from_env`, after the metadata is loaded and the
network guards pass, resolve the key:

```
agent_key(key.account_id) via state_call "BudgetsApi_agent_key"
  Some((principal, scopes)) -> Mode::Delegated { principal, scopes }
  None, or the API is absent (spec < 322) -> Mode::Direct (today's behaviour)
```

`Direct` keeps every existing user working: legacy project keys (spec 287) and
human seeds passed as `MATTER_API_KEY` sign exactly as they do now. Log the
resolved mode once at connect (`info!`), because a key that is *meant* to be
delegated but comes back `None` (revoked, or minted on a network the client is
not pointed at) is the first thing anyone will need to see.

- `connect_with_signer` (HSM/KMS path) resolves the mode the same way from the
  signer's account id.
- Expose it: `MatterClient::mode()`, `principal() -> Option<AccountId>`,
  `scopes() -> Option<ScopeSet>`.
- Optional override: `MATTER_PRINCIPAL=<ss58>` forces `Delegated` with that
  principal when the pointer is stale but the proxy still exists (the runtime
  API returns `None` only when the *proxy* is gone, so this is rarely needed;
  keep it for operators, document it as an escape hatch).

Cache the resolution for the life of the client; re-resolve on a
`NotProxy` dispatch error (see §4).

### 2. Wrap writes in `Delegated` mode

In `tx`, when `Mode::Delegated`:

```
outer = subxt::dynamic::tx("Proxy", "proxy", [
    Value::unnamed_variant("Id", [Value::from_bytes(principal)]),   // MultiAddress::Id
    Value::unnamed_variant("None", []),                              // force_proxy_type
    inner_call_value,                                                // the pallet.call(args)
])
```

Build the inner call as a `Value` (subxt's `dynamic::tx` payload can be
converted, or construct the `RuntimeCall` variant `Value::named_variant`
directly by pallet/call name against the metadata). Sign the **outer** call
with the key. Never nest: if the caller asks for `Proxy.*`, `Utility.*` or
`EthSigning.*` in delegated mode, refuse locally (§3) — the chain would refuse
it too.

Batching: the existing "one call per `tx`" surface stays. If a batch helper is
added, it must be a **top-level** `Utility.batch_all([proxy.proxy(principal,
None, c1), proxy.proxy(principal, None, c2), …])` signed by the key. The
runtime sponsors that shape iff every element resolves to the same payer.

### 3. Local scope check before submitting

Mirror the chain's table (`matter-node/docs/api-keys.md`, "What each Write
scope admits") in one function `required_scopes(pallet, call, args) ->
Option<ScopeSet>` and refuse locally with a typed error when the key's set
does not cover it:

```
SdkError::NotPermitted { pallet, call, required: ScopeSet, held: ScopeSet }
```

This is the difference between "your key lacks `Volumes:Write`" and a pool
rejection that reads as "cannot pay fees". Two table rows need the arguments,
not just the name: `Jobs.request_deployment` with `secret_ref` or
`tls_secret_ref` set, and `Jobs.set_deployment_secret_ref` with `Some`, require
`Secrets:Read` in addition to `Deployments:Write`.

Keep the mirror honest with a test that decodes the metadata of a spec-322
node and asserts every call of the ten scoped pallets is classified — the
runtime has the same test on its side
(`required_scopes_table_classifies_every_call_of_the_scoped_pallets`), so the
two cannot drift without one of them failing.

### 4. Receipts and errors

`proxy.proxy` **succeeds as an extrinsic even when the inner call fails**; the
failure is the `Proxy.ProxyExecuted { result: Err(..) }` event. Today's
`wait_for_success` would report success. In delegated mode:

- After finalization, find `ProxyExecuted`; if `result` is `Err`, decode the
  `DispatchError` through the metadata and return
  `SdkError::Dispatch { pallet, call, error }` — the same error a direct call
  would have produced.
- `TxReceipt.events` should list the inner events too; the outer receipt
  otherwise shows only `Proxy.ProxyExecuted` and the fee events.
- Map the two new failure shapes:
  - pool rejection `InvalidTransaction::Payment` in delegated mode → the call
    was not admitted by the key's scopes (or the member and their org cannot
    cover gas). Report as `NotPermitted` when the local table says the scope is
    missing, else as `SdkError::Unsponsored { principal }`.
  - dispatch error `Proxy.NotProxy` → the key was revoked or re-scoped since
    connect; re-resolve the mode once and retry, then surface
    `SdkError::KeyRevoked`.

### 5. `ScopeSet` type (shared, `matter-vault-key`)

```
pub enum Scope { Deployments=0, Collaborations=1, Secrets=2, Volumes=3, Datasets=4,
                 Networking=5, Resources=6, Organization=7, Billing=8, Communities=9 }
pub enum Access { Read=0, Write=1 }
pub struct ScopeSet(u32);   // bit = scope*2 + access; encodes as a bare u32
```

With `contains`, `with`, `is_superset`, `is_valid` (no bits ≥ 20), and a
pinned bit-layout test identical to the runtime's
(`common/src/scopes.rs` in matter-node). Both enums are append-only; never
reorder. Provide a readable `Display` (`deployments:rw, secrets:r`) and a
parser for the same form so CLI flags and env vars can carry it.

### 6. Façades

- **New `Keys` façade** on the client (member-signed, so it is used by a
  human/HSM signer in `Direct` mode, not by a key):
  - `authorize(key: AccountId, scopes: ScopeSet)` → `Budgets.authorize_agent_key`
  - `revoke(key: AccountId)` → `Budgets.revoke_agent_key`
  - `lookup(key: AccountId) -> Option<(AccountId, ScopeSet)>` → runtime API
- `Orgs::authorize_secrets_agent` / `revoke_secrets_agent`
  (`crates/matter-vault/src/chain/facade.rs`) stay, documented as the legacy
  project-tied path.
- `Staking` façade: unreachable from a delegated key (staking is never
  admitted). Make those methods return `NotPermitted` in delegated mode rather
  than submitting a doomed call.
- `Secrets` façade: no call changes, but document that a key needs
  `Secrets:Write` to store/rotate/grant and `Secrets:Read` to decrypt through
  the committee. The `/partial-decrypt` request path is unchanged: the key
  signs as itself, the committee calls `SecretsApi_is_authorized(secret, key)`,
  and the runtime answers for the key as it would for the member.
- `Resources` façade: `report_capacity` and `update_sku` are provider/root
  calls and never admitted; `register`, `set_privacy`, `allow`, `disallow` need
  `Resources:Write`.

### 7. Language bindings (parity per `docs/parity.md`)

| Surface | Rust core | TypeScript client | Python | Go | wasm |
|---|---|---|---|---|---|
| Mode resolution at connect | yes | yes (`#connectBackend`) | yes | yes | n/a (encryptor only) |
| `proxy.proxy` wrapping in `tx` | yes | yes (`#backend.submit`) | yes | yes | n/a |
| `ScopeSet` + local table | `matter-vault-key` | port (small) | native port | native port | n/a |
| `Keys` façade | yes | yes | yes | yes | n/a |
| `ProxyExecuted` unwrap | yes | yes | yes | yes (`TxAndWait`) | n/a |
| `MATTER_PRINCIPAL` | yes | yes | yes | yes | n/a |

TypeScript's `runtimeApi(method, argsHex)` (`packages/typescript-client/src/client.ts`)
already takes a `state_call` name; `BudgetsApi_agent_key` takes the 32-byte
account as its SCALE argument and returns `Option<(AccountId32, u32)>`.

### 8. Docs and examples

- `docs/client-guide.md`: a "Keys and scopes" section (mode, wrapping, local
  check, error mapping); the "Connecting" table gains a column for what a
  delegated key can reach.
- `docs/agent-credential-delivery.md`: the credential is now
  `(key seed, principal, scopes)`; the dashboard shows all three at mint.
- `README.md` quick start: `MATTER_API_KEY` unchanged; add the one-line
  "your key acts as the member who minted it" model statement.
- `examples/`: one delegated-key example that stores a secret, reads it back
  through the committee, and shows a `NotPermitted` error for an out-of-scope
  call.

## Tests

- Unit: bit layout pinned; `required_scopes` mirror covers every call name in
  a checked-in spec-322 metadata fixture; wrapping produces the exact
  `Proxy.proxy(MultiAddress::Id(principal), None, inner)` encoding; `None` from
  the runtime API yields `Direct`.
- Integration (dev node, `matter-node` built at spec ≥ 322): mint Ferdie as
  Alice's key with `Deployments:Write`; delegated `jobs.cancel_deployment` is
  finalized with `ProxyExecuted(Err(DeploymentNotFound))` surfaced as a
  dispatch error and Alice paying; `balances.transfer_all` refused locally as
  `NotPermitted`; re-scope to `Secrets:Read` and confirm a `/partial-decrypt`
  style authorization via `SecretsApi_is_authorized`; revoke and confirm
  `KeyRevoked`. That lives in `crates/matter-vault/tests/scoped_keys_dev.rs`,
  driven against `./target/release/matter-node --dev`.
  `examples/delegated-e2e` walks the same path against a real network, with a
  key you cannot mint for yourself.

## Sequencing

1. Land the runtime (spec 322) on testnet; publish `metadata.scale`.
2. Ship the SDK with mode resolution defaulting to `Direct` when the API is
   absent — safe against any older network.
3. The dashboard switches minting to member-tied keys (its own doc).
4. Deprecate `Direct` mode for keys after mainnet is on 322: warn at connect
   when a key has a balance and no principal.

## Open questions

- Should `Direct` mode be refused outright for a key that *has* a principal
  pointer but whose proxy is gone (`agent_key == None`)? Recommendation: no —
  connect read-only and log; the operator decides.
- Per-call `force_proxy_type`: the runtime accepts `Some(Scoped(exact set))`
  as well as `None`. `None` is simpler and is what the runtime tests pin; use
  `None` unless a member has deliberately given the same key two proxies,
  which the registrar refuses anyway.

## Deviations from this design, and why

Four things landed differently from the plan above. Each was a deliberate call.

- **`ScopeSet` lives in `matter-vault-key`, not `matter-vault-core`.** It is not
  cryptography, and the key crate is where the account and signer types it sits
  beside already are.
- **Python and Go port the table rather than reaching it through FFI.** A scope
  set is not cryptography, so it does not belong behind `matter-vault-ffi` — and
  the two argument-sensitive rows could not cross that boundary anyway without
  shipping the whole dynamic argument tree with them. `scope_bits.json` and
  `required_scopes.json` keep the four honest instead.
- **`MATTER_PRINCIPAL` assumes every scope.** The override exists for a stale
  pointer, so it cannot ask the chain what the key may do. Assuming the empty set
  would refuse every call locally and make the escape hatch useless, so the
  override turns the local check off and lets the runtime decide alone. It warns
  when it does.
- **The `Staking` façade needed no special case.** Staking has no row in the
  table, so it is already `NeverAdmitted` — both accurate and a better message
  than `NotPermitted` would have been.

## What a revoked key does, and does not do

A key whose grant is gone stays in `Delegated` mode. It would be easy to reset it
to `Direct` and let it sign for itself, and that would be wrong: the key holds no
balance, so the next call would fail in the pool for want of fees, and the caller
would read "cannot pay some fees" instead of "your key was revoked". The client
keeps wrapping, keeps failing, and keeps saying why.

The same reasoning drives the detection rule. "This chain has no scoped keys" is
read from metadata, which is a fact held locally; a lookup that *failed* is not a
fact at all, and reporting it as "no delegation" would resolve a delegated client
to `Direct` on a dropped connection and produce exactly that unexplained fee
error one call later.
