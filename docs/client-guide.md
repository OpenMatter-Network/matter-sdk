# The OpenMatter client

One `apiKey` in, a client that can do anything that account is entitled to on
MatterChain. This page is the how-to; [`secure-signing.md`](secure-signing.md) is
the *should-I*, and [`parity.md`](parity.md) says which language has what.

## Connecting

Four constructors, four distinct intents. There is deliberately no builder — a
builder would let you set both an API key and a signer and defer "which wins?" to
run time.

| Constructor | Use when | What it can reach |
|---|---|---|
| `connect` | read-only tooling: explorers, dashboards, health checks | every read; no writes |
| `connect_with_api_key` | a key must live in the process: CI, agents, ephemeral workers | every read, plus the writes the key's scopes admit — as the member who minted it |
| `connect_with_signer` | the key is in an HSM, KMS, or remote signer. **Recommended for production.** | as above; a human or org signer reaches everything that account can do |
| `from_env` | you want the environment to decide, including "no key ⇒ read-only" | whichever of the above the environment produced |

A member-tied key is bounded twice: by the runtime's proxy filter, and by the same table
mirrored locally so the refusal names the missing scope. A human seed or HSM key is
bounded only by what its account can do.

Names follow each language's convention (`connectWithApiKey`, `ConnectFromEnv`, …).
**One asymmetry:** Python's bring-your-own-key constructor is `connect_with_keypair`
— it takes an in-process `substrate-interface` keypair (built from a keystore or an
unwrapped KMS blob), not the remote-signer seam the other three offer, so the
key-never-in-process posture is not yet reachable from Python. A `connect_with_signer`
seam there is tracked in [`parity.md`](parity.md#notes--remaining-work).

```rust
use matter_vault::chain::{MatterClient, MatterConfig, Network};
use matter_vault::ApiKey;

let key = ApiKey::parse(&std::env::var("MATTER_API_KEY")?)?;
let client = MatterClient::connect_with_api_key(
    MatterConfig::for_network(Network::Testnet),
    key,
).await?;
```

```ts
import { ApiKey, MatterClient } from "@openmatter-network/matter-client";

const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));
```

```python
from matter_vault import MatterClient

client = MatterClient.from_env()          # MATTER_API_KEY / MATTER_NETWORK / …
```

A read-only client is a legitimate outcome, not an error: `from_env` with no key
set connects anyway, and any attempt to submit returns a typed `ReadOnly` /
`kind: "read-only"` failure rather than a panic or a confusing chain rejection.

### Networks and the mainnet guard

Testnet is the default. A **signing** client refuses to connect to mainnet unless
you set `MATTER_CONFIRM=yes` or pass `confirm_mainnet` / `confirmMainnet: true`.

Two things about that guard are deliberate and worth knowing:

- **It checks what the endpoint actually serves**, not what you configured. A
  testnet config pointed at a mainnet RPC URL fails with `WrongNetwork` — which is
  exactly the hole a config-flag-only check would leave open, and the cheapest
  place to catch a typo'd URL.
- **Read-only mainnet access needs no confirmation.** Reading cannot spend
  anything, so the guard would only be noise.

Detection prefers the genesis hash (spoof-resistant) and falls back to the token
symbol (`MTR` vs `MTR-Test`) — mainnet's genesis hash is not yet pinned because its
RPC endpoint was unreachable when this was written.

## The generic surface

Four methods reach **every** pallet the runtime exposes — 60-plus of them, including
any added by a future forkless upgrade. Nothing is vendored: pallets and calls
resolve by name against the metadata fetched at connect, so this SDK never has to
track `spec_version`.

| Method | Reaches |
|---|---|
| `tx(pallet, call, args)` | any extrinsic; signs, submits, waits for **finalization** |
| `query(pallet, entry, keys)` | any storage entry |
| `runtime_api(…)` | any runtime API |
| `constant(pallet, name)` | any pallet constant |

```rust
client.tx("Communities", "vote_proposal", vec![community, proposal, vote]).await?;
let account = client.query("System", "Account", vec![Value::from_bytes(id)]).await?;
```

Three behaviours to rely on:

- **`tx` waits for finalization, not inclusion.** That is not conservatism: the
  committee authorizes a partial-decrypt against the finalized head, so decrypting
  a secret stored in a merely-included block returns HTTP 403. This was a real bug
  in the TypeScript harness before it was fixed, and the client now enforces the
  lesson structurally rather than by comment.
- **An absent storage entry is `None`/`undefined`, not an error.** An unfunded
  account simply has no `System.Account` row; that is normal control flow.
- **A timeout says the extrinsic may still land.** Resubmitting blindly could apply
  it twice, so the error tells you to check the chain first.

### When a name does not resolve

A rename in a runtime upgrade surfaces as a typed chain error naming the
`pallet.call` — at the call, not silently. `tests/live_chain.rs` is the tripwire
that catches it before a user does:

```bash
cargo test -p matter-vault --features chain --test live_chain -- --ignored
```

## Keys and scopes

An OpenMatter API key acts **for the member who minted it**, not for itself. The client
resolves that at connect and adapts: a member-tied key wraps every write in
`proxy.proxy(member, null, call)`, and a human seed or HSM key signs directly. Nothing
about your calling code changes.

```rust
let client = MatterClient::connect_with_api_key(config, key).await?;
match client.mode() {
    Mode::Delegated { principal, scopes } => // acts for `principal`, bounded by `scopes`
    Mode::Direct => // acts as itself
}
```

At connect the client says which it found, through your logger rather than to your
console:

```
INFO acting for a member principal=5GrwvaEF… scopes="deployments:w, secrets:r"
```

The principal is SS58 in every binding, so it can be compared directly against what the
dashboard showed whoever minted the key. Where the line goes is the host's decision, not
this library's: Rust emits it through `tracing` and says nothing until a subscriber is
installed, Python through the `matter_vault.client` logger, Go through
`Config.Logger` (default `slog.Default()`), and TypeScript through `MatterConfig.logger`
(default the console).

A key you expected to be delegated but which resolves `Direct` is revoked, or was minted
against a different network. That line is the first thing to check, because the chain's
own complaint about it is unhelpful — see below.

**A revoked key stays delegated.** If the grant disappears mid-session, the client does
not fall back to signing for itself: a key with no balance would then fail for want of
fees, and you would read "cannot pay some fees" instead of `KeyRevoked`. It keeps
wrapping, and keeps telling you why.

### Scopes are checked locally first, and that is not paranoia

The runtime is the enforcer; the client mirrors its table only so the error is legible.
A delegated key holds **no balance**, so when the runtime refuses one of its calls the
node rejects the transaction for want of fees. The chain's answer to "your key may not
do that" is therefore `Inability to pay some fees`, which names neither the call nor the
scope. So the client refuses first:

```
key lacks volumes:w for Volumes.retire_volume; it holds deployments:w
```

Two calls need their *arguments* read, not just their names — `Jobs.request_deployment`
and `Jobs.set_deployment_secret_ref` require `secrets:r` on top of `deployments:w` when
they reference a secret, because shipping a secret into a container the key controls is
a read of it. Where the client cannot read the argument it demands the **wider** set: a
spurious local rejection is a nuisance, while the opposite default would let through a
call the chain then refuses.

### A delegated failure is not a silent success

`proxy.proxy` succeeds as an extrinsic even when the call it wrapped fails; the failure
rides in a `Proxy.ProxyExecuted` event. The client unwraps it and returns the error a
direct call would have produced, so a failed delegated call never reads as a win.

### Minting keys

Member-signed — a key can never mint or revoke on itself, because the roster calls are
on the runtime's never-admitted list precisely so it cannot widen its own authority:

```rust
client.keys().authorize(agent_account, "deployments:w".parse()?).await?;
let held = client.keys().lookup(agent_account).await?;   // Option<(principal, scopes)>
client.keys().revoke(agent_account).await?;
```

Only the principal can revoke their own key: the chain answers `NotKeyPrincipal` to
anyone else, an org Owner included.

`authorize` is an upsert, so re-scoping a live key is the same call. Revocation cuts off
the key's committee decrypt rights too, on the next request — with one caveat: a key
that held `secrets:w` may have granted itself per-secret access, and **those grants
survive revocation**. Sweep them.

`MATTER_PRINCIPAL` forces a principal when the chain's pointer is stale but the proxy
still stands. It disables the local scope check (the chain cannot report scopes for a
pointer it has lost), warns loudly, and leaves enforcement entirely to the runtime.

## The curated façades

Typed wrappers for the domains most integrations reach for daily:

| Façade | Backed by |
|---|---|
| `secrets` | `pallet-secrets` — all five calls |
| `deployments` | `pallet-jobs` |
| `resources` | `pallet-resources` |
| `staking` | `pallet_staking` + `NominationPools` |
| `orgs` | `pallet-organizations` + `pallet-budgets` |
| `keys` | `pallet-budgets`' roster calls — mint and revoke API keys |

```rust
client.staking().bond(client.parse_amount("10")?, payee).await?;
client.secrets().revoke(secret_id, &GrantTarget::User(account)).await?;
client.deployments().set_secret_ref(deployment, Some(secret_id)).await?;
```

```ts
await client.staking.bond(client.parseAmount("10"), { Staked: null });
await client.secrets.revoke(secretId, { User: account });
await client.deployments.setSecretRef(deployment, secretId);
```

```python
client.staking.bond(client.parse_amount("10"), {"Staked": None})
client.secrets.revoke(secret_id, grant_to_user(account))
client.deployments.set_secret_ref(deployment, secret_id)
```

```go
amount, _ := client.ParseAmount("10")
client.Staking().Bond(amount, payee)
target, _ := mv.UserTarget(account)
client.Secrets().Revoke(secretID, target)
client.Deployments().SetSecretRef(deployment, &secretID)
```

A façade method is a thin, named wrapper around `tx` — it shapes typed arguments
and delegates. No encoding, no error handling, no chain access of its own, so a
façade can be wrong about a *name* but never about the wire format.

**A façade is a convenience, not a gate.** Anything not covered is one
`client.tx(...)` away, and that is a supported thing to do, not a workaround. The
surface is pinned by `testvectors/facade_calls.json`, replayed both ways in
TypeScript, Python, and Go so that a fixture row without a method fails *and* a
method without a row fails; Rust has no reflection, so its emitter test pins the
same list instead.

`pallet-staking-gateway` is deliberately absent: it is the Ethereum
meta-transaction path, and belongs with the reserved `secp256k1` scheme.

### Grant targets

`secrets.grant` and `secrets.revoke` take a `GrantTarget`, not a bare account:

```rust
GrantTarget::User(account)         // another user or a resource node
GrantTarget::Deployment(id)        // whichever resource is assigned to it
```

The `Deployment` variant exists so an owner can say "whatever runs this
deployment" without naming an account that only exists after assignment. (The
enum is not cosmetic: earlier builders emitted a raw 32-byte grantee, which the
runtime cannot decode — the call data was dead on arrival.)

## Receipts and events

`tx` (and every façade method) resolves at **finalization** with a receipt carrying
the transaction hash, block hash, and the events the extrinsic emitted. Events are
how the chain hands back what it assigned — most importantly the secret id, which
arrives in the `Secrets.SecretStored` event, not as a return value:

- **Rust / Python:** `receipt.emitted("Secrets", "SecretStored")`; Python adds
  `receipt.require_event(...)`, which raises if the event is absent.
- **TypeScript:** the receipt carries `[pallet, event]` name pairs; check with the
  free function `emitted(receipt, "Secrets", "SecretStored")`.
- **Go:** `client.Tx` returns the finalized block hash; decode events from it with
  `ChainClient.FindEvent`, or `FindStoredSecret(blockHash, owner)` +
  `SecretIDFromEvent` for the secret-id case.

Match `SecretStored` on the **owner account**, never on a pre-read of the
`Secrets.NextSecretId` counter — two submitters racing the counter would each
pick up the other's secret. Go's `FindStoredSecret` does the owner-match for you.

## Amounts

**Every amount is an integer count of plancks** — `u128` in Rust, `bigint` in
TypeScript, `int` in Python. There is no float anywhere: a double cannot represent
18 decimal places, and rounding someone's balance is not a risk worth taking for
ergonomics.

```rust
let ten = client.parse_amount("10")?;      // -> plancks
client.format_amount(ten);                  // -> "10"
client.one_token();                         // -> 10^decimals
```

An amount with more fractional digits than the chain supports is **rejected**, not
truncated.

### Which decimal count?

The client exposes two, because they can disagree:

- `token_decimals_declared` — from `system_properties`. **Presentational.** It is
  served from the node's chain-spec *file*, not the runtime, so it can be stale or
  ahead of the deployed wasm.
- `token_decimals_effective` — derived from the live runtime's own
  `Balances.ExistentialDeposit` (`ED == 10^(d-3)`). **Consensus-backed**, and what
  every conversion uses.

This is not academic. matter-node changed `UNIT` from `10^12` to `10^18` **with no
storage migration**, so the same plancks value means amounts a million-fold apart
depending on which runtime is live. When the two disagree the client logs one
warning at connect and trusts the runtime.

## Errors

Branch on the discriminant, never on message text.

Python raises subclasses of `ChainError` with the same names (`NotPermittedError`,
`NeverAdmittedError`, `KeyRevokedError`, `UnsponsoredError`, `DispatchError`); Go
returns a `*ChainError` whose `Kind` carries the same string as the TypeScript column,
matched with `errors.As`.

| Rust `SdkError` | TypeScript `kind` | Meaning |
|---|---|---|
| `ReadOnly` | `read-only` | no signer; build with a key or a signer |
| `Config` | `config` | inconsistent connection config |
| `Chain` | `chain` | a read or submission failed; carries the `pallet.item` |
| `MainnetNotConfirmed` | `mainnet-not-confirmed` | signing client, mainnet, no confirmation |
| `WrongNetwork` | `wrong-network` | the endpoint serves a different chain than configured |
| `FinalityTimeout` | `finality-timeout` | may still land — check before resubmitting |
| `NotPermitted` | `not-permitted` | the key's scopes do not cover this call; names the missing scope |
| `NeverAdmitted` | `never-admitted` | no key may make this call, whatever its scopes |
| `Dispatch` | `dispatch` | the delegated call landed but the wrapped call failed |
| `KeyRevoked` | `key-revoked` | the key's proxy is gone or now points elsewhere; re-authorize it |
| `Unsponsored` | `unsponsored` | neither the member nor their billing org could cover the fee |
| `BadAmount` | (`AmountError`) | not convertible to plancks |
| `Key` | — | key ingestion failed; never echoes the key |

## Escape hatches

A client you cannot escape from is a client that blocks work, so both are exposed
and using them is not a bug report:

- **Rust:** `client.subxt()` and `client.rpc()`.
- **TypeScript:** `client.backend`, or implement `ChainBackend` yourself and pass
  it as `config.backend` — which is also how the client is unit-tested without a
  node.
- **Python:** `client.chain`, the underlying `ChainClient`.
- **Go:** `client.Chain()`, the underlying `ChainClient`.

## Cross-language differences

The surface is the same; the idioms are not.

| | Rust | TypeScript | Python | Go |
|---|---|---|---|---|
| Enabled by | `chain` cargo feature (default **off**) | `@openmatter-network/matter-client` package | `[sdk]` extra | always |
| Amounts | `u128` | `bigint` | `int` | `*big.Int` |
| `tx` args | `Vec<Value>` | `unknown[]` | `dict` | `types.Call` |
| Façade access | `client.secrets()` | `client.secrets` | `client.secrets` | `client.Secrets()` |
| Method names | `snake_case` | `camelCase` | `snake_case` | `PascalCase` |

All four expose the same five façades and the same thirty fixture-pinned methods;
only the naming convention differs, and `testvectors/facade_calls.json` pins the
mapping. Rust adds two typed conveniences on top — `grant_to_user` and
`grant_to_deployment`, thin wrappers that shape a `GrantTarget` and delegate to
`grant`.

Go's amounts are `*big.Int` rather than a fixed integer because `uint64` overflows at
10¹⁸ — a modest balance on this chain does not fit.

Rust gates the chain client behind a cargo feature and TypeScript behind a package
boundary for the same reason expressed two ways: a cargo feature that is off is
genuinely not fetched or compiled, while npm installs any declared dependency — so
in npm the package boundary is the only real opt-out. That keeps
`@openmatter-network/matter-vault` at **zero runtime dependencies**, which CI asserts.
