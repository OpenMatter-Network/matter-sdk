# The OpenMatter client

How to use the client. [`secure-signing.md`](secure-signing.md) covers where the key
should live; [`parity.md`](parity.md) covers which language has what.

## Connecting

Four constructors, one per intent. There is no builder, so an API key and a signer can
never both be set.

| Constructor | Use when | What it can reach |
|---|---|---|
| `connect` | read-only tooling: explorers, dashboards, health checks | every read; no writes |
| `connect_with_api_key` | a key must live in the process: CI, agents, ephemeral workers | every read, plus the writes the key's scopes admit, as the member who minted it |
| `connect_with_signer` | the key is in an HSM, KMS, or remote signer. **Recommended for production.** | as above; a human or org signer reaches everything that account can do |
| `from_env` | the environment decides, including "no key ⇒ read-only" | whichever of the above the environment produced |

Names follow each language's convention (`connectWithApiKey`, `ConnectFromEnv`, …).
Python takes an in-process keypair (`connect_with_keypair`); see
[parity](parity.md#notes--remaining-work).

```rust
use matter_sdk::chain::{MatterClient, MatterConfig, Network};
use matter_sdk::ApiKey;

let key = ApiKey::parse(&std::env::var("MATTER_API_KEY")?)?;
let client = MatterClient::connect_with_api_key(
    MatterConfig::for_network(Network::Testnet),
    key,
).await?;
```

```ts
import { ApiKey, MatterClient } from "@openmatter-network/matter-sdk";

const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));
```

```python
from matter_sdk import MatterClient

client = MatterClient.from_env()          # MATTER_API_KEY / MATTER_NETWORK / …
```

`from_env` with no key connects read-only; any submit then fails with a typed
`ReadOnly` / `kind: "read-only"` error.

### Networks and the mainnet guard

Testnet is the default. A **signing** client refuses mainnet unless you set
`MATTER_CONFIRM=yes` or pass `confirm_mainnet` / `confirmMainnet: true`.

- **It checks what the endpoint serves**, not what you configured: a testnet config
  pointed at a mainnet RPC URL fails with `WrongNetwork`.
- **Read-only mainnet access needs no confirmation.**

Detection uses the genesis hash (spoof-resistant) and falls back to the token symbol
(`MTR` vs `MTR-Test`) while mainnet's genesis hash is unpinned.

## The generic surface

Four methods reach every pallet the runtime exposes, including any added by a forkless
upgrade. Pallets and calls resolve by name against the metadata fetched at connect.

| Method | Reaches |
|---|---|
| `tx(pallet, call, args)` | any extrinsic; signs, submits, waits for **finalization** |
| `query(pallet, entry, keys)` | any storage entry |
| `runtime_api(…)` | any runtime API |
| `constant(pallet, name)` | any pallet constant |

Go spells the by-name write `Call(pallet, method, args...)`. Its `Tx` takes a prebuilt
`types.Call` and returns without waiting; `TxAndWait` waits.

```rust
client.tx("Communities", "vote_proposal", vec![community, proposal, vote]).await?;
let account = client.query("System", "Account", vec![Value::from_bytes(id)]).await?;
```

- **`tx` waits for finalization, not inclusion.** The committee authorizes a
  partial-decrypt against the finalized head, so decrypting a secret stored in a
  merely-included block returns HTTP 403.
- **An absent storage entry is `None`/`undefined`, not an error.**
- **A timeout means the extrinsic may still land.** Check the chain before resubmitting.

### When a name does not resolve

A runtime rename surfaces as a typed chain error naming the `pallet.call`.
`tests/live_chain.rs` checks every curated name against the live chain:

```bash
cargo test -p matter-sdk --features chain --test live_chain -- --ignored
```

## Keys and scopes

An API key acts **for the member who minted it**. At connect the client resolves which
kind of key it holds: a member-tied key wraps every write in
`proxy.proxy(member, null, call)`; a human seed or HSM key signs directly. Calling code
is the same either way.

```rust
let client = MatterClient::connect_with_api_key(config, key).await?;
if let Mode::Delegated { principal, scopes } = client.mode() {
    // acts for `principal`, bounded by `scopes`
} else {
    // acts as itself
}
```

(`Mode` is `#[non_exhaustive]`, so match it with `if let` or a trailing `_` arm.)

The accessors are `mode()`, `principal()`, `scopes()` in Rust; `mode`, `principal`,
`scopes` in TypeScript; `is_delegated`, `principal`, `scopes` in Python; `IsDelegated()`,
`Principal()`, `Scopes()` in Go.

At connect the client logs what it found:

```
INFO acting for a member principal=5GrwvaEF… scopes="deployments:w, secrets:r"
```

The principal is SS58 in every binding. The line goes to the host's logger: Rust via
`tracing` (silent without a subscriber), Python via the `matter_sdk.client` logger, Go
via `Config.Logger` (default `slog.Default()`), TypeScript via `MatterConfig.logger`
(default the console).

A key you expected to be delegated that resolves `Direct` is revoked or was minted
against a different network. Check this line first.

**A revoked key stays delegated.** If the grant disappears mid-session the client keeps
wrapping and reports `KeyRevoked`, rather than signing for itself and failing on fees. At
connect, a delegation lookup that fails is an error, never a fallback to `Direct`; only a
successful lookup (no grant, or metadata showing no scoped keys) resolves `Direct`.

### Scopes are checked locally first

The runtime enforces scopes; the client mirrors its table so the error is legible. A
delegated key holds no balance, so a runtime refusal surfaces as `Inability to pay some
fees`. The client refuses first instead:

```
key lacks volumes:w for Volumes.retire_volume; it holds deployments:w
```

`Jobs.request_deployment` and `Jobs.set_deployment_secret_ref` also require `secrets:r`
when they reference a secret, since shipping a secret into a container the key controls
is a read of it. When the client cannot read the argument it demands the **wider** set.

Calls outside the ten scoped pallets (staking among them), node-operator reports, and
the key roster are **never admitted** for a scoped key, whatever its scopes
(`NeverAdmitted`, not `NotPermitted`). Use a directly-signing key for them.

Every binding carries the same scope table, pinned by `scope_bits.json` and
`required_scopes.json` (see [`testvectors/`](../testvectors/README.md)).

### A delegated failure is not a silent success

`proxy.proxy` succeeds as an extrinsic even when the wrapped call fails; the failure is
in a `Proxy.ProxyExecuted` event. The client unwraps it and returns the error a direct
call would have produced.

### Minting keys

Member-signed only. The roster calls are never admitted for a key, so a key cannot widen
its own authority:

```rust
client.keys().authorize(agent_account, "deployments:w".parse()?).await?;
let held = client.keys().lookup(agent_account).await?;   // Option<(principal, scopes)>
client.keys().revoke(agent_account).await?;
```

Only the principal can revoke their key; anyone else, an org Owner included, gets
`NotKeyPrincipal`.

`authorize` is an upsert, so it also re-scopes a live key. Revocation also removes the
key's committee decrypt rights on the next request, but per-secret grants a `secrets:w`
key made to itself **survive revocation**. Sweep them.

`MATTER_PRINCIPAL` forces a principal when the chain's pointer is stale but the proxy
still stands. It disables the local scope check, warns, and leaves enforcement to the
runtime.

## The curated façades

| Façade | Backed by |
|---|---|
| `secrets` | `pallet-secrets` (all five calls) |
| `deployments` | `pallet-jobs` |
| `resources` | `pallet-resources` |
| `staking` | `pallet_staking` + `NominationPools` |
| `orgs` | `pallet-organizations` + `pallet-budgets` |
| `keys` | `pallet-budgets` roster calls: mint and revoke API keys |

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
target, _ := mattersdk.UserTarget(account)
client.Secrets().Revoke(secretID, target)
client.Deployments().SetSecretRef(deployment, &secretID)
```

`Deployments::request` takes the runtime's `ResourceRequest` as a `Value`. A
QuantumGuard-guarded deployment (requires runtime spec ≥ 324) is the stock image plus
the engine as a read-only image volume, the supervisor as the launcher, the policy
commitment, and `privileged`; the guard's key travels only inside the sealed env that
`secret_ref` names. All twelve request fields are required.

```rust
use matter_sdk::chain::Value;

fn quantum_guard_request(treasury: [u8; 32], sealed_env: u128, policy_root: [u8; 32]) -> Value {
    let none = || Value::unnamed_variant("None", []);
    let some = |v: Value| Value::unnamed_variant("Some", [v]);
    let engine = "ghcr.io/openmatter-network/quantum-guard/engine@sha256:…";

    let container = Value::named_composite([
        ("image", Value::from_bytes("nousresearch/hermes-agent")),
        ("tag", Value::from_bytes("latest")),
        (
            "ports",
            some(Value::unnamed_composite([Value::named_composite([
                ("container_port", Value::u128(8089)),
                ("protocol", Value::unnamed_variant("Tcp", [])),
            ])])),
        ),
        // The engine, mounted read-only from its own image.
        (
            "volumes",
            some(Value::unnamed_composite([Value::named_composite([
                ("name", Value::from_bytes("zkfw-engine")),
                ("target", Value::from_bytes("/opt/zkfw")),
                (
                    "source",
                    some(Value::named_variant(
                        "Image",
                        [("reference", Value::from_bytes(engine))],
                    )),
                ),
            ])])),
        ),
        ("command", none()),
        ("privileged", some(Value::bool(true))),
    ]);

    Value::named_composite([
        (
            "config",
            Value::unnamed_variant("ContainerRequest", [container]),
        ),
        ("expiration", none()),
        ("requirements", Value::u128(1)),
        ("treasury", Value::from_bytes(treasury)),
        ("private_resources_only", Value::bool(false)),
        ("allowed_resources", none()),
        ("simple_env_vars", none()),
        ("secret_ref", some(Value::u128(sealed_env))),
        ("tls_secret_ref", none()),
        (
            "launch",
            some(Value::named_composite([
                (
                    "launcher",
                    some(Value::unnamed_composite([Value::from_bytes(
                        "/opt/zkfw/zkfw-sandboxd",
                    )])),
                ),
                ("user", some(Value::from_bytes("0"))),
            ])),
        ),
        ("policy_root", some(Value::from_bytes(policy_root))),
        ("restart_policy", none()),
    ])
}

client.deployments().request(quantum_guard_request(treasury, sealed_env, policy_root)).await?;
```

[`tests/guide_examples.rs`](../crates/matter-sdk/tests/guide_examples.rs) compiles this
code and encodes it against spec-330 metadata.

`policy_root` is the BLAKE3 of the sealed policy envelope (stored off chain). Its DEK is
a `pallet-secrets` secret (`Aad::QuantumGuardPolicyDekV1`) with a `User` grant for the
guard's key; the guard recovers it with `Secrets::recover`. To publish a new policy,
upload it and call `client.tx("Jobs", "set_deployment_policy_root", …)`. The guard adopts
hot fields in place; a boot-time field stays pending until `set_deployment_launch` is
re-sent with the same launch, which the provider treats as a restart.

A façade method only shapes typed arguments and delegates to `tx`; it does no encoding
or error handling of its own. Anything not covered is one `client.tx(...)` away, which is
supported. The surface is pinned by `testvectors/facade_calls.json` (see
[`testvectors/`](../testvectors/README.md)).

`pallet-staking-gateway` (the Ethereum meta-transaction path) is excluded until the
reserved `secp256k1` scheme lands.

### Grant targets

`secrets.grant` and `secrets.revoke` take a `GrantTarget`, not a bare account:

```rust
GrantTarget::User(account)         // another user or a resource node
GrantTarget::Deployment(id)        // whichever resource is assigned to it
```

`Deployment` names "whatever runs this deployment" before that account exists.

## Receipts and events

`tx` and every façade method resolve at **finalization** with a receipt carrying the
transaction hash, block hash, and emitted events. The secret id arrives in the
`Secrets.SecretStored` event, not as a return value:

- **Rust / Python:** `receipt.emitted("Secrets", "SecretStored")`; Python also has
  `receipt.require_event(...)`, which raises if the event is absent.
- **TypeScript:** `emitted(receipt, "Secrets", "SecretStored")`.
- **Go:** `receipt.Emitted("Secrets", "SecretStored")` on the `TxReceipt`; read the id
  with `client.Chain().FindStoredSecret(receipt.BlockHash, owner)`.

Match `SecretStored` on the **owner account**, never on a pre-read of
`Secrets.NextSecretId`: concurrent submitters would pick up each other's secret.

## Amounts

**Every amount is an integer count of plancks**: `u128` in Rust, `bigint` in
TypeScript, `int` in Python, `*big.Int` in Go (`uint64` overflows at 10¹⁸). Never a float.

```rust
let ten = client.parse_amount("10")?;      // -> plancks
client.format_amount(ten);                  // -> "10"
client.one_token();                         // -> 10^decimals
```

More fractional digits than the chain supports is **rejected**, not truncated.

### Which decimal count?

- `token_decimals_declared`: from `system_properties`. **Presentational**; it comes from
  the node's chain-spec file and can disagree with the deployed runtime.
- `token_decimals_effective`: derived from the runtime's `Balances.ExistentialDeposit`
  (`ED == 10^(d-3)`). **Consensus-backed**, and what every conversion uses.

When they disagree the client logs one warning at connect and uses the effective value.

## Errors

Branch on the type or kind, never on message text. TypeScript throws `ClientError` with
a `kind`; Go returns `*ChainError` whose `Kind` is the same string (match with
`errors.As`); Python raises a subclass of `ChainError`.

| Rust `SdkError` | TypeScript `kind` / Go `Kind…` | Python | Meaning |
|---|---|---|---|
| `ReadOnly` | `read-only` / `KindReadOnly` | `ReadOnlyError` | no signer; build with a key or a signer |
| `Config` | `config` / `KindConfig` | `ConfigError` | inconsistent connection config |
| `Chain` | `chain` / `KindChain` | `ChainError` | a read or submission failed; carries the `pallet.item` |
| `MainnetNotConfirmed` | `mainnet-not-confirmed` / `KindMainnetNotConfirmed` | `MainnetNotConfirmedError` | signing client, mainnet, no confirmation |
| `WrongNetwork` | `wrong-network` / `KindWrongNetwork` | `WrongNetworkError` | the endpoint serves a different chain than configured |
| `FinalityTimeout` | `finality-timeout` / `KindFinalityTimeout` | — (waits without a deadline) | may still land — check before resubmitting |
| `NotPermitted` | `not-permitted` / `KindNotPermitted` | `NotPermittedError` | the key's scopes do not cover this call; names the missing scope |
| `NeverAdmitted` | `never-admitted` / `KindNeverAdmitted` | `NeverAdmittedError` | no key may make this call, whatever its scopes |
| `Dispatch` | `dispatch` / `KindDispatch` | `DispatchError` | the delegated call landed but the wrapped call failed |
| `KeyRevoked` | `key-revoked` / `KindKeyRevoked` | `KeyRevokedError` | the key's proxy is gone or now points elsewhere; re-authorize it |
| `Unsponsored` | `unsponsored` / `KindUnsponsored` | `UnsponsoredError` | neither the member nor their billing org could cover the fee |
| `BadAmount` | `AmountError` / a plain error from `ParseAmount` | `ValueError` | not convertible to plancks |
| `Key` | — / `ErrBadAPIKey` | `ValueError` | key ingestion failed; never echoes the key |
| `Scope` | an `Error` from `ScopeSet.parse` / a plain error from `ParseScopeSet` | `ValueError` | a scope string did not parse |

## Escape hatches

- **Rust:** `client.subxt()` and `client.rpc()`.
- **TypeScript:** `client.backend`, or pass your own `ChainBackend` as `config.backend`
  (also how the client is unit-tested without a node).
- **Python:** `client.chain`, the underlying `ChainClient`.
- **Go:** `client.Chain()`, the underlying `ChainClient`.

## Cross-language differences

| | Rust | TypeScript | Python | Go |
|---|---|---|---|---|
| Enabled by | `chain` cargo feature (default **off**) | `@openmatter-network/matter-sdk` package | `[sdk]` extra | always |
| Amounts | `u128` | `bigint` | `int` | `*big.Int` |
| Generic write | `tx(pallet, call, Vec<Value>)` | `tx(pallet, call, unknown[])` | `tx(pallet, call, dict)` | `Call(pallet, method, args...)` |
| Façade access | `client.secrets()` | `client.secrets` | `client.secrets` | `client.Secrets()` |
| Method names | `snake_case` | `camelCase` | `snake_case` | `PascalCase` |

`testvectors/facade_calls.json` pins the method-name mapping. Rust adds
`grant_to_user` and `grant_to_deployment`, thin wrappers over `grant`.
