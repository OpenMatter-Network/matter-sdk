# The chain surface

Four generic methods reach every pallet the MatterChain runtime exposes. They resolve
pallets, calls, storage entries and runtime APIs **by name** against the metadata the
client fetched when it connected. A pallet added by a forkless runtime upgrade works
the moment the upgrade lands, with no SDK release.

| Method | Reaches | Returns |
|---|---|---|
| `tx(pallet, call, args)` | any extrinsic | a [receipt](#receipts-and-events), once the block is **finalized** |
| `query(pallet, entry, keys)` | any storage entry | the decoded value, or none when absent |
| `runtime_api(…)` | any runtime API | the result |
| `constant(pallet, name)` | any pallet constant | the value |

The [façades](README.md#guides) are typed wrappers over `tx` for the calls most
integrations need. Use `tx` for everything else.

## Writing: `tx`

Pallet names are spelled as the metadata spells them (`Jobs`, `Secrets`,
`NominationPools`), and call names in snake_case (`cancel_deployment`). Each language
passes arguments in its chain library's native form:

| | Arguments are | Example |
|---|---|---|
| Rust | `Vec<Value>` (subxt's dynamic `Value`), positional | `vec![Value::u128(id)]` |
| TypeScript | an array in @polkadot/api's JS form, positional | `[id]` |
| Python | a `dict` of named params in substrate-interface's form | `{"deployment": id}` |
| Go | `Call(pallet, method, args...)` with GSRPC-encodable values | `types.NewU128(*id.BigInt())` |

```rust
use matter_sdk::chain::Value;

let receipt = client
    .tx("Communities", "vote_proposal", vec![community, proposal, vote])
    .await?;
```

```ts
const receipt = await client.tx("Staking", "bond", [client.parseAmount("10"), { Staked: null }]);
```

```python
receipt = client.tx("Jobs", "cancel_deployment", {"deployment": deployment})
```

```go
receipt, err := client.Call("Staking", "chill")
```

What `tx` guarantees:

- **It waits for finalization, not inclusion.** The committee authorizes decryption
  against the finalized head. A write that is only included looks absent to the
  committee.
- **It is bounded.** After two minutes (set with `finality_timeout` / `finalityTimeoutMs`
  / `FinalityTimeout`) it fails with `FinalityTimeout`. The extrinsic may still land, so
  check the chain before you resubmit. Python takes the budget as `finality_timeout=`
  in seconds.
- **It signs through your signer**, whether that is an in-process `ApiKey` or a
  [`KeySigner`](secure-signing.md) over an HSM.
- **It respects scoped keys.** Under a [scoped key](keys-and-scopes.md#scoped-keys) the
  call is checked against the key's scopes, wrapped in `Proxy.proxy`, and a failure
  inside the proxy comes back as a `Dispatch` error instead of a silent success.
- **It refuses on a read-only client** with `ReadOnly`.

Go has two lower-level forms: `TxAndWait(types.Call)` submits a prebuilt call and waits
for finalization, and `Tx(types.Call)` returns the hash without waiting.

### When a name does not resolve

A pallet, call or entry the runtime does not have fails **before** anything is signed.
Every language reports a `Chain` error that names the target, e.g.
`Jobs.cancel_deploymnt`, for writes and reads alike. Under a scoped key, an unknown call in a scoped pallet
is refused first, as `NeverAdmitted`. Check the
spelling against the runtime's metadata; `spec_version` on
[`properties`](connecting.md#chain-properties) tells you which runtime you are talking to.

## Reading: `query`, `runtime_api`, `constant`

```rust
let account = client
    .query("System", "Account", vec![Value::from_bytes(account_id)])
    .await?; // Option<DecodedValue>
let nodes = client.runtime_api("KgcApi", "kgc_nodes", vec![]).await?;
let deposit = client.constant("Balances", "ExistentialDeposit")?;
```

```ts
const account = await client.query("System", "Account", [client.accountId]); // undefined if absent
const epoch = await client.runtimeApi("KgcApi_dkg_epoch"); // SCALE result as 0x-hex
const deposit = client.constant("Balances", "ExistentialDeposit");
```

```python
account = client.query("System", "Account", [client.address])  # None if absent
epoch = client.runtime_api("KgcApi_dkg_epoch", return_type="u32")
deposit = client.constant("Balances", "ExistentialDeposit")
```

```go
raw, err := client.QueryRaw("Secrets", "NextSecretId")            // SCALE bytes
var info types.AccountInfo
found, err := client.Query(&info, "System", "Account", accountID)  // decode into a type
epoch, err := client.RuntimeAPI("KgcApi_dkg_epoch", nil)           // SCALE bytes
deposit, err := client.Constant("Balances", "ExistentialDeposit")  // SCALE bytes
```

- **Absent is not an error.** An entry with nothing stored, such as an unfunded
  account's `System.Account`, reads as `None` / `undefined` / `None` / `found == false`,
  even when the runtime declares a default for it. A stored zero is a value, not absent.
- **Runtime APIs are named differently.** Rust takes the trait and method separately
  (`"KgcApi", "kgc_nodes"`). TypeScript, Python and Go take the `state_call` name
  (`"KgcApi_kgc_nodes"`) with SCALE-encoded arguments. TypeScript returns hex and Go
  returns bytes; Python decodes to `return_type`.
- **Reads need no key** and work on a read-only client.

## Receipts and events

Every write resolves to a receipt for the finalized block:

| | Receipt | Events | Look up an event |
|---|---|---|---|
| Rust | `TxReceipt { tx_hash, block_hash, events }` | `(pallet, event)` names | `receipt.emitted("Secrets", "SecretStored")` |
| TypeScript | `TxReceipt { txHash, blockHash, events }` | `[pallet, event]` names | `emitted(receipt, "Secrets", "SecretStored")` |
| Python | `TxReceipt` | `(pallet, event, attributes)` | `receipt.emitted(...)`, `receipt.require_event(...)` returns the attributes |
| Go | `TxReceipt { TxHash, BlockHash, ExtrinsicIndex, Events }` | `Event { Pallet, Name, Fields }` with decoded fields | `receipt.Emitted("Secrets", "SecretStored")` |

Only the extrinsic's own events are included. Go additionally has block-level helpers:
`EventsAt`, `FindEvent`, `SecretIDFromEvent` and `FindStoredSecret`. For anything wider,
such as subscribing to new blocks, use the underlying client (see
[escape hatches](#escape-hatches)).

## Amounts

Every amount in the SDK is an integer number of **plancks**, the chain's smallest unit.
The helpers convert between plancks and human-readable text **without floating point**:

| | Parse | Format | One token |
|---|---|---|---|
| Rust | `client.parse_amount("1.5")?` → `u128` | `client.format_amount(plancks)` | `client.one_token()` |
| TypeScript | `client.parseAmount("1.5")` → `bigint` | `client.formatAmount(plancks)` | `client.oneToken()` |
| Python | `client.parse_amount("1.5")` → `int` | `client.format_amount(plancks)` | `client.one_token()` |
| Go | `client.ParseAmount("1.5")` → `*big.Int` | `client.FormatAmount(plancks)` | `client.OneToken()` |

The client methods use the chain's
[effective decimal count](connecting.md#chain-properties). Free functions that take
`decimals` explicitly exist too: `parse_amount` / `format_amount` / `one_token` (Rust,
under `matter_sdk::chain`), `parseAmount` / `formatAmount` / `oneToken` (TypeScript),
`parse_amount` / `format_amount` (Python), and `mattersdk.ParseAmount` /
`FormatAmount` (Go).

Parsing is strict. It accepts digits with an optional fraction and an optional leading
`+`. It rejects negatives, exponents, hex, thousands separators, `1.` and `.5`. **Too many
fractional digits is an error, never a silent truncation.** Formatting is lossless and
trims trailing zeros.

## Escape hatches

When the generic surface is not enough, reach the underlying library:

| | What you get |
|---|---|
| Rust | `client.subxt()` (the `OnlineClient`) and `client.rpc()` (legacy RPC methods): subscriptions, historic blocks, custom RPCs |
| TypeScript | inject your own `ChainBackend` (for example, one that owns an @polkadot/api `ApiPromise`) through `MatterConfig.backend`; `client.backend` returns it |
| Python | `client.chain`, a `ChainClient` over substrate-interface, with committee and secret readers |
| Go | `client.Chain()`, a `ChainClient` over GSRPC, with readers, `SubmitCall`, `SubmitAndWatch` and event helpers; `PrepareExtrinsic` builds an unsigned extrinsic and its `SigningPayload` for fully offline or air-gapped signing |

Go builds and signs extrinsics itself, walking every signed extension the runtime
declares. It refuses to sign an extension it does not know, rather than produce a
transaction the chain would reject.
