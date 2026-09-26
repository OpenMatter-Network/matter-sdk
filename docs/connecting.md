# Connecting

Every chain operation starts with a `MatterClient`. How you build it decides what it can do:
read only, sign with an API key, or sign with a key that never enters your process.

## Pick a constructor

There is one constructor per intent and no builder, so an API key and a signer can never
both be set on one client.

| Constructor | Use it when | The client can |
|---|---|---|
| `connect` | explorers, dashboards, health checks | read everything; any submit fails with `ReadOnly` |
| `connect_with_api_key` | the key must live in the process: CI, agents, workers | read, and submit as the key's account (or, for a [scoped key](keys-and-scopes.md#scoped-keys), as the member who minted it) |
| `connect_with_signer` | the key lives in an HSM, KMS, wallet, or remote signer. **Recommended for production.** | the same, but the SDK only ever sees signatures ([secure signing](secure-signing.md)) |
| `from_env` | the environment decides | whichever of the above the [environment variables](#environment-variables) select; no key means read-only |

Names follow each language's convention:

| | Rust | TypeScript | Python | Go |
|---|---|---|---|---|
| read-only | `MatterClient::connect(config)` | `MatterClient.connect(config?)` | `MatterClient.connect(network=, rpc_url=)` | `mattersdk.Connect(cfg)` |
| API key | `connect_with_api_key(config, key)` | `connectWithApiKey(key, config?)` | `connect_with_api_key(key, ...)` | `ConnectWithApiKey(cfg, key)` |
| signer | `connect_with_signer(config, Arc<dyn KeySigner>)` | `connectWithSigner(signer, config?)` | `connect_with_keypair(keypair, ...)` | `ConnectWithSigner(cfg, ExtrinsicSigner)` |
| environment | `from_env()` | `fromEnv(config?)` | `from_env()` | `ConnectFromEnv()` |

Python's signer seam takes a `substrate-interface` keypair-shaped object (its `sign()`
can be remote), and Go's `ConnectFromEnv` also returns the `*ApiKey`, which you
`Close()`. See [parity](parity.md).

```rust
use matter_sdk::chain::{MatterClient, MatterConfig, Network};
use matter_sdk::ApiKey;

let key = ApiKey::parse(&std::env::var("MATTER_API_KEY")?)?;
let client =
    MatterClient::connect_with_api_key(MatterConfig::for_network(Network::Testnet), key).await?;
```

```ts
import { ApiKey, MatterClient } from "@openmatter-network/matter-sdk";

const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));
```

```python
from matter_sdk import MatterClient

with MatterClient.from_env() as client:  # MATTER_API_KEY, MATTER_NETWORK, ...
    print(client.address)
```

```go
client, key, err := mattersdk.ConnectFromEnv()
if err != nil {
	return err
}
defer client.Close()
if key != nil {
	defer key.Close()
}
```

Rust needs the `chain` cargo feature; Python needs the `[sdk]` extra. Close the client when
you are done: `disconnect()` (TypeScript), `close()` or a `with` block (Python), `Close()`
(Go). Rust drops it.

## Networks

| Network | Default RPC | Token |
|---|---|---|
| `testnet` (default everywhere) | `wss://node2.testnet.openmatter.network` | `MTR-Test` |
| `mainnet` | `wss://node2.mainnet.openmatter.network` | `MTR` |
| `custom` | none: you must give an RPC URL | whatever the node reports |

Set an explicit endpoint with `MatterConfig::for_url` (Rust), `rpcUrl` (TypeScript),
`rpc_url=` (Python), or `Config.RPCURL` (Go). A local dev node is a `custom` network.

## The mainnet guard

A client that can **sign** refuses to connect to mainnet until you confirm it with
`MATTER_CONFIRM=yes` or in code (`confirm_mainnet` / `confirmMainnet: true` /
`ConfirmMainnet: true`). An accidental production write takes two mistakes, not one.

- **The guard checks what the endpoint serves, not what you configured.** A `testnet`
  config pointed at a mainnet URL fails with `WrongNetwork`.
- **Detection reads the chain.** The client compares the endpoint's genesis hash against
  the pinned testnet genesis
  (`0xd87ca10ad40194ff37525c0b5fc5997d94010107a399d03bf5672c0a7b30f058`) and recognises
  mainnet by its token symbol (`MTR`). The mainnet genesis hash joins the pin once the
  mainnet endpoint serves it ([parity](parity.md#roadmap)).
- **Read-only clients need no confirmation.** Reading mainnet state is always safe.

## Chain properties

The client reads the chain's identity once at connect and exposes it as `properties`
(`Properties()` in Go):

| Field | Meaning |
|---|---|
| `genesis_hash` | block 0's hash: `[u8; 32]` in Rust, a `0x`-prefixed string elsewhere |
| `chain_name` | e.g. `MatterChain Testnet` |
| `spec_version` | the live runtime's version |
| `token_symbol` | `MTR` or `MTR-Test` |
| `ss58_prefix` | address format, 42 unless the node says otherwise |
| `token_decimals_effective` | decimals derived from the runtime; **every amount conversion uses this** |
| `token_decimals_declared` | decimals from the node's chain-spec file; presentational only |
| `existential_deposit` | `Balances.ExistentialDeposit`, in plancks |

The effective decimal count comes from consensus: the runtime sets
`ExistentialDeposit = 10^(decimals − 3)`. The declared count comes from a file the node
operator ships and can go stale. When they disagree, the client logs a warning once and
follows the runtime. Check it with `properties().decimals_disagree()` (Rust),
`decimalsDisagree(client.properties)` (TypeScript), `client.properties.decimals_disagree`
(Python) or `Properties().DecimalsDisagree()` (Go). Amounts are covered in [the chain surface](chain-surface.md#amounts).

## Environment variables

`from_env` and every example read these variables. Keys come from the environment, never
from argv, because argv lands in shell history and `ps` output.

| Variable | Default | Meaning |
|---|---|---|
| `MATTER_API_KEY` | unset | the key to sign with (any [`ApiKey` format](keys-and-scopes.md#api-keys)); unset or blank falls back to `MATTER_SIGNER_SEED`; neither set gives a read-only client |
| `MATTER_SIGNER_SEED` | unset | fallback key, same formats |
| `MATTER_NETWORK` | `testnet` | `testnet` or `mainnet`; anything else is a `Config` error |
| `MATTER_RPC_URL` | the network's default | endpoint override |
| `MATTER_CONFIRM` | unset | exactly `yes` confirms a **signing** client on mainnet. Read on every connect, not just by `from_env` |
| `MATTER_PRINCIPAL` | unset | forces the member a scoped key acts for (hex or SS58); see [scoped keys](keys-and-scopes.md#overriding-the-principal). Read on every signing connect |

The examples add a few of their own, such as `MATTER_SUBMIT`; see
[examples](../examples/README.md).

## Logging

The client logs twice at connect: which member a scoped key acts for, and a decimals
disagreement. It never logs key material or plaintext. Route these messages with `tracing`
(Rust), `MatterConfig.logger` (TypeScript), the `matter_sdk.client` stdlib logger (Python),
or `Config.Logger` (Go, a `*slog.Logger`).
