# @openmatter-network/matter-sdk

The TypeScript client for OpenMatter. It reads any state on MatterChain, signs and
submits any call the runtime exposes, and runs threshold secrets on the matter-kgc
committee. A single `apiKey`, or a signer you control, is all it needs.

## Install

```bash
npm install @openmatter-network/matter-sdk
```

- Needs Node 22+. The package is ESM only.
- It depends on `@polkadot/api`. That dependency loads lazily, so it isn't loaded when you inject your own `backend`.
- It re-exports all of
  [`@openmatter-network/matter-sdk-core`](https://github.com/OpenMatter-Network/matter-sdk/blob/main/packages/typescript-core/README.md),
  so one import covers sealing, recovery, and the chain client.

## Quick start

```ts
import { ApiKey, MatterClient } from "@openmatter-network/matter-sdk";

// Read-only: no key, no gas. Testnet is the default.
const reader = await MatterClient.connect();
console.log(reader.properties.chainName, reader.properties.specVersion);
console.log(await reader.query("Secrets", "NextSecretId"));
await reader.disconnect();

// With a key, the same client signs and submits.
const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));

// Any pallet, any call, resolved by name from live metadata. A write resolves at
// finalization, with a receipt of the emitted events.
const receipt = await client.tx("Staking", "bond", [client.parseAmount("10"), { Staked: null }]);

// Reads, runtime APIs and constants use the same surface.
const account = await client.query("System", "Account", [client.accountId]);
const epoch = await client.runtimeApi("KgcApi_dkg_epoch");

// Typed façades cover the common flows.
await client.staking.chill();
await client.disconnect();
```

`MatterClient.fromEnv()` reads the key and network from the environment. With no key set
it connects read-only.

## What's in the package

| Area | Surface |
|---|---|
| Connect | `MatterClient.connect`, `connectWithApiKey`, `connectWithSigner` (any `KeySigner`: HSM, KMS, wallet), `fromEnv`. `MatterConfig` sets `network`, `rpcUrl`, `confirmMainnet`, `finalityTimeoutMs`, `backend` and `logger` |
| Generic chain | `tx(pallet, call, args)`, `query(pallet, entry, keys)`, `runtimeApi(method, argsHex)`, `constant(pallet, name)` |
| Façades | `client.secrets`, `client.deployments`, `client.resources`, `client.staking`, `client.orgs`, `client.keys` |
| Scoped keys | `mode`, `principal`, `principalAddress`, `scopes`, `agentKey`, plus `Scope`, `Access`, `ScopeSet` and `requiredScopes` |
| Amounts | `client.parseAmount` / `formatAmount` / `oneToken` use the runtime's decimals. Also free functions `parseAmount`, `formatAmount`, `oneToken` and `decimalsFromExistentialDeposit`. All are `bigint` plancks and never `number` |
| Receipts | `TxReceipt` (`txHash`, `blockHash`, `events`) and `emitted(receipt, pallet, event)` |
| Errors | `ClientError`, whose `kind` is one of `read-only`, `config`, `chain`, `mainnet-not-confirmed`, `wrong-network`, `finality-timeout`, `not-permitted`, `never-admitted`, `dispatch`, `key-revoked`, `unsponsored` |
| Everything in the core | `encrypt`, `decrypt`, `openSecret`, `Aad`, `ApiKey`, call builders, `wipe`, … |

The client guards mainnet. A **signing** client refuses mainnet unless you set
`MATTER_CONFIRM=yes` or `confirmMainnet: true`. The check runs against what the endpoint
actually serves, not what you configured.

## Guides

- [Connecting](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/connecting.md): constructors, networks, the mainnet guard, and environment variables
- [Keys and scopes](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/keys-and-scopes.md)
- [The generic chain surface](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/chain-surface.md): `tx`, `query`, `runtimeApi`, `constant`, receipts, and amounts
- Façades: [secrets](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/secrets.md) ·
  [deployments](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/deployments.md) ·
  [resources](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/resources.md) ·
  [staking](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/staking.md) ·
  [organizations](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/organizations.md)
- [Secure signing](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/secure-signing.md) ·
  [Errors](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/errors.md) ·
  [Language parity](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/parity.md)
- Runnable example:
  [`examples/client-typescript`](https://github.com/OpenMatter-Network/matter-sdk/blob/main/examples/client-typescript/run.ts)

## Development (this repository)

The core is a regular dependency at `^<this version>`, and `scripts/check-versions.sh`
fails if the two drift. It is also linked from the sibling directory as a dev dependency,
and the linked copy wins locally:

```bash
npm --prefix ../typescript-core ci
npm --prefix ../typescript-core run build   # the wasm core + dist that this package links
npm ci
npm test
npm run typecheck
```

Never publish from a package directory (`prepublishOnly` refuses). The release pipeline
builds one tarball and checks it; that tarball is what gets published. See
[RELEASING.md](https://github.com/OpenMatter-Network/matter-sdk/blob/main/RELEASING.md).
