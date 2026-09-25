# @openmatter-network/matter-sdk

The TypeScript client for OpenMatter: read state, sign and submit any call the runtime
exposes, and the threshold Secrets path.

```ts
import { MatterClient, ApiKey } from "@openmatter-network/matter-sdk";

// Read-only needs no key and costs nothing.
const reader = await MatterClient.connect();
console.log(await reader.query("Secrets", "NextSecretId"));
await reader.disconnect();

// With a key, the same client signs and submits.
const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));

// Any pallet, resolved from live metadata. Writes resolve at finalization with a
// receipt carrying the emitted events.
const receipt = await client.tx("Staking", "bond", [client.parseAmount("10"), { Staked: null }]);

// Reads and runtime APIs go through the same surface.
const account = await client.query("System", "Account", [client.accountId]);
const epoch = await client.runtimeApi("KgcApi_dkg_epoch");
```

The six façades (`client.secrets`, `deployments`, `resources`, `staking`, `orgs`,
`keys`) are described in the
[client guide](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/client-guide.md).

Defaults are testnet. A *signing* client refuses mainnet without `MATTER_CONFIRM=yes` or
`confirmMainnet: true`, checked against what the endpoint actually serves.

## Why this is a separate package

`@openmatter-network/matter-sdk-core` has **zero runtime dependencies** (CI asserts it
with `npm ls --omit=dev`). The chain client needs `@polkadot/api`, and npm installs even
`optionalDependencies` by default, so a separate package is the only real opt-out. This
package re-exports the whole core, so chain consumers import one package name.

## Layout

| File | Role |
|---|---|
| `src/client.ts` | `MatterClient`: four named constructors, the generic surface, the network guards |
| `src/backend.ts` | `ChainBackend`, the seam that keeps `@polkadot/api` swappable and the client testable without a node |
| `src/polkadot.ts` | the `@polkadot/api` backend, imported lazily |
| `src/amount.ts` | plancks-only arithmetic (`bigint`, never `number`) |
| `src/network.ts` | network selection and `ChainProperties` |
| `src/errors.ts` | `ClientError` with a `kind` discriminant |

## Development

The core is a regular dependency at `^<this version>` (`scripts/check-versions.sh` fails
if it drifts) and is also linked from the sibling directory as a dev dependency, which
wins locally:

```bash
npm --prefix ../typescript-core ci
npm --prefix ../typescript-core run build   # the wasm core + dist, which this package links
npm ci
npm test
npm run typecheck
```

Never publish from a package directory (`prepublishOnly` refuses). The release builds one
tarball, `scripts/check-npm-tarball.sh` asserts no `file:` specifier reached its
`dependencies`, and that tarball is what gets published.
