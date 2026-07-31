# @openmatter-network/matter-client

**One `apiKey`, every pallet.** The TypeScript client for OpenMatter: connect,
read state, and sign and submit any call the runtime exposes — plus the whole
MatterVault threshold-secret path.

```ts
import { MatterClient, ApiKey, Aad } from "@openmatter-network/matter-client";

const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));

// Any pallet, resolved from live metadata — no vendored types, so a pallet added
// by a forkless upgrade is reachable without an SDK release.
await client.tx("Jobs", "request_deployment", [request]);
await client.tx("Staking", "bond", [client.parseAmount("10"), { Staked: null }]);

// Reads and runtime APIs go through the same surface.
const account = await client.query("System", "Account", [client.accountId]);
const epoch = await client.runtimeApi("KgcApi_dkg_epoch");
```

Defaults are testnet, and a *signing* client refuses to touch mainnet without
`MATTER_CONFIRM=yes` or `confirmMainnet: true`. The check is on what the endpoint
actually serves, so pointing a testnet config at a mainnet URL still trips.

## Why this is a separate package

`@openmatter-network/matter-vault` advertises **zero runtime dependencies**, and
CI asserts it (`npm ls --omit=dev`). A chain client needs `@polkadot/api`, which is
several megabytes — so it lives here rather than being forced on a dashboard that
only seals and recovers secrets in the browser.

npm has no real opt-out for a declared dependency: `optionalDependencies` are
installed by default, so the package boundary is the only honest way to keep that
promise. (Rust gets a cargo feature instead, because a feature that is off is
genuinely not fetched or compiled.)

This package re-exports the entire `matter-vault` surface, so a chain consumer
still imports one package name.

## Layout

| File | Role |
|---|---|
| `src/client.ts` | `MatterClient` — four named constructors, the generic surface, the network guards |
| `src/backend.ts` | `ChainBackend`, the seam that keeps `@polkadot/api` swappable and the client testable without a node |
| `src/polkadot.ts` | the `@polkadot/api` backend, imported lazily |
| `src/amount.ts` | plancks-only arithmetic (`bigint`, never `number`) |
| `src/network.ts` | network selection and `ChainProperties` |
| `src/errors.ts` | `ClientError` with a `kind` discriminant |

## Development

`matter-vault` is a **peer** dependency (so consumers resolve the published
version) and is **linked from the sibling directory** as a dev dependency, since
it is published to a private registry:

```bash
npm --prefix ../typescript run build   # build the wasm core + dist first
npm install
npm test
npm run typecheck
```

`npm publish` refuses a `file:` specifier, so the dev link cannot silently ship.
