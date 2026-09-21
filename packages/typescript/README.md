# @openmatter-network/matter-sdk

**One `apiKey`, every pallet.** The TypeScript client for OpenMatter: connect,
read state, and sign and submit any call the runtime exposes — plus the whole
threshold Secrets path.

```ts
import { MatterClient, ApiKey, Aad } from "@openmatter-network/matter-sdk";

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

`@openmatter-network/matter-sdk-core` advertises **zero runtime dependencies**, and
CI asserts it (`npm ls --omit=dev`). A chain client needs `@polkadot/api`, which is
several megabytes — so it lives here rather than being forced on a dashboard that
only seals and recovers secrets in the browser.

npm has no real opt-out for a declared dependency: `optionalDependencies` are
installed by default, so the package boundary is the only honest way to keep that
promise. (Rust gets a cargo feature instead, because a feature that is off is
genuinely not fetched or compiled.)

This package re-exports the entire `matter-sdk` surface, so a chain consumer
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

`@openmatter-network/matter-sdk-core` is a regular **dependency**, at exactly
`^<this version>` — both packages are released together, and
`scripts/check-versions.sh` fails if the range drifts. For development it is also
**linked from the sibling directory** as a dev dependency, which takes precedence
locally, so the client always builds against the core next to it:

```bash
npm --prefix ../typescript-core ci
npm --prefix ../typescript-core run build   # the wasm core + dist, which this package links
npm ci
npm test
npm run typecheck
```

Neither package is ever published from its directory (`prepublishOnly` refuses). The
release builds one tarball, `scripts/check-npm-tarball.sh` asserts that no `file:`
specifier reached its `dependencies`, and that same file is what gets published.
