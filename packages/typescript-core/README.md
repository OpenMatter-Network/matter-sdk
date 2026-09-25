# @openmatter-network/matter-sdk-core

Seal secrets under the matter-kgc committee and recover them through a signed, threshold
`/partial-decrypt` quorum.

Cryptography and API-key derivation run in the shared wasm core (the same core as the
Rust SDK); this package adds the committee client, quorum orchestration, the signer seam,
and on-chain call builders.

**Zero runtime dependencies** (CI asserts it), so it fits a browser bundle. For the chain
client install
[`@openmatter-network/matter-sdk`](https://www.npmjs.com/package/@openmatter-network/matter-sdk),
which re-exports everything here.

## Install

```bash
npm install @openmatter-network/matter-sdk-core
```

## Quick start

```ts
import {
  encrypt, decrypt, FetchTransport, substrateSigner, Aad, storeSecret, wipe,
} from "@openmatter-network/matter-sdk-core";

// jointPk, epoch, sharedA, threshold and nodes are chain state; the chain client
// (@openmatter-network/matter-sdk) reads them for you.

// 1. Seal (pure, no network).
const env = encrypt(jointPk, epoch, new TextEncoder().encode("API_KEY=swordfish"), Aad.EnvV1);

// 2. Store: submit these args with your own @polkadot/api client.
const call = storeSecret(env, epoch, "prod-env", Aad.EnvV1);
// api.tx.secrets.storeSecret(call.payload, call.epoch, call.label, call.aad) ...

// 3. Recover. Your key stays in the signing callback — never in the SDK.
const signer = substrateSigner(accountId, (payload) => pair.sign(payload));
const plaintext = await decrypt(new FetchTransport(), signer, {
  secretId, epoch, bindingId: env.bindingId, aad: Aad.EnvV1,
  capsule: env.capsule, ct: env.ct, sharedA, blockHash, threshold, nodes,
});
// …use it, then:
wipe(plaintext);
```

## Secure signing

`decrypt` takes a `Signer`:

- `keySigner({ accountId, sign })` or `substrateSigner(accountId, sign)` wrap a callback
  you control (a `@polkadot/keyring` pair, a browser wallet, an HSM/KMS adapter), so the
  key never enters the SDK. Recommended for production.
- `new ApiKey(process.env.MATTER_API_KEY!)` holds the key in-process, redacted through
  `toString`/`toJSON`/`inspect`, with no accessor for the material. It is a `KeySigner`;
  `keySigner(key)` turns it into a `Signer`.

See [`docs/secure-signing.md`](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/secure-signing.md)
for the trade. The core wipes its own copy of recovered plaintext; never log the one you
get back, and `wipe` it when done.

## Building from source (this repository)

Needs read access to the private cryptographic core.

```bash
npm run build       # builds the wasm core, then tsc
npm test            # builds wasm, runs the conformance + orchestration tests
```

`npm test` replays the Rust-generated `testvectors/` fixtures, which must match
byte-for-byte.
