# @openmatter-network/matter-sdk-core

The zero-dependency core of MatterSDK for OpenMatter: seal secrets under the matter-kgc
committee's joint key, and recover them through a signed, threshold `/partial-decrypt`
quorum. Runs in Node and in the browser.

Cryptography and API-key derivation run in the shared WebAssembly core, which is the same
Rust core every MatterSDK language uses. This package adds the committee client, quorum
orchestration, the signer seam, and argument builders for the `Secrets` pallet calls.

**Core or client?** This package has no runtime dependencies (CI asserts it), so it fits a
browser bundle or any service that only seals and recovers. To read chain state and submit
calls, install
[`@openmatter-network/matter-sdk`](https://github.com/OpenMatter-Network/matter-sdk/blob/main/packages/typescript/README.md)
instead. It re-exports everything here.

## Install

```bash
npm install @openmatter-network/matter-sdk-core
```

Needs Node 22+ or a bundler. ESM only. Bundlers resolve the `browser` build of the core
automatically.

## Quick start

```ts
import {
  Aad, decrypt, encrypt, FetchTransport, storeSecret, substrateSigner, wipe,
} from "@openmatter-network/matter-sdk-core";

// jointPk, epoch, sharedA, blockHash, threshold and nodes are chain state.
// @openmatter-network/matter-sdk reads them for you.

// 1. Seal. Pure computation, no network.
const env = encrypt(jointPk, epoch, new TextEncoder().encode("API_KEY=swordfish"), Aad.EnvV1);

// 2. Store: submit these arguments with your own @polkadot/api client.
const call = storeSecret(env, epoch, "prod-env", Aad.EnvV1);
// api.tx.secrets.storeSecret(call.payload, call.epoch, call.label, call.aad)

// 3. Recover. The key stays behind your sign callback and never enters the SDK.
const signer = substrateSigner(accountId, (payload) => pair.sign(payload));
const plaintext = await decrypt(new FetchTransport(), signer, {
  secretId, epoch, bindingId: env.bindingId, aad: Aad.EnvV1,
  capsule: env.capsule, ct: env.ct, sharedA, blockHash, threshold, nodes,
});
// ...use it, then:
wipe(plaintext);
```

## What's in the package

| Area | Exports |
|---|---|
| Seal and open | `encrypt`, `openSecret`, `verifyPlaintextProof`, `signingPayload`, `lagrangeFor`, `cryptoProtocolVersion`, `maxCommitteeResponseBytes` |
| Committee | `decrypt`, `FetchTransport`, `Transport`, `CommitteeNode`, `DecryptParams`, `DecryptError` (`kind`: `quorum` / `epoch` / `transport` / `crypto`, plus per-node `faults`) |
| Keys and signing | `ApiKey`, `keySigner`, `substrateSigner`, `partialDecryptAuth`, `Signer`, `KeySigner` |
| AAD registry | `Aad`: `EnvV1`, `TlsV1`, `StorageCredsV1`, `VolumeDekV1`, `DatasetSourceCredsV1`, `QuantumGuardPolicyDekV1`. Also `aadBytes` |
| Call builders | `storeSecret`, `rotateSecret`, `grantAccess`, `grantToUser`, `grantToDeployment`, `revokeAccess`, `deleteSecret` |
| Utilities | `toHex`, `fromHex`, `secretIdToHex`, `wipe` |

`FetchTransport` streams every committee response and enforces a size cap. Its default
timeout is 30 s.

## Keys and signing

`decrypt` takes a `Signer`. You can build one in two ways:

- **`substrateSigner(accountId, sign)` or `keySigner({ accountId, sign })`.** Wraps a
  callback you control: a `@polkadot/keyring` pair, a browser wallet, or an HSM or KMS
  adapter. The key never enters the SDK. This is the way to go in production.
- **`new ApiKey(process.env.MATTER_API_KEY!)`.** Holds the key in-process.
  `toString`, `toJSON` and `inspect` all redact it, nothing exposes the key material, and
  `free()` releases it. An `ApiKey` is a `KeySigner`; `keySigner(key)` turns it into a
  `Signer`.

The core wipes its own copy of a recovered plaintext. Never log the copy you get back,
and `wipe` it when you're done.

## Guides

- [Threshold secrets](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/secrets.md)
- [Keys and scopes](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/keys-and-scopes.md)
- [Secure signing](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/secure-signing.md)
- [Errors](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/errors.md)
- [Language parity](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/parity.md)
- [All documentation](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/README.md)

## Building from source (this repository)

Building from source needs read access to the private cryptographic core.

```bash
npm ci
npm run build       # wasm-pack builds the Node and browser cores, then tsc
npm test            # rebuilds the Node core, then replays the conformance vectors
```

`npm test` replays the Rust-generated
[`testvectors/`](https://github.com/OpenMatter-Network/matter-sdk/blob/main/testvectors/README.md)
fixtures, which must match byte for byte. Never publish from this directory
(`prepublishOnly` refuses). See
[RELEASING.md](https://github.com/OpenMatter-Network/matter-sdk/blob/main/RELEASING.md).
