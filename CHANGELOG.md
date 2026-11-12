# Changelog

All notable changes to MatterSDK are recorded here. One tag releases every binding at one
version. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `@openmatter-network/matter-sdk-core` exports `./wasm-web/*`, so a bundler that needs
  to point at the browser build can name it without a path alias. CI now loads the
  published web build and the default transport in a headless browser
  (`npm run test:browser`).

- `seal_for` (`sealFor`, `SealFor`, `msdk_seal_for`) seals a secret for the account that
  will own it: the envelope's binding id is an owner-bound binding id, which the chain
  checks when the secret is stored or rotated. With it come `binding_id_for` and
  `binding_commits_to`, and the cross-language vector `testvectors/binding_ids.json`.
  Use `seal_for` for every secret you store; see `docs/secrets.md`.

- **OpenMatter Login** in the TypeScript core: a chain account from an OpenID Connect
  sign-in, with the key sealed under the committee and released only against a valid
  ID token. `prepareLoginRegistration`, `attestLoginRequest`, `collectLoginAttestations`
  and `registerLogin` register a login; `oidcSigner` and `openLogin` sign in;
  `FetchTransport.attestLogin` and the typed `LoginError` keep each node's HTTP status.
  `AuthScheme` gains `"oidc"`, and `RequestAuth` / `PartialDecryptRequest` gain the
  optional `id_token` and `app_id`; requests from every other signer are byte-identical.
  See `docs/login.md` and `examples/login-e2e`.
- The login byte contract in the core (`login_identity`, `login_nonce`,
  `login_payload_hash`, `login_attestation_payload`, `login_seed_aad`; `matter_sdk::login`
  in Rust, `loginIdentity` … in TypeScript), pinned by `testvectors/login.json`. Python,
  Go and the C ABI do not expose it yet.

- TypeScript receipts carry each event's fields under the runtime's field names
  (`["Secrets", "SecretStored", { secret_id, owner }]`), with `requireEvent` and
  `secretIdFromReceipt`, so the id of a stored secret is read from the receipt as in
  Python and Go.
- TypeScript `client.finalizedHead()`: the finalized block hash a `decrypt` request is
  bound to, so recovering a secret needs no second chain connection.

- Python and Go read a secret's epoch committee in one call: `ChainClient.committee_at(epoch)`
  returns a `CommitteeState`, and `ChainClient.CommitteeAt(epoch)` an `EpochCommittee`, with
  everything `decrypt` needs, mirroring Rust's `recover`.
- Python: `finality_timeout=` (seconds, default 120) on `connect_with_api_key` and
  `connect_with_keypair`, raising `FinalityTimeoutError` like the other languages.
- Python and Go forward the Ethereum-auth fields (`eth_address`, `valid_until`,
  `eth_signature`) from a custom committee `Signer`.

### Changed

- `encrypt` refuses an explicit binding id that is empty (previously sealed under an empty
  label). Omit it for the random default, or use `seal_for`.
- **Breaking (Go):** `ChainClient.StoreSecret` takes an `ExtrinsicSigner` and a `label`:
  `StoreSecret(signer, env, epoch, label, aad)`. Wrap a keyring pair in `KeyringSigner`.
- An `ApiKey` with an unknown `scheme:` prefix is now `Malformed` rather than
  `UnsupportedScheme`; `UnsupportedScheme` names only reserved schemes.
- TypeScript receipts name pallets as the metadata does (`Secrets`, not `secrets`).
- `query` returns none only when nothing is stored, in every language: Python no longer
  returns a storage default for a missing key, and TypeScript no longer reports a stored
  zero as absent.
- Unknown pallet, call or entry names raise a typed `Chain` error in Python and in Go's
  read methods.

- Rewrote the documentation around capabilities, with one guide per feature area and
  examples in all four languages. See [`docs/`](docs/README.md).
- The release gate now refuses a version that has no `CHANGELOG.md` section, before
  anything is built.
- The live end-to-end harnesses store a labelled secret, read committee state at the
  secret's epoch, and all require `MATTER_CONFIRM=yes` when the network or URL names
  mainnet. `examples/golden.json` is gone; re-decrypt across languages with
  `MATTER_SECRET_ID`.

### Fixed

- `FetchTransport` works in a browser. It kept `fetch` as a field and called it as a
  method, which a browser refuses ("Illegal invocation"), so the default transport — and
  one handed `window.fetch` — failed every request there; Node allows the call, so tests
  and the e2e runs passed. The caller's `fetch` is now always called bare. Browser callers
  who worked around it with `new FetchTransport((...args) => fetch(...args))` can keep or
  drop the wrapper.
- `FetchTransport` no longer needs `AbortSignal.timeout`: where the runtime lacks it
  (Safari before 16) the deadline is an `AbortController` and a timer.
- The TypeScript client reads its mainnet confirmation variable through
  `globalThis.process?.env`, so a browser bundle with no `process` gets the documented
  `mainnetNotConfirmed` refusal instead of a `ReferenceError`.

- **TypeScript could not submit `Secrets.store_secret`, `rotate_secret` or any call with a
  variable-length byte argument.** The façades and `tx` handed @polkadot raw `Uint8Array`s,
  which it reads as length-prefixed SCALE: the call was rejected while encoding
  (`Bytes: required length less than remainder`, `Bytes length … exceeds`) or, when the
  first byte happened to decode as a small length, silently truncated
  (`deployments.registerWgPeer`'s ciphertext). The @polkadot backend now converts every
  `Uint8Array` argument for `tx` and `query`, and an encoding failure is a `chain`
  `ClientError`.
- **TypeScript signed extrinsic payloads over 256 bytes unhashed**, so the chain rejected
  every such extrinsic (`store_secret` is hundreds of kilobytes) as a bad signature, with an
  `ApiKey` and with a custom `KeySigner` alike. The backend now hands the signer the
  blake2b-256 digest beyond 256 bytes, as Substrate verifies and as the other three
  languages already did. A `KeySigner` signs exactly the bytes it is given.
- Go `ChainClient.StoreSecret` and `FindStoredSecret` find the signer's `SecretStored`
  event again. GSRPC decodes the event's `AccountId32` owner as a one-field composite,
  which the owner match did not unwrap, so a finalized, successful store was reported as
  "finalized without a SecretStored event for this account".
- Go's `KeyringSigner` signs the bytes it is given verbatim. It called GSRPC's
  `signature.Sign`, which hashes anything over 256 bytes a second time; as the committee
  signer that would have broken a quorum of 21 or more nodes.
- The TypeScript and Rust live harnesses (`examples/e2e`, `examples/rust-e2e`) store and
  sign through `MatterClient` with a custom `KeySigner`, so the SDK's own write path is
  what runs against testnet; Rust recovers through `secrets().recover`. They previously
  built the extrinsic with @polkadot and subxt directly, which is how the two faults above
  shipped.
- A SURI whose password or junction contains `:` is parsed as a key. It was mistaken for a
  scheme prefix and rejected with an error that repeated the phrase.
- Go façades `Resources.{Register,SetPrivacy,Allow,Disallow}` and
  `Orgs.{AddMember,RemoveMember,AuthorizeSecretsAgent,RevokeSecretsAgent}` encode account
  ids as `AccountId32`, and `Orgs.Allot` its amount as `u128`; the calls were malformed.
- Python signs with the SS58 prefix the chain reports instead of assuming 42.

### Security

- The threshold-crypto core (`matter-crypto` 0.9.0) moves to `crypto-bigint` 0.7.11, which
  removes secret-dependent timing in big-integer arithmetic (RUSTSEC-2026-0387). Ciphertexts,
  proofs and derived keys are byte-for-byte unchanged, so this release interoperates with
  committees and SDKs on earlier versions in both directions.
- TLS and async runtime updates: `rustls` 0.23.46 (RUSTSEC-2026-0346, -0347, -0348, -0349),
  `rustls-webpki` 0.103.16 (RUSTSEC-2026-0382), `webpki-roots` and `webpki-root-certs` 1.0.11
  (RUSTSEC-2026-0381, -0383, removing the distrusted emSign root) and `tokio` 1.54.1
  (RUSTSEC-2026-0386).

## [2.3.0] - 2026-09-25

The first public release: a general client for OpenMatter's MatterChain, with threshold
secret management built in. It ships for Rust, TypeScript, Python and Go.

### Added

- **Every pallet, by name.** `tx`, `query`, `runtime_api` and `constant` resolve against
  the metadata the chain serves, so a pallet added by a forkless upgrade needs no SDK
  release. Writes are signed, submitted and followed to finalization, and a finality
  timeout can be configured.
- **Six typed façades:**

  | Façade | Covers |
  |---|---|
  | `secrets` | store, rotate, grant, revoke, delete |
  | `deployments` | request, cancel, secret and env references, WireGuard peers |
  | `resources` | registration, SKUs, capacity, privacy, allow-lists |
  | `staking` | bonding and nomination, plus nomination pools |
  | `orgs` | organisations, members, budget allotments, secrets agents |
  | `keys` | mint, re-scope, revoke and look up API keys |

- **API keys.** An `ApiKey` accepts a hex seed, a BIP39 mnemonic or an sr25519 SURI.
  - It is held zeroized and redacted, never serializes its key material, and rejects phrase-less dev
    URIs.
  - Scheme prefixes are reserved so that more key types can be added without breaking
    anything.
- **Member-tied scoped keys.**
  - A key acts for the member who minted it: the client detects the delegation and wraps
    each call in `proxy.proxy`.
  - Calls outside the key's scopes are refused locally before any fee is spent.
  - Failures are reported as `KeyRevoked`, `Unsponsored`, `NotPermitted` or
    `NeverAdmitted`.
- **Bring your own signer.** A `KeySigner` (or Go's `ExtrinsicSigner`) keeps production
  keys in an HSM, KMS, wallet or remote signer.
- **The mainnet guard.**
  - Mainnet is identified from what the endpoint actually serves, not what was
    configured.
  - A signing client refuses mainnet without `MATTER_CONFIRM=yes` or `confirm_mainnet`.
- **Exact amounts.** `parse_amount`, `format_amount` and `one_token` use the decimals the
  runtime enforces. They never pass through floating point and never truncate.
- **Threshold secrets.**
  - Seal a secret under the committee's post-quantum (RLWE/BGV) joint key and store it
    on-chain.
  - Recover it with a random `t`-of-`n` quorum, verified and aggregated in your process.
  - Includes typed errors that name each faulty node, a one-call `recover` in Rust, and
    call builders for people using their own Substrate client.
- **The AAD registry.** Tags bind a sealed payload to its purpose:
  - deployment env and TLS
  - volume storage credentials and data-encryption keys
  - dataset source credentials
  - QuantumGuard policy keys
- **Post-quantum WireGuard peers.** `register_wg_peer` carries an ML-KEM-768
  encapsulation for the tunnel's preshared key.
- **QuantumGuard deployments** are expressible through `deployments.request`, with the
  engine mounted from an image volume and its key delivered in the sealed env.
- **Packages.**

  | Language | Package | Notes |
  |---|---|---|
  | TypeScript | `@openmatter-network/matter-sdk` and `-core` | WebAssembly core; Node 22+ and bundlers |
  | Python | `matter-sdk` wheels | Python 3.9+ |
  | Go | `github.com/openmatter-network/matter-sdk-go/v2` | Prebuilt static core |
  | Rust | the `matter-sdk` git tag | — |

  Wheels and Go archives are built for Linux (x86-64 and arm64, glibc and musl) and
  macOS (x86-64 and arm64). A C ABI (`matter_sdk.h`) is attached to each GitHub Release.
- **Cross-language conformance vectors** keep all four bindings byte-for-byte identical.
