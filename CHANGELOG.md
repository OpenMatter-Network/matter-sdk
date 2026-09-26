# Changelog

All notable changes to MatterSDK are recorded here. One tag releases every binding at one
version. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Python and Go read a secret's epoch committee in one call: `ChainClient.committee_at(epoch)`
  returns a `CommitteeState`, and `ChainClient.CommitteeAt(epoch)` an `EpochCommittee`, with
  everything `decrypt` needs, mirroring Rust's `recover`.
- Python: `finality_timeout=` (seconds, default 120) on `connect_with_api_key` and
  `connect_with_keypair`, raising `FinalityTimeoutError` like the other languages.
- Python and Go forward the Ethereum-auth fields (`eth_address`, `valid_until`,
  `eth_signature`) from a custom committee `Signer`.

### Changed

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

- A SURI whose password or junction contains `:` is parsed as a key. It was mistaken for a
  scheme prefix and rejected with an error that repeated the phrase.
- Go façades `Resources.{Register,SetPrivacy,Allow,Disallow}` and
  `Orgs.{AddMember,RemoveMember,AuthorizeSecretsAgent,RevokeSecretsAgent}` encode account
  ids as `AccountId32`, and `Orgs.Allot` its amount as `u128`; the calls were malformed.
- Python signs with the SS58 prefix the chain reports instead of assuming 42.

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
