# MatterSDK

**Client SDKs for [OpenMatter](https://openmatter.network): one `apiKey` reaches every pallet
on MatterChain, plus threshold secret management on the matter-kgc committee.**

- **Chain client.** Every pallet the runtime exposes, resolved from live metadata rather
  than vendored types: deployments, resources, staking, org budgets, governance.
- **Secrets.** Seal a secret under a committee's joint public key, store the ciphertext
  on-chain, and recover it only with a `t`-of-`n` quorum. No single party, operators
  included, can decrypt alone.

| Term | Meaning |
|---|---|
| **MatterChain** | OpenMatter's Substrate-based blockchain; testnet is the default everywhere. |
| **Pallet** | A runtime module (e.g. `Secrets`, `Jobs`, `Staking`), reached by name. |
| **KGC committee** | The `n` independent `matter-kgc` nodes that jointly hold the decryption key as shares. |
| **Threshold decryption** | Any `t` of the `n` nodes can decrypt together; fewer than `t` learn nothing. |
| **API key** | A dashboard-minted key (hex seed, mnemonic, or sr25519 SURI) that acts for the member who minted it. |
| **Planck** | The chain's smallest unit; every SDK amount is an integer number of plancks. |

> Status: **early access.** Rust, TypeScript, Python, and Go all work end-to-end against
> the live testnet. See [Language support](#language-support) and
> [`docs/parity.md`](docs/parity.md).

<p align="center">
  <img src="docs/assets/integration-flow.svg" alt="Your app calls MatterSDK to encrypt a secret and store the ciphertext on the matter chain, then to decrypt by requesting partial decryptions from a t-of-n matter-kgc committee and aggregating them locally" width="880">
</p>

## Why a committee?

There is **no master key**. The decryption key exists only as Shamir shares across `n`
committee nodes; recovering a secret needs `t` of them to each return a *partial
decryption*, which your client verifies and aggregates locally. The cryptography is
RLWE/BGV threshold decryption with zero-knowledge proofs at every step, implemented in
`matter-crypto` (a private OpenMatter repository).

<p align="center">
  <img src="docs/assets/quorum.svg" alt="Five committee nodes each hold one piece of the private key; any three pieces reconstruct the secret while any two reveal nothing — no single node ever holds the full key" width="760">
</p>

## Architecture

The cryptography lives in one audited Rust crate (`crates/matter-sdk-core`, plus
`crates/matter-sdk-key` for API keys), shared by every binding over FFI/wasm/PyO3 and never
re-implemented. Networking, the quorum loop, and signing are idiomatic per language;
[conformance vectors](testvectors/) keep the bindings byte-for-byte identical. Crate map
and data flow: [`docs/architecture.md`](docs/architecture.md).

## Install

All bindings release together from one tag at one version ([`CHANGELOG.md`](CHANGELOG.md)).

```bash
# TypeScript / JavaScript (Node 22+). The client re-exports the core; install the core
# alone for a browser bundle or anything that only seals and recovers.
npm install @openmatter-network/matter-sdk
npm install @openmatter-network/matter-sdk-core

# Python 3.9+. The [sdk] extra adds the chain client.
pip install "matter-sdk[sdk]"

# Go 1.22+, with cgo (CGO_ENABLED=1 and a C compiler). On Alpine/musl add -tags musl.
go get github.com/openmatter-network/matter-sdk-go/v2
```

The Python wheel and the Go module carry the Rust core prebuilt, so neither needs a Rust
toolchain and a Go binary has no run-time dependency on the core. Supported platforms:

<!-- platforms:begin -->
| OS | Architecture | C library | Python wheel | Go build |
|---|---|---|---|---|
| Linux | x86-64 | glibc | `manylinux_2_17_x86_64` | `go build` |
| Linux | arm64 | glibc | `manylinux_2_17_aarch64` | `go build` |
| Linux | x86-64 | musl | `musllinux_1_2_x86_64` | `go build -tags musl` |
| Linux | arm64 | musl | `musllinux_1_2_aarch64` | `go build -tags musl` |
| macOS | x86-64 | — | `macosx_11_0_x86_64` | `go build` |
| macOS | arm64 | — | `macosx_11_0_arm64` | `go build` |
<!-- platforms:end -->

**Windows is not supported.** There is no Python sdist (the core is not public), so on
any other platform (Windows, PyPy, free-threaded CPython, 32-bit) `pip` reports *"No
matching distribution found"*. In Go, an unsupported platform or a missing or misplaced
`musl` tag is a compile error. The npm packages are WebAssembly and run anywhere Node 22+
or a bundler does.

**Rust** is not on crates.io, because the crate depends on the private core. Depend on the
release tag, which requires read access to the `openmatter-network` core repositories:

```toml
[dependencies]
matter-sdk = { git = "https://github.com/OpenMatter-Network/matter-sdk", tag = "v2.3.0" }
# features = ["chain"] adds the chain client and façades (subxt + tokio); default is off.
```

```toml
# .cargo/config.toml, in your project: a dependency's cargo config is never read, and
# the core is pinned by ssh:// URL, which only the git CLI can authenticate.
[net]
git-fetch-with-cli = true
```

MSRV is Rust 1.90.

## Quickstart

Connect read-only (no key, no gas) and read live chain state:

```ts
import { MatterClient } from "@openmatter-network/matter-sdk";

const client = await MatterClient.connect();                  // read-only, testnet
console.log(client.properties.chainName, client.properties.specVersion);
console.log(await client.query("Secrets", "NextSecretId"));
await client.disconnect();
```

```python
from matter_sdk import MatterClient

client = MatterClient.connect()                               # read-only, testnet
print(client.properties.chain_name, client.properties.spec_version)
print(client.query("Secrets", "NextSecretId"))
client.close()
```

```go
client, err := mattersdk.Connect(mattersdk.Config{}) // read-only, testnet
if err != nil {
	return err
}
defer client.Close()
fmt.Println(client.Properties().ChainName, client.Properties().SpecVersion)
next, err := client.QueryRaw("Secrets", "NextSecretId")
```

```rust
async fn quickstart() -> matter_sdk::Result<()> {
    let client = MatterClient::connect(MatterConfig::for_network(Network::Testnet)).await?;
    let chain = client.properties();
    println!("{} {}", chain.chain_name, chain.spec_version);
    println!(
        "{:?}",
        client.query("Secrets", "NextSecretId", vec![]).await?
    );
    Ok(())
}
```

(Go imports `mattersdk "github.com/openmatter-network/matter-sdk-go/v2"`; Rust needs
`matter_sdk::chain::{MatterClient, MatterConfig, Network}` and the `chain` feature.)

**To write, bring a key.** Set `MATTER_API_KEY` and connect with `connectWithApiKey` /
`connect_with_api_key` / `ConnectWithApiKey`, or `from_env` / `ConnectFromEnv`. Read the
key from the environment, never argv or source. The key acts as the member who minted it,
bounded by the scopes they granted; the member pays. See
[Keys and scopes](docs/client-guide.md#keys-and-scopes).

```ts
import { MatterClient, ApiKey } from "@openmatter-network/matter-sdk";

const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));

// Any pallet the runtime exposes, resolved from live metadata; resolves at finalization.
const receipt = await client.tx("Staking", "bond", [client.parseAmount("10"), { Staked: null }]);
```

Secrets: seal with `encrypt()`, store with `client.secrets.store(...)`, recover with the
threshold `decrypt()`. See the [client guide](docs/client-guide.md) and the
[examples](examples/README.md).

A *signing* client refuses mainnet without explicit confirmation. See
[Secure signing](#secure-signing) and [`docs/`](docs/README.md).

## What the SDK does and does not do

- **Does:** call any pallet via `tx` / `query` / `runtimeApi` / `constant`, so a pallet
  added by a forkless upgrade needs no SDK release; sign, submit, and track extrinsics to
  finalization.
- **Does:** the whole Secrets path (seal; health-probe → random quorum → signed
  `/partial-decrypt` → verify + aggregate + open), and builds `store` / `rotate` / `grant`
  call data if you submit with your own Substrate client.
- **Does not:** decide where your key lives. Use a signer over an HSM, KMS, or wallet
  (recommended for production), or an `apiKey` the SDK holds under documented guardrails.
- **Does not:** hold state, cache secrets, or phone home. Recovered plaintext is returned
  to you and written nowhere.

## How it works

<p align="center">
  <img src="docs/assets/lifecycle.svg" alt="Six-step lifecycle: Seal, Store, Authorize, Request, Partial-decrypt, Deploy. Any t of the n committee nodes suffice to decrypt; fewer than t learn nothing" width="900">
</p>

## Language support

| Language | Seal & recover | `apiKey` | Chain client | Façades | Chain client enabled by |
|---|:--:|:--:|:--:|:--:|---|
| Rust (`matter-sdk`, git tag; needs core access) | ✅ | ✅ | ✅ | ✅ | `chain` cargo feature (default off) |
| TypeScript (`@openmatter-network/matter-sdk-core`) | ✅ | ✅ | ✅ | ✅ | `@openmatter-network/matter-sdk` |
| Python (`matter-sdk`) | ✅ | ✅ | ✅ | ✅ | `pip install "matter-sdk[sdk]"` |
| Go (`mattersdk`) | ✅ | ✅ | ✅ | ✅ | always (cgo already binds the core) |

Python takes an in-process keypair (`connect_with_keypair`); see
[parity](docs/parity.md#notes--remaining-work).

Per-language guides: [Rust](examples/rust/README.md) ·
[TypeScript](packages/typescript/README.md) · [Python](bindings/python/README.md) ·
[Go](packages/go/mattersdk/README.md) · [all examples](examples/README.md).

## Secure signing

Production keys belong in an HSM, KMS, wallet, or remote signer behind a `KeySigner`; the
key never enters the SDK. An `apiKey` held in-process is zeroizing, redacted,
non-serializable, and refuses mainnet unconfirmed, but anything that can read the process
can read it ([the trade](docs/secure-signing.md#what-you-are-trading)). Recovered plaintext
is never logged. The `..._insecure_dev_only` helpers must never ship. Read
[`SECURITY.md`](SECURITY.md) and [`docs/secure-signing.md`](docs/secure-signing.md) before
integrating.

## Security FAQ

**Does committee rotation affect my data?** No. The committee is a dynamic `t`-of-`n`
group whose joint public key is stable across membership changes, so stored ciphertext
keeps decrypting, and each rotation makes old shares useless. See
[Key rotation](docs/architecture.md#key-rotation).

**Is it quantum-safe?** The encryption is lattice-based, the family NIST chose for
post-quantum standards (ML-KEM / FIPS 203 is a close relative), targeting the ~128-bit
post-quantum security range. Data recorded today cannot be unsealed by a future quantum
computer ("harvest now, decrypt later"). The same construction gives both the post-quantum
and the no-single-key guarantee. See [`SECURITY.md`](SECURITY.md) for assumptions.

**How does it differ from a KMS or HSM?**

| | Key in your app | KMS / HSM | MatterSDK |
|---|---|---|---|
| Where the decryption key lives | one place | one box / one provider | split across `n` nodes; never assembled |
| Single point of compromise | yes | yes | **no** — need `t` nodes at once |
| Who sees plaintext at decrypt time | whoever holds the key | the KMS / HSM | **no one** — nodes return verified partials; your client combines them |
| Survives key-holder rotation without re-encrypting | n/a | usually re-key | **yes** — the public key is stable across membership changes |
| Quantum-safe | depends on cipher | usually classical (RSA / ECC) | **yes** — lattice / post-quantum |

## Building from source

The private core crates are git-tag dependencies (see the workspace `Cargo.toml`) fetched
over SSH, so you need a GitHub SSH key with access to the `openmatter-network` repos.
`.cargo/config.toml` sets `net.git-fetch-with-cli`; CI uses an HTTPS token
(`.github/actions/fetch-core-crates`).

```bash
cargo test -p matter-sdk-core   # crypto core + roundtrip
cargo test -p matter-sdk        # Rust SDK
```

### Live end-to-end test

Each binding has a live harness (encrypt → `secrets.storeSecret` → read back →
threshold-decrypt) that proves the committee accepts the SDK's signature on-chain:
[Rust](examples/rust-e2e) · [TypeScript](examples/e2e) ([README](examples/e2e/README.md)) ·
[Python](examples/python-e2e) · [Go](examples/go-e2e). Env vars: `MATTER_RPC_URL`
(default testnet) and `MATTER_SIGNER_SEED` (a funded sr25519 key as `0x`-hex seed or
BIP39 mnemonic; `TEST_KEY` also accepted). [`preflight.ts`](examples/e2e/preflight.ts)
checks funding and committee health without gas.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0 © Open Matter. See [`LICENSE`](LICENSE).
