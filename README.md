# MatterSDK

**The client SDK for [OpenMatter](https://openmatter.network), in Rust, TypeScript,
Python and Go.** One key, or a signer you control, reaches everything your account can do
on MatterChain: deploy workloads, run compute resources, stake, manage organizations and
budgets, hand out narrowly scoped API keys, and keep secrets that no single party can
decrypt.

```ts
import { ApiKey, MatterClient } from "@openmatter-network/matter-sdk";

const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));
await client.staking.bond(client.parseAmount("10"), { Staked: null }); // a typed façade
await client.tx("Communities", "vote_proposal", [community, proposal, vote]); // any pallet
```

## What you can do

| Capability | What it gives you | Guide |
|---|---|---|
| **Any pallet, by name** | `tx`, `query`, runtime APIs and constants for all 60+ pallets, resolved from live metadata, so a runtime upgrade needs no SDK release. Writes wait for finality and return a receipt. | [Chain surface](docs/chain-surface.md) |
| **Deployments** | the `deployments` façade: request and cancel workloads, attach sealed env and TLS secrets, set env, register post-quantum WireGuard peers, run QuantumGuard-guarded deployments | [Deployments](docs/deployments.md) |
| **Compute resources** | the `resources` façade: register machines, manage privacy and allow-lists | [Resources](docs/resources.md) |
| **Staking** | the `staking` façade: bond, nominate, unbond, and nomination pools | [Staking](docs/staking.md) |
| **Organizations and budgets** | the `orgs` façade: create organizations, manage members and roles, allot project budgets | [Organizations](docs/organizations.md) |
| **Scoped API keys** | the `keys` façade: mint keys that act as a member with only the scopes you grant (`deployments:w`, `secrets:r`…), checked locally and enforced by the runtime | [Keys and scopes](docs/keys-and-scopes.md) |
| **Threshold secrets** | the `secrets` façade: seal a secret under a `t`-of-`n` committee's key, store it on chain, grant it to users or deployments, and recover it only with a quorum. Post-quantum lattice cryptography; no master key exists anywhere. | [Threshold secrets](docs/secrets.md) |
| **Keys that never enter your process** | sign through an HSM, KMS, wallet or remote signer; or hold an `ApiKey` that zeroizes, redacts itself and refuses mainnet until you confirm | [Secure signing](docs/secure-signing.md) |

Also included: lossless token amounts, typed errors, a mainnet guard that checks the
endpoint rather than your config, and identical behaviour across languages, pinned by
shared test vectors. Start with [concepts](docs/concepts.md) or the
[documentation index](docs/README.md).

## Install

Every package ships from one tag at one version ([changelog](CHANGELOG.md)).

```bash
# TypeScript (Node 22+). The client re-exports the core; the core alone suits a browser
# bundle or code that only seals and recovers secrets.
npm install @openmatter-network/matter-sdk
npm install @openmatter-network/matter-sdk-core

# Python 3.9+. The [sdk] extra adds the chain client.
pip install "matter-sdk[sdk]"

# Go 1.22+ with cgo (CGO_ENABLED=1 and a C compiler). On Alpine/musl, build with -tags musl.
go get github.com/openmatter-network/matter-sdk-go/v2
```

The Python wheels and the Go module include the Rust core prebuilt: you need no Rust
toolchain, and a Go binary has no run-time dependency on it. Supported platforms:

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

Windows is not supported yet. There is no Python sdist, so on other platforms `pip`
reports *"No matching distribution found"*. In Go, an unsupported platform or a missing
`musl` tag is a compile error. The npm packages are WebAssembly and run anywhere Node 22+
or a bundler does.

**Rust** depends on the release tag. That requires read access to OpenMatter's private
cryptography repositories, which the published packages ship compiled:

```toml
[dependencies]
matter-sdk = { git = "https://github.com/OpenMatter-Network/matter-sdk", tag = "v2.3.1" }
# features = ["chain"] adds the chain client and façades (subxt + tokio); default is off.
```

```toml
# .cargo/config.toml in your project: the core is fetched over ssh://, which only the
# git CLI can authenticate, and a dependency's own cargo config is never read.
[net]
git-fetch-with-cli = true
```

MSRV is Rust 1.90.

## Quickstart

Connect read-only, with no key and no fees, and read live chain state:

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

```ts
import { MatterClient } from "@openmatter-network/matter-sdk";

const client = await MatterClient.connect(); // read-only, testnet
console.log(client.properties.chainName, client.properties.specVersion);
console.log(await client.query("Secrets", "NextSecretId"));
await client.disconnect();
```

```python
from matter_sdk import MatterClient

with MatterClient.connect() as client:  # read-only, testnet
    print(client.properties.chain_name, client.properties.spec_version)
    print(client.query("Secrets", "NextSecretId"))
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

Rust needs `matter_sdk::chain::{MatterClient, MatterConfig, Network}` and the `chain`
feature. Go imports `mattersdk "github.com/openmatter-network/matter-sdk-go/v2"`.

**To write, bring a key.** Set `MATTER_API_KEY` and connect with `from_env`
(`fromEnv`, `ConnectFromEnv`), or pass a signer backed by your HSM or KMS. Testnet is the
default. A signing client refuses mainnet unless you set `MATTER_CONFIRM=yes`. See
[connecting](docs/connecting.md).

## Languages

| | Rust | TypeScript | Python | Go |
|---|:--:|:--:|:--:|:--:|
| Generic chain surface and the six façades | ✅ | ✅ | ✅ | ✅ |
| `ApiKey`, scoped keys, mainnet guard | ✅ | ✅ | ✅ | ✅ |
| Threshold secrets (seal, store, grant, recover) | ✅ | ✅ | ✅ | ✅ |
| Signer that keeps the key out of the process | ✅ | ✅ | ✅ (keypair-shaped) | ✅ |
| Browser build | — | ✅ | — | — |

Per-language guides: [TypeScript](packages/typescript/README.md) ·
[TypeScript core](packages/typescript-core/README.md) · [Python](bindings/python/README.md) ·
[Go](packages/go/mattersdk/README.md) · [examples](examples/README.md). Every difference
is listed in [parity](docs/parity.md).

## Security

- **No key in your process, if you choose.** Every signature goes through a seam you can
  back with an HSM, KMS, wallet or remote signer.
- **In-process keys are contained.** An `ApiKey` is zeroized, redacted, not
  serializable, and never echoed in errors.
- **No single point of decryption.** A sealed secret opens only with `t` of `n`
  independent committee nodes. No node, operator included, can decrypt alone, and
  plaintext exists only in your process.
- **Post-quantum.** The secret encryption is lattice-based (RLWE), the family NIST chose
  for post-quantum standards, so data recorded today cannot be decrypted by a future
  quantum computer. Deployment WireGuard tunnels take an ML-KEM-768 preshared key.
- **Committee rotation is invisible to your data.** The committee reshares its key each
  epoch; the joint public key stays the same, stored ciphertext keeps decrypting, and
  old shares become useless.

The threat model and how to report a vulnerability are in [`SECURITY.md`](SECURITY.md).

## Building from source

Building needs read access to the private cryptography repositories over SSH
([contributing](CONTRIBUTING.md)):

```bash
cargo test -p matter-sdk-core                 # crypto core
cargo test -p matter-sdk --features chain     # Rust SDK and chain client
```

Each language also has a live end-to-end harness against testnet: it seals, stores,
reads back, and threshold-decrypts. See [examples](examples/README.md).

## License

Apache-2.0 © Open Matter. See [`LICENSE`](LICENSE).
