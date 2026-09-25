# mattersdk (Go)

The Go client for MatterSDK and the OpenMatter chain. Cryptography and API-key derivation
come from the shared Rust core via cgo over `crates/matter-sdk-ffi`; this package adds
the committee HTTP client, the quorum loop, the `Signer` abstraction, and a chain client.
See [`docs/parity.md`](../../../docs/parity.md) for differences from the other bindings.

## Install

```bash
go get github.com/openmatter-network/matter-sdk-go/v2
```

The module ships the Rust core as a prebuilt static library per supported platform: no
Rust toolchain needed, no run-time dependency on the core. You need cgo
(`CGO_ENABLED=1` and a C compiler). On musl (e.g. Alpine) build with `-tags musl`. An
unsupported platform, or a missing or misplaced `musl` tag, is a compile error.

<!-- monorepo-only -->
## Build & test (in this repository)

Here cgo links the core built from source (`link_dev.go`; the published module carries a
generated `link.go` instead):

```bash
cargo build -p matter-sdk-ffi --release   # -> target/release/libmatter_sdk_ffi.a
cd packages/go/mattersdk
go test ./...
```
<!-- /monorepo-only -->

## Quick start

```go
import mattersdk "github.com/openmatter-network/matter-sdk-go/v2"

// MATTER_API_KEY / MATTER_NETWORK / MATTER_RPC_URL / MATTER_CONFIRM.
// No key set connects read-only, which is a legitimate outcome rather than an error.
client, key, err := mattersdk.ConnectFromEnv()
if err != nil {
	return err
}
defer client.Close()
if key != nil {
	defer key.Close()
}

// Reads: any pallet the runtime exposes, resolved by name from live metadata.
raw, err := client.QueryRaw("Secrets", "NextSecretId")
epoch, err := client.RuntimeAPI("KgcApi_dkg_epoch", nil)

// Amounts are *big.Int plancks — uint64 overflows at 10^18.
amount, err := client.ParseAmount("1.5")

// Writes wait for finalization and return a TxReceipt; a delegated call the runtime
// refused is a *ChainError of KindDispatch, never a receipt.
receipt, err := client.Staking().Bond(amount, payee)
receipt, err = client.Secrets().Revoke(secretID, target)
receipt, err = client.Call("Staking", "chill") // any call, by name
```

[`examples/client-go`](../../../examples/client-go) is the same program, runnable.
`client.Chain()` returns the underlying `ChainClient` for anything the client does not
cover.

An `ApiKey` is redacted through `String()` and every `fmt` verb, and `MarshalJSON`
**errors** rather than emitting a placeholder. `NewApiKey` derives through the FFI, not
go-subkey, so junctions, phrase-less-URI rejection, and the reserved `secp256k1:` scheme
behave as in every other binding. See [`docs/secure-signing.md`](../../../docs/secure-signing.md).

## Notes specific to this binding

- **`SecretID` is a u128 value type**, matching the chain's `SecretIdentifier`.
- **The signed extrinsic is hand-assembled**, because go-substrate-rpc-client v4.2.1 does
  not encode this runtime's `CheckMetadataHash` / `WeightReclaim` signed extensions.
  `extrinsic.go` walks the extensions the metadata declares and **refuses to sign** one
  it cannot account for.
- **Writes are followed to finalization.** Every façade method, `Call`, and `TxAndWait`
  locate the extrinsic by the exact bytes submitted and decode its outcome, including a
  failure wrapped in `proxy.proxy`. `Tx` alone is fire-and-forget. To confirm a separate
  effect, `ChainClient.WaitForFinalized` takes a domain predicate ("is the secret
  readable at this block?").
- **A stored secret's id comes from the `Secrets.SecretStored` event**, matched on the
  owner account via `client.Chain().FindStoredSecret(receipt.BlockHash, owner)`. Never
  predict it from `NextSecretId`: concurrent submitters read the same counter.

## Façades

`Secrets()`, `Deployments()`, `Resources()`, `Staking()`, `Orgs()`, and `Keys()`:

```go
client.Secrets().Store(env, epoch, "prod", mattersdk.AadEnvV1)
client.Staking().Bond(amount, payee)
client.Deployments().SetSecretRef(deployment, &secretID)
client.Orgs().AuthorizeSecretsAgent(org, project, who)
```

Anything not covered is one `client.Call(pallet, method, args...)` away.
`facade_test.go` replays `testvectors/facade_calls.json` both ways.
