# mattersdk (Go)

The Go client for OpenMatter. It reads any state on MatterChain, signs and submits any
call the runtime exposes, and runs threshold secrets on the matter-kgc committee.
Cryptography and API-key derivation come from the shared Rust core over cgo. This package
adds the chain client, the committee HTTP client, the quorum loop, and the signer seams.

## Install

```bash
go get github.com/openmatter-network/matter-sdk-go/v2
```

- **Requirements:** Go 1.22+ with cgo (`CGO_ENABLED=1` and a C compiler).
- **Rust core:** the module ships it as a prebuilt static library for each supported platform. You don't need a Rust toolchain, and your binary has no run-time dependency on the core.
- **musl:** on Alpine and other musl systems, build with `-tags musl`.
- **Unsupported setups fail at compile time.** This covers an unsupported platform, a missing or misplaced `musl` tag, and building without cgo.

<!-- monorepo-only -->
## Build and test (in this repository)

In this repository, cgo links the core built from source through `link_dev.go`. The
published module carries a generated `link.go` instead:

```bash
cargo build -p matter-sdk-ffi --release   # -> target/release/libmatter_sdk_ffi.a
cd packages/go/mattersdk
go test ./...
```
<!-- /monorepo-only -->

## Quick start

```go
import mattersdk "github.com/openmatter-network/matter-sdk-go/v2"

// Reads MATTER_API_KEY / MATTER_NETWORK / MATTER_RPC_URL / MATTER_CONFIRM.
// With no key set it connects read-only, which is a valid result, not an error.
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

// Amounts are *big.Int plancks, because uint64 overflows at 10^18.
amount, err := client.ParseAmount("1.5")

// Writes wait for finalization and return a TxReceipt.
receipt, err := client.Staking().Bond(amount, payee)
receipt, err = client.Call("Staking", "chill") // any call, by name
```

[`examples/client-go`](../../../examples/client-go/main.go) is the same program, and you
can run it.

## What's in the package

| Area | Surface |
|---|---|
| Connect | `Connect`, `ConnectWithApiKey`, `ConnectWithSigner` (any `ExtrinsicSigner`: HSM, KMS, remote), `ConnectFromEnv`. `Config` sets `Network`, `RPCURL`, `ConfirmMainnet`, `FinalityTimeout` and `Logger` (`*slog.Logger`) |
| Generic chain | `Call(pallet, method, args...)` waits for finalization. `TxAndWait(call)` submits a prebuilt `types.Call` and waits. `Tx(call)` submits and returns at once. Also `Query`, `QueryRaw`, `RuntimeAPI`, `Constant` |
| Façades | `Secrets()`, `Deployments()`, `Resources()`, `Staking()`, `Orgs()`, `Keys()` |
| Scoped keys | `IsDelegated`, `Principal`, `PrincipalAddress`, `Scopes`, `AgentKey`, plus `ScopeSet` and `RequiredScopes` |
| Lower level | `Chain()` returns the `ChainClient`. It has `CommitteeAt(epoch)`, which reads everything a decrypt needs for a secret's epoch, plus single readers (`JointPk`, `DkgEpoch`, `SharedA` and `Nodes` for the current epoch, `ThresholdAtEpoch`, `ShareCommitment`, `SecretPayload`, `SecretEpoch`, `FinalizedHead`), `StoreSecret(signer, env, epoch, label, aad)`, events (`EventsAt`, `FindEvent`, `FindStoredSecret`) and `WaitForFinalized`. For offline signing, the package-level `PrepareExtrinsic` returns an `UnsignedExtrinsic` with `SigningPayload` and `Assemble` |
| Secrets | `Encrypt`, `Decrypt`, `OpenSecret`, `VerifyPlaintextProof`, `HTTPTransport`, the `Aad*` constants, the `*Call` builders, `SecretID` and `Wipe` |
| Errors | `*ChainError` with a `Kind` (e.g. `KindReadOnly`, `KindDispatch`, `KindKeyRevoked`, `KindFinalityTimeout`), and `*DecryptError` with per-node `Faults` |

The façades in use:

```go
client.Secrets().Store(env, epoch, "prod", mattersdk.AadEnvV1)
client.Deployments().SetSecretRef(deployment, &secretID)
client.Orgs().AuthorizeSecretsAgent(org, project, who)
client.Keys().Authorize(agentKey, scopes)
```

Notes specific to Go:

- **`SecretID` is a u128 value type.** The same type carries deployment and SKU ids.
- **The signed extrinsic is assembled from the metadata.** The code walks the signed
  extensions the runtime declares and **refuses to sign** any it cannot account for.
- **Writes are followed to finalization.** Every façade method, `Call` and `TxAndWait`
  locates the extrinsic by the exact bytes submitted and decodes the outcome. That
  includes a failure wrapped in `proxy.proxy`, which comes back as a `*ChainError` of
  `KindDispatch`, never as a receipt.
- **A stored secret's id comes from its `Secrets.SecretStored` event.** Use
  `client.Chain().FindStoredSecret(receipt.BlockHash, owner)`, which matches the event on
  the owner account.
- **An `ApiKey` is redacted by `String()` and by every `fmt` verb.** `MarshalJSON` returns
  an error. `Close()` wipes the key.

## Guides

- [Connecting](../../../docs/connecting.md): constructors, networks, the mainnet guard, and environment variables
- [Keys and scopes](../../../docs/keys-and-scopes.md)
- [The generic chain surface](../../../docs/chain-surface.md)
- Façades: [secrets](../../../docs/secrets.md) · [deployments](../../../docs/deployments.md) ·
  [resources](../../../docs/resources.md) · [staking](../../../docs/staking.md) ·
  [organizations](../../../docs/organizations.md)
- [Secure signing](../../../docs/secure-signing.md) · [Errors](../../../docs/errors.md) ·
  [Language parity](../../../docs/parity.md)
