# mattervault (Go)

The Go client for MatterVault and the OpenMatter chain. See
[`docs/parity.md`](../../../docs/parity.md) for what has landed here versus the
other bindings.

Cryptography **and** API-key derivation come from the one shared Rust core via cgo
over `crates/matter-vault-ffi`, so this package agrees byte-for-byte with Rust,
TypeScript, and Python against `testvectors/`. On top of that core it adds the
committee HTTP client, the quorum loop, the `Signer` abstraction, and a chain client
that signs and submits extrinsics.

## Build & test

cgo needs the FFI library built first:

```bash
cargo build -p matter-vault-ffi --release   # -> target/release/libmatter_vault_ffi.{a,so}
cd packages/go/mattervault
go test ./...
```

The LDFLAGS link the **cdylib**, so a binary using this package needs the library on
its search path at run time:

```bash
LD_LIBRARY_PATH=../../target/release go run .
```

## Quick start

```go
// MATTER_API_KEY / MATTER_NETWORK / MATTER_RPC_URL / MATTER_CONFIRM.
// No key set connects read-only, which is a legitimate outcome rather than an error.
client, key, err := mv.ConnectFromEnv()
defer client.Close()
if key != nil {
    defer key.Close()
}

// Reads: any pallet the runtime exposes, resolved by name from live metadata.
raw, err := client.QueryRaw("Secrets", "NextSecretId")
epoch, err := client.RuntimeAPI("KgcApi_dkg_epoch", nil)

// Amounts are *big.Int plancks — uint64 overflows at 10^18.
amount, err := client.ParseAmount("1.5")

// Writes: a curated façade, or any call through the generic surface.
txHash, err := client.Staking().Bond(amount, payee)
txHash, err = client.Secrets().Revoke(secretID, target)
```

`ChainClient` remains the layer underneath and stays usable directly for anything the
client does not cover — `client.Chain()` returns it.

An `ApiKey` is redacted through `String()` and every `fmt` verb, and
`MarshalJSON` **errors** rather than emitting a placeholder — a silent placeholder
would pass code review. See [`docs/secure-signing.md`](../../../docs/secure-signing.md).

## Why cgo over a shared Rust core

The RLWE/BGV threshold cryptography is novel and lives in exactly one audited
implementation (`matter-crypto`, wrapped by `matter-vault-core`). Re-implementing it
in Go would be a second, divergent copy of lattice crypto — a security and
correctness hazard. cgo lets Go call the same core the other SDKs use.

The same argument applies to **key derivation**, which is why `NewApiKey` goes
through the FFI rather than go-subkey: the parts that are easy to get wrong natively
are applying SURI junctions, refusing a phrase-less URI that would fall back to the
public development phrase, and reporting a reserved `secp256k1:` scheme as
unsupported rather than malformed.

## Notes specific to this binding

- **`SecretID` is a u128 value type**, not a `uint64`. On chain
  `SecretIdentifier` is a u128; carrying it as a `uint64` was a silent-truncation
  trap and a parity break with the other three bindings.
- **The signed extrinsic is hand-assembled**, because go-substrate-rpc-client v4.2.1
  does not encode this runtime's `CheckMetadataHash` / `WeightReclaim` signed
  extensions. `extrinsic.go` walks the extensions the metadata *declares* and
  **refuses to sign** one it cannot account for, rather than hardcoding a layout that
  would silently break on the next runtime upgrade.
- **Finality is confirmed by a domain predicate**, not by extrinsic-hash matching —
  see `WaitForFinalized`. Confirming the *effect* ("is the secret readable at this
  block?") is both simpler and a stronger guarantee than confirming presence.

- **Amounts are `*big.Int`**, not a fixed integer: `uint64` overflows at 10¹⁸, so a
  modest balance on this chain does not fit.
- **`StoreSecret` reads the id from the chain's own `Secrets.SecretStored` event**,
  matched on the owner account, rather than predicting it from the `NextSecretId`
  counter. Two concurrent submitters read the same counter, so the prediction could
  confirm someone else's secret.

## Façades

The five curated façades, reachable as accessors:

```go
client.Secrets().Store(env, epoch, "prod", mv.AadEnvV1)
client.Staking().Bond(amount, payee)
client.Deployments().SetSecretRef(deployment, &secretID)
client.Orgs().AuthorizeSecretsAgent(org, project, who)
```

A façade is a convenience, not a gate: anything not covered is one `client.Tx(call)`
away. The surface is pinned by `testvectors/facade_calls.json` and replayed by
`facade_test.go` **both ways** — a fixture row without a method fails, and a method
without a row fails.
