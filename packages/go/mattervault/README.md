# mattervault (Go)

**Status: scaffold / proof-of-binding.** See [`docs/parity.md`](../../../docs/parity.md).

This package binds Go to the one shared MatterVault cryptographic core via cgo over
`crates/matter-vault-ffi`. The implemented surface (`Encrypt`, `SigningPayload`,
`LagrangeFor`) calls real core crypto and is checked against the same
cross-language fixtures as the Rust and TS bindings. The committee client, quorum
orchestration, `Signer` abstraction, and `OpenSecret` are not yet implemented.

## Build & test

cgo needs the FFI staticlib built first:

```bash
cargo build -p matter-vault-ffi --release   # -> target/release/libmatter_vault_ffi.a
cd packages/go/mattervault
go test ./...                               # runs the conformance tests
```

## Why cgo over a shared Rust core

The RLWE/BGV threshold cryptography is novel and lives in exactly one audited
implementation (`matter-crypto`, wrapped by `matter-vault-core`). Re-implementing it
in Go would be a second, divergent copy of lattice crypto — a security and
correctness hazard. cgo lets Go call the same core the Rust and TypeScript SDKs use.

## Roadmap to parity

1. Add `OpenSecret` to the FFI (it takes the partial array — modeled as a C array of
   `MvBuf` quads).
2. Port the committee HTTP client + quorum loop using `net/http` (idiomatic Go; the
   crypto stays in the core).
3. Add a `Signer` interface mirroring the Rust/TS one.
