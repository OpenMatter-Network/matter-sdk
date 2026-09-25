# Contributing to MatterSDK

## Ground rules

- **Never re-implement the cryptography.** All cryptographic logic lives in
  `matter-sdk-core` (which wraps `matter-crypto`). A binding *calls* the core; it does
  not port BGV, ZK proofs, or aggregation. Open an issue before proposing a crypto change.
- **Keep the core pure.** `matter-sdk-core` has no networking, async, or signing; those
  belong in the per-language shells. It must keep compiling to native, `wasm32`, and a
  C ABI.
- **Cross-language parity is enforced by vectors.** If you change a core output,
  [regenerate the conformance vectors](testvectors/README.md#regenerate) and keep every
  binding's vector test passing. A binding that disagrees with the core is a bug in the
  binding.
- **Secrets never leak.** No secret material in logs, errors, panics, or `Debug` output.
  Recovered plaintext stays in a zeroizing buffer, or one the caller can `wipe`.

## Without access to the core

Every binding compiles the private core (`matter-crypto`, `matter-kgc`), so building or
testing from source needs read access to those repositories. Without it you can still
report issues, improve docs and examples, and test against the published npm, PyPI, and
Go packages. On a fork PR, CI jobs that fetch the core fail at their first step; a
maintainer runs them for you.

## Local setup

The core crates are git-tag dependencies fetched over SSH, so you need a GitHub SSH key
with access to the `openmatter-network` repos
([Building from source](README.md#building-from-source)).

```bash
cargo test                # Rust core + SDK
cargo test -p matter-sdk --features chain   # the chain client (default-off feature)
cargo fmt --all --check -- --config imports_granularity=Module,group_imports=StdExternalCrate,imports_layout=HorizontalVertical
cargo clippy --all-targets -- -Dwarnings
cargo clippy -p matter-sdk --features chain --all-targets -- -Dwarnings
cargo deny check          # supply-chain gate (deny.toml)
```

Other bindings: [`packages/typescript-core`](packages/typescript-core/README.md),
[`packages/typescript`](packages/typescript/README.md),
[`bindings/python`](bindings/python/README.md), and
[`packages/go/mattersdk`](packages/go/mattersdk/README.md).

## Style

- Match the surrounding code. Prefer enums/constants over string literals and magic
  numbers. Keep comments brief and about *why*, not *what*.
- Document every public item (the workspace denies `missing_docs`).
- Write the test first for any business logic.

## Pull requests

- One concern per PR. Describe the user-facing change and the reasoning.
- CI (fmt, clippy, build, test, vector conformance, supply chain) must be green.

By contributing you agree your contributions are licensed under Apache-2.0.
