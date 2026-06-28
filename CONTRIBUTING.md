# Contributing to MatterSDK

Thanks for your interest. MatterSDK is a showcase of how we build at Open Matter, so we
hold contributions to the same bar as the rest of the codebase.

## Ground rules

- **Never re-implement the cryptography.** All cryptographic logic lives in
  `matter-vault-core` (which wraps `matter-crypto`). A language binding *calls* the core;
  it does not port BGV, ZK proofs, or aggregation. If you think a crypto change is needed,
  open an issue first.
- **Keep the core pure.** `matter-vault-core` has no networking, async, or signing. Those
  belong in the per-language shells. The core must keep compiling to native, `wasm32`, and
  a C ABI.
- **Cross-language parity is enforced by vectors.** If you change a core output, regenerate
  the [conformance vectors](testvectors/) (`cargo test -p matter-vault-core --test roundtrip
  -- --ignored`) and make sure every binding's vector test still passes. A binding that
  disagrees with the core is a bug in the binding.
- **Secrets never leak.** No secret material in logs, errors, panics, or `Debug` output.
  Recovered plaintext stays in a zeroizing buffer.

## Local setup

Clone the sibling core repos next to this one (see the README "Building from source").

```bash
cargo test                # Rust core + SDK
cargo fmt --all --check -- --config imports_granularity=Module,group_imports=StdExternalCrate,imports_layout=HorizontalVertical
cargo clippy --all-targets -- -Dwarnings
```

For the TypeScript package, see `packages/typescript/README.md`.

## Style

- Match the surrounding code ("chameleon coding"). Prefer enums/constants over string
  literals and magic numbers. Keep comments brief and about *why*, not *what*.
- Document every public item (the workspace denies `missing_docs`).
- Write the test first for any business logic.

## Pull requests

- Keep PRs focused. One concern per PR.
- Describe the user-facing change and the reasoning.
- CI (fmt, clippy, build, test, vector conformance) must be green.

By contributing you agree your contributions are licensed under Apache-2.0.
