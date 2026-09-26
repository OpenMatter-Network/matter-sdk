# Contributing to MatterSDK

MatterSDK is one Rust core behind four language shells: Rust, TypeScript, Python and Go.
This page covers the rules that keep them in agreement, how to build and test each one,
and what CI checks in the docs.

## Ground rules

- **Never re-implement the cryptography.** All of it lives in `matter-sdk-core`, which
  wraps the private `matter-crypto`, and API-key derivation lives in `matter-sdk-key`. A
  binding *calls* the cores and never ports BGV, the ZK proofs, aggregation or SURI
  derivation. Open an issue before proposing a crypto change.
- **Keep the cores pure.** `matter-sdk-core` and `matter-sdk-key` do no networking, run
  nothing async and read no environment variables. They must keep compiling to native
  code, `wasm32-unknown-unknown` and the C ABI.
- **Conformance vectors enforce parity.** Every cross-language contract is a fixture in
  [`testvectors/`](testvectors/README.md) that Rust emits and every binding replays. If
  you change a core output, a scope-table row or a façade method, regenerate the fixture
  and keep every binding's replay passing. A binding that disagrees with the fixture has
  a bug in the binding.
- **Secrets never leak.** Secret material never appears in logs, errors, panics or debug
  output. Recovered plaintext stays in a zeroizing buffer or one the caller can `wipe`.
  `*_insecure_dev_only` helpers stay out of shipped code ([SECURITY.md](SECURITY.md)).

## Without access to the core

Every binding compiles the private core (`matter-crypto`, `matter-kgc-proto`,
`matter-kgc-config`), so building from source needs read access to those repositories.
Without that access you can still report issues, improve docs and examples, and test
against the published npm, PyPI and Go packages. On a PR from a fork, CI jobs that fetch
the core fail at their first step, and a maintainer runs them for you.

## Local setup

The core crates are git-tag dependencies fetched over SSH, so you need a GitHub SSH key
with access to the `openmatter-network` repositories. `.cargo/config.toml` sets
`net.git-fetch-with-cli`, and CI authenticates with a token instead
(`.github/actions/fetch-core-crates`).

**Rust**, from the repository root:

```bash
cargo test --workspace                              # cores, FFI, SDK
cargo test -p matter-sdk --features chain           # the chain client (default-off feature)
cargo fmt --all -- --config imports_granularity=Module,group_imports=StdExternalCrate,imports_layout=HorizontalVertical
cargo clippy --workspace --all-targets -- -Dwarnings
cargo clippy -p matter-sdk --features chain --all-targets -- -Dwarnings
cargo deny check                                    # supply-chain gate (deny.toml)
```

`bindings/wasm` and `bindings/python` are outside the Cargo workspace, so run clippy in
each of them separately. The ZKP round-trip tests do real proving and take about 30 s
each. They are slow, not hung.

**TypeScript** needs Node 22 and `wasm-pack`:

```bash
cd packages/typescript-core && npm ci && npm run build && npm test
cd packages/typescript      && npm install && npm run typecheck && npm test
```

**Python** needs maturin, and the chain tests need `substrate-interface`:

```bash
cd bindings/python
pip install maturin pytest 'substrate-interface>=1.7'
maturin build --release && pip install --force-reinstall --no-deps target/wheels/matter_sdk-*.whl
pytest -q
```

**Go** needs cgo. Build the static core first, then run from `packages/go/mattersdk`:

```bash
cargo build -p matter-sdk-ffi --release
cd packages/go/mattersdk && gofmt -l . && go vet ./... && go test ./...
```

## Documentation

CI keeps the docs honest in five places:

- **Compiled snippets.** `crates/matter-sdk/tests/guide_examples.rs` builds the README
  quickstart, the `KeySigner` example in `docs/secure-signing.md` and the QuantumGuard
  request in `docs/deployments.md`, then checks that each doc contains that code
  character for character. To change a snippet, edit the test first, run `cargo fmt`,
  then paste the result into the doc.
- **Façade coverage.** `crates/matter-sdk/tests/facade_calls.rs` fails if a façade method
  is missing from its guide, or if a façade is not named in the README and
  `docs/parity.md`.
- **Links.** `scripts/check-doc-links.sh` resolves every relative link. The published
  package READMEs (`bindings/python`, `packages/typescript*`) must use absolute URLs,
  because they are rendered on npm and PyPI.
- **The platform table** in the README is generated. Run `scripts/platform-table.sh` and
  paste its output between the markers, and never hand-edit it.
- **Names.** `scripts/check-old-names.sh` rejects pre-2.0 package names everywhere except
  `CHANGELOG.md`.

## Style

- Match the surrounding code. Prefer enums and constants over string literals and magic
  numbers. Keep comments short, and make them say *why*, not *what*.
- Document every public item; the workspace denies `missing_docs`.
- Write the test first for any business logic.

## Pull requests

- Keep each PR to one concern. Describe the user-facing change and why it is needed.
- CI must be green: guards, fmt, clippy, build, tests, vector conformance, supply chain,
  and all four bindings.
- Add a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) for any
  user-visible change.

By contributing you agree that your contributions are licensed under Apache-2.0.
