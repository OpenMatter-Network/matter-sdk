# Changelog

All notable changes to MatterSDK are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). One version covers every
binding: the Rust crates, both npm packages, the PyPI wheel and the Go module are
released together from one tag (see [`RELEASING.md`](RELEASING.md)).

## [2.1.1]

The first release published to public registries. Nothing in the SDK's API changes;
what changes is that the install commands in the documentation now work.

### Added

- **npm:** `@openmatter-network/matter-sdk-core` and `@openmatter-network/matter-sdk` are
  published to the public npm registry, with provenance. Both declare an `exports` map
  and `engines.node >= 22`.
- **PyPI:** `pip install matter-sdk` (and `matter-sdk[sdk]`). abi3 wheels for CPython 3.9+
  on Linux x86-64 and arm64 (glibc 2.17+ and musl 1.2+) and macOS 11+ on Intel and Apple
  silicon. Wheels only — there is no source distribution, because the cryptographic core
  is not public.
- **Go:** `go get github.com/openmatter-network/matter-sdk-go/v2`. The module ships the
  Rust core as a prebuilt static library for the same six platforms, so it needs no Rust
  toolchain. It needs cgo; on Alpine and other musl systems build with `-tags musl`.
- **Rust:** the supported way to depend on the crate — a git tag — is documented, and CI
  now proves it from a crate outside this workspace, on the declared MSRV (1.90).
- A release pipeline that builds every artifact once, proves each one from a consumer's
  point of view, publishes those exact bytes, and re-checks them from the registries.

### Changed

- **Go binaries link the core statically.** `LD_LIBRARY_PATH` is no longer needed — for
  consumers, or for `go test` and the examples in this repository.
- The `sdk` extra of the Python package declares `scalecodec`, which it imports directly.
- The release version has one home (`Cargo.toml`). `scripts/set-version.sh` now refreshes
  the five lockfiles as well, and a tag that disagrees with the manifests fails the
  release before anything is built.
- GitHub Release assets: one `matter-sdk-ffi-<version>-<platform>.tar.gz` per platform
  (static library + C header). The shared library, the wheel and the Go source bundle are
  no longer attached; the wheel and the Go module now come from their registries.

### Fixed

- The Go suite could not start without `LD_LIBRARY_PATH`, which CI never set.
- CI's MSRV job named one toolchain and built on another: `rust-toolchain.toml` outranks
  the default toolchain the job installed. It now selects the declared MSRV explicitly.
- A `DEPS_PAT` that is present but expired now fails at the step that uses it, naming the
  repository it cannot read, instead of minutes later inside cargo.

## [2.1.0] - 2026-09-21

Tagged, never released: the release workflow failed before building anything, and the
manifests at this tag still said 2.0.0. The tag stays where it is — a pushed tag is never
moved — and its changes ship in 2.1.1.

### Changed

- `register_wg_peer` takes the post-quantum ciphertext; fixtures regenerated against
  runtime spec 330.

## [2.0.0] - 2026-09-20

Tagged, never released (the release workflow failed). Its changes ship in 2.1.1.

### Changed

- **Renamed** from `matter-vault` to `matter-sdk` throughout: the crates
  (`matter-sdk`, `matter-sdk-core`, `matter-sdk-key`, `matter-sdk-ffi`), the npm packages
  (`@openmatter-network/matter-sdk-core`, `@openmatter-network/matter-sdk`), the Python
  distribution and module (`matter-sdk`, `matter_sdk`), the Go package (`mattersdk`) and
  the C ABI prefix (`msdk_`). Nothing had been published under the old names to a public
  registry.

## Earlier versions

`v1.1.0` – `v1.3.2` (2026-09-08 – 2026-09-16) exist as tags only; no release was produced
for them. `v0.2.0` – `v1.0.0` have GitHub Releases with Linux x86-64 artifacts under the
`matter-vault` names. None of them was published to a public package registry.
