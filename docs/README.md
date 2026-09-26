# MatterSDK documentation

Start with the [project README](../README.md) to install the SDK and run a first program,
then [concepts](concepts.md) for the vocabulary. Every guide shows Rust, TypeScript,
Python and Go side by side.

## Guides

- [**Connecting**](connecting.md): constructors, networks, the mainnet guard, chain
  properties, environment variables.
- [**The chain surface**](chain-surface.md): `tx`, `query`, runtime APIs and constants
  for any pallet; receipts, amounts, escape hatches.
- [**Keys and scopes**](keys-and-scopes.md): API key formats, member-tied scoped keys,
  and minting and revoking keys with the `keys` façade.
- [**Deployments**](deployments.md): requesting workloads, sealed env and TLS,
  post-quantum WireGuard peers, QuantumGuard.
- [**Resources**](resources.md): registering and operating compute resources.
- [**Staking**](staking.md): bonding, nominating, nomination pools.
- [**Organizations**](organizations.md): organizations, members, budgets, secrets agents.
- [**Threshold secrets**](secrets.md): sealing, the AAD registry, storing, granting,
  recovering, and how decrypt works.
- [**Secure signing**](secure-signing.md): HSM, KMS and remote signers; operating an
  `ApiKey` safely.

## Reference

- [**Errors**](errors.md): every error in every language, and what to do about it.
- [**Language parity**](parity.md): where the four languages differ.
- [**Conformance vectors**](../testvectors/README.md): the fixtures that keep them
  byte-for-byte identical.
- [**Examples**](../examples/README.md): runnable programs, from offline demos to live
  end-to-end harnesses.

## Design and project

- [**Architecture**](architecture.md): the shared core, the per-language shells, the C
  ABI.
- [**Security policy**](../SECURITY.md) · [**Contributing**](../CONTRIBUTING.md) ·
  [**Releasing**](../RELEASING.md) · [**Changelog**](../CHANGELOG.md)
