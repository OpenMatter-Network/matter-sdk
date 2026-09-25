# MatterSDK documentation

Start with the [project README](../README.md) for install and a first program.

## Guides

- [**The OpenMatter client**](client-guide.md): connecting, the generic `tx` / `query` /
  `runtime_api` surface, API keys and scopes, façades, receipts, amounts, errors.
- [**Secure signing**](secure-signing.md): where your key should live, what an in-process
  `apiKey` trades away, and how to plug in an HSM, KMS, or remote signer.

## Reference

- [**Language parity**](parity.md): what each binding has and where they differ.
- [**Conformance vectors**](../testvectors/README.md): the fixtures that keep the bindings
  byte-for-byte identical, and how to regenerate them.
- [**Security policy**](../SECURITY.md): threat model, secret handling, reporting.

## Design

- [**Architecture**](architecture.md): the shared cryptographic core, the data flow of a
  sealed secret, and key rotation.
