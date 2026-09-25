# Language parity

Bindings share the Rust cores ([architecture](architecture.md)).

All four bindings implement the full crypto core (`encrypt`, `signingPayload`, `lagrangeFor`,
`verifyPlaintextProof`, `openSecret`), committee orchestration and call builders, `ApiKey`
ingestion, signed-extrinsic assembly, the generic `tx`/`query`/`runtimeApi` surface with the
mainnet guard, the six façades, and the full scoped-key contract (mode resolution,
`proxy.proxy` wrapping and `ProxyExecuted` unwrapping, local scope table incl.
argument-sensitive rows, `KeyRevoked`/`Unsponsored` mapping). Each is pinned by a fixture or
tested per binding. Differences are listed below.

The bring-your-own-signer seam differs: Rust and TypeScript take a `KeySigner` (account id +
`sign`), Go an `ExtrinsicSigner` (account id + `SignExtrinsic`), and Python an in-process
keypair.

## How conformance is guaranteed

Every cross-language contract is a fixture emitted by Rust and replayed by every binding;
bindings may differ in ergonomics, never in bytes. What each fixture pins, which direction
it is checked, and how to regenerate:
[`testvectors/README.md`](../testvectors/README.md#regenerate).

## Per-binding implementation notes

**Wrapping writes in `proxy.proxy`.** Rust nests via subxt's
`DefaultPayload::into_value`; TypeScript passes the inner call object to
`api.tx.proxy.proxy`; Python nests one `compose_call` in another; Go passes the inner
`types.Call` as an argument. Go's encoding relies on GSRPC's reflection encoder emitting
`pallet ++ call ++ args`, so `scopes_test.go` pins the bytes.

**Detecting a wrapped failure.** substrate-interface's `receipt.is_success` is **true**
when the wrapped call failed, so Python scans `triggered_events` itself. @polkadot's
`result.dispatchError` likewise sees only the outer extrinsic. Go decodes the
`ProxyExecuted` result from SCALE bytes: GSRPC's rendered event field discards variant
names, so `Ok(())` and `Err(Other)` are indistinguishable there.

**Python mode resolution.** `connect_with_keypair` resolves delegation like
`connect_with_api_key`, since it is Python's only bring-your-own-key path.

**Go finality.** Every façade write, `Call`, and `TxAndWait` follow the extrinsic to
finalization, locating it by the exact submitted bytes, and return a wrapped failure as
`KindDispatch`. `Tx` (prebuilt call) is fire-and-forget. Because `Tx` receives an encoded
call, the argument-sensitive scope rows decode it against metadata, narrowing **only**
when the field decodes to exactly `Option::None` and taking the wider set otherwise.

**Signed-extrinsic assembly.** Rust uses subxt, TypeScript `@polkadot/api`, Python
`substrate-interface`. Go hand-assembles, because GSRPC's default signer does not cover
`CheckMetadataHash` / `WeightReclaim`; it walks the extensions the metadata declares and
**refuses to sign** one it cannot account for. Its layout is pinned by synthetic-metadata
unit tests.

**Python key derivation.** `substrate-interface`'s `create_from_uri` cannot derive a hex
phrase with junctions, so `ApiKeySigner` adapts an `ApiKey` into a keypair-shaped object
that delegates to the shared core: one derivation. `ChainClient.keypair_from_seed`
remains for callers needing a real `Keypair` and raises on junctions it cannot apply.

**`Secrets::recover` is Rust-only.** It composes the chain reads a decrypt needs (the
secret's payload and epoch, and `KgcApi`'s committee at that epoch) with
`recover_secret`, returning zeroizing plaintext. Other bindings expose the primitives
(`open_secret` / `recover_secret`) and the reads. It is not in `facade_calls.json`
because it submits nothing.

Live e2e harnesses: see [README](../README.md#live-end-to-end-test).

## Notes & remaining work

- **Ethereum / EIP-712 signing** is reserved, not implemented. `ApiKey` carries a scheme
  discriminant (a `secp256k1:` key reports "unsupported scheme") and the wire types carry
  the Ethereum fields, so adding it (porting the dashboard's EIP-712 typed-data builder)
  is non-breaking. `pallet-eth-signing` and `pallet-staking-gateway` stay out of the
  façades until then.
- **Mainnet genesis hash** is unpinned, so the mainnet guard falls back to the token
  symbol. Pin it from `chain_getBlockHash(0)` once the endpoint answers.
- **Python remote-signer seam.** Python takes an in-process keypair
  (`connect_with_keypair`), not a `connect_with_signer` callback, so the
  key-never-in-process posture is not yet reachable from Python.
