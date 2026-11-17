# Language parity

All four languages share one Rust core for cryptography and key handling
([architecture](architecture.md)). The chain client, the committee client and the
façades are written natively in each language, and Rust-emitted
[conformance vectors](../testvectors/README.md) hold them to the same bytes. This page
is the single list of where the languages differ.

## What every language has

- **The crypto core:** `seal_for`, `binding_id_for`, `binding_commits_to`, `encrypt`,
  `signing_payload`, `lagrange_for`,
  `verify_plaintext_proof`, `open_secret`, and the protocol constants.
- **Keys:** `ApiKey` in every format, with the same guardrails, and scope parsing.
- **Committee:** threshold `decrypt` with health probing, a random quorum, per-node
  faults, Ethereum-auth fields forwarded from a custom `Signer`, and the offline call
  builders.
- **The chain client:**
  - generic `tx` / `query` / runtime API / `constant`
  - the mainnet guard and effective decimals
  - lossless amounts
  - scoped-key delegation, including `MATTER_PRINCIPAL` and the
    `KeyRevoked` / `Unsponsored` / `Dispatch` classification
- **Every façade:** `accounts`, `network`, `fees`, `secrets`, `deployments`,
  `resources`, `staking`, `orgs`, `keys`. Every method is pinned in both directions: writes by
  `testvectors/facade_calls.json`, reads by `testvectors/facade_reads.json`.
- **Which block a read sees:** the latest finalized one, for the generic `query` and
  runtime API calls and for every façade read.
- **Façade reads:** at the latest finalized block, or one pinned with `at`; strict
  decoding; and one [canonical JSON](reading-state.md#canonical-json) shape. Every
  language replays the same vectors through its real façade, and a nightly job
  (`scripts/compare-live-reads.sh`) holds all four to the same bytes on a live chain.

## Where they differ

| Capability | Rust | TypeScript | Python | Go |
|---|---|---|---|---|
| Package | `matter-sdk` (git tag; `chain` feature) | `@openmatter-network/matter-sdk` (+ `-core`) | `matter-sdk` (`[sdk]` extra) | `mattersdk` (cgo) |
| Chain signer seam | `KeySigner` | `KeySigner` (sync or async `sign`) | `connect_with_keypair` (keypair-shaped object) | `ExtrinsicSigner` |
| `tx` arguments | `Vec<Value>` | positional array | `dict` of named params | `Call(pallet, method, args...)` |
| Submit without waiting | — | — | — | `Tx(types.Call)` |
| Finality timeout | `finality_timeout` | `finalityTimeoutMs` | `finality_timeout=` (seconds) | `FinalityTimeout` |
| Runtime API call | `runtime_api(trait, method, args)` | `runtimeApi(stateCallName, argsHex)` → hex | `runtime_api(name, args, return_type)` → decoded | `RuntimeAPI(name, args)` → bytes |
| Account argument of a read | `impl Into<AccountId>`; `parse_account(text)` | `Uint8Array` or text | `bytes` or text | `[]byte`; `ParseAccount(text)` |
| Account in a read result | `Address` | SS58 `string` | SS58 `str` | `Address` |
| Text in a read result | `Text` (`Utf8` / `Raw`) | `string` or `{ hex }` | `str` or `bytes` | `Text` |
| Read result as canonical JSON text | `serde_json::to_string(&result)` | `canonicalJson(result)` | `canonical_json(result)` | `CanonicalJSON(result)` |
| Read result as a JSON value | `serde::Serialize` | `toJson(result)` | `to_json(result)` | `json.Marshal(result)` |
| Block hash in a read result | `[u8; 32]` | `0x` hex `string` | `0x` hex `str` | `[32]byte` |
| 64-bit integer in a read result | `u64` | `bigint` | `int` | `uint64` |
| Block pin for a read | `at([u8; 32])` | `at(bytes or hex)` | `at(bytes or hex)` | `At([32]byte)` |
| Receipt events | names | names + fields, `requireEvent`, `secretIdFromReceipt` | names + attributes, `require_event` | names + decoded `Fields`, block-level helpers |
| Secret recovery | one call: `secrets().recover(id, aad)` | `decrypt` + your reads | `decrypt` + `chain.committee_at(epoch)` | `Decrypt` + `Chain().CommitteeAt(epoch)` |
| Finalized head for `decrypt` | inside `recover`; else `rpc()` | `finalizedHead()` | `committee_at(epoch).block_hash` | `CommitteeAt(epoch).BlockHash` |
| Offline extrinsic signing | via `subxt()` | via @polkadot | via substrate-interface | `PrepareExtrinsic` |
| Committee transport timeout | 30 s | 30 s | 15 s | 20 s |
| Browser build | — | `-core` (`wasm-web`) | — | — |
| [OpenMatter Login](login.md) | byte contract only (`matter_sdk::login`) | `-core`: contract, `oidcSigner`, attestations, `openLogin` | — | — |
| Logging | `tracing` | `MatterConfig.logger` | stdlib `logging` | `*slog.Logger` |
| Error model | `SdkError` enum | `ClientError.kind` | exception classes | `ChainError.Kind` |

"—" means the language does not offer it; [errors](errors.md) maps the error models to
one another.

## Implementation notes

These are for contributors. Users never need them.

- **Signed extrinsics.** Rust uses subxt, TypeScript @polkadot/api, and Python
  substrate-interface. Go assembles extrinsics itself, because GSRPC's signer does not
  cover every extension the runtime declares. It walks the extensions in the metadata
  and refuses to sign one it cannot account for. Synthetic-metadata unit tests pin its
  layout.
- **Delegated writes.** Each language nests the inner call in `Proxy.proxy` natively.
  Go's encoding relies on GSRPC emitting `pallet ++ call ++ args`, and `scopes_test.go`
  pins the bytes.
- **Detecting a failed delegated call.** The outer extrinsic succeeds even when the
  wrapped call fails, so every language reads the `ProxyExecuted` event:
  - Python scans the triggered events itself, because substrate-interface's
    `is_success` is true in this case.
  - Go decodes the result from SCALE bytes, because GSRPC's rendered field cannot
    tell `Ok(())` from `Err(Other)`.
- **Scope checks from Go's `Tx`.** A prebuilt call arrives encoded, so Go decodes it
  against metadata. It narrows the requirement only when an optional field decodes to
  exactly `None`.
- **Python key derivation.** substrate-interface cannot derive a hex seed with
  junctions, so `ApiKeySigner` adapts an `ApiKey` into a keypair-shaped object that
  delegates to the core. There is one derivation, not two.
- **Metadata versions.** Go and Python read V14 metadata; Rust and TypeScript read V15.
  Scoped-key support is detected from the `BudgetsApi_agent_key` runtime API in Rust
  and TypeScript, and from the `Budgets.authorize_agent_key` call in Python and Go.
  Both ship in the same runtime, and a Rust test pins that.

## Roadmap

- **Ethereum (EIP-712) keys.** `ApiKey` reserves the `secp256k1:` scheme, and the
  request types carry the Ethereum fields, so adding it is non-breaking.
  `EthSigning` and `StakingGateway` join the façades then.
- **A mainnet genesis pin** joins the testnet pin in the mainnet guard once the mainnet
  endpoint serves it.
