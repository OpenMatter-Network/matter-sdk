# Errors

Every failure the SDK raises is typed. Branch on the type or kind, never on the message
text, which may change between versions. The same failure has the same name in every
language, spelled in that language's style.

| Language | Chain client errors | Decrypt errors |
|---|---|---|
| Rust | `SdkError` enum (`#[non_exhaustive]`; keep a catch-all arm) | the same `SdkError` |
| TypeScript | `ClientError`, branch on `.kind` | `DecryptError`, branch on `.kind` |
| Python | exception classes under `ChainError` | `DecryptError`, branch on `.kind` |
| Go | `*ChainError`, branch on `.Kind` via `errors.As` | `*DecryptError`, branch on `.Kind` |

## Chain client

| Rust `SdkError::` | TypeScript / Go kind | Python | Cause | What to do |
|---|---|---|---|---|
| `ReadOnly` | `read-only` / `KindReadOnly` | `ReadOnlyError` | the client has no key or signer | connect with a key or signer ([connecting](connecting.md#pick-a-constructor)) |
| `Config` | `config` / `KindConfig` | `ConfigError` (also a `ValueError`) | inconsistent configuration, e.g. `custom` with no URL, or an unknown `MATTER_NETWORK` | fix the configuration |
| `MainnetNotConfirmed` | `mainnet-not-confirmed` / `KindMainnetNotConfirmed` | `MainnetNotConfirmedError` | a signing client reached mainnet without confirmation | set `MATTER_CONFIRM=yes` or confirm in code, if you mean it ([mainnet guard](connecting.md#the-mainnet-guard)) |
| `WrongNetwork` | `wrong-network` / `KindWrongNetwork` | `WrongNetworkError` | the endpoint serves a different network than configured | fix the URL or the network |
| `Chain { target, … }` | `chain` / `KindChain` | `ChainError` | a read or submit failed: a name did not resolve, the node refused, the call failed | read `target`; for dispatch failures, the runtime's error is in the message |
| `FinalityTimeout { waited }` | `finality-timeout` / `KindFinalityTimeout` | `FinalityTimeoutError` | the extrinsic did not finalize in time | **check the chain before resubmitting**: it may still land |
| `NotPermitted { required, held, … }` | `not-permitted` / `KindNotPermitted` | `NotPermittedError` | a [scoped key](keys-and-scopes.md#scoped-keys) lacks a scope the call needs | widen the key's scopes |
| `NeverAdmitted` | `never-admitted` / `KindNeverAdmitted` | `NeverAdmittedError` (a `NotPermittedError`) | no scoped key may make this call | sign with the member's own key |
| `KeyRevoked` | `key-revoked` / `KindKeyRevoked` | `KeyRevokedError` | the key's grant is gone or points at another member | mint a new key |
| `Unsponsored { principal, … }` | `unsponsored` / `KindUnsponsored` | `UnsponsoredError` | the call is in scope, but nobody can pay the fee | fund the member or their billing org |
| `Dispatch` | `dispatch` / `KindDispatch` | `DispatchError` | a delegated call landed, but the call it wrapped failed | handle it as the runtime error it names |
| `BadAmount` | TypeScript throws `AmountError`; Go returns a plain `error` | `ValueError` | an amount string did not parse ([amounts](chain-surface.md#amounts)) | fix the input; nothing is ever truncated |

Python has two lower-level classes:
`PoolRejectedError` (the node refused the extrinsic before any block) and
`OuterDispatchError` (the `Proxy.proxy` wrapper itself failed). The client translates them
into the scoped-key errors above for a delegated key. From a direct client, or from
`ChainClient` on its own, they surface as they are.

## Keys

Parsing a key raises `KeyError` in Rust (`Empty`, `UnsupportedScheme`, `Malformed`,
`Derivation`, `NoKey`). TypeScript and Python raise an error at `new ApiKey(…)` /
`ApiKey(…)`, and Go returns `ErrBadAPIKey`. None of them contains any part of the key.
`UnsupportedScheme` means a reserved prefix such as `secp256k1:`, and names it from the
SDK's own list; any other unknown prefix is `Malformed`
([key formats](keys-and-scopes.md#api-keys)).

A malformed scope string, such as `deployments` with no `:r` or `:w`, raises
`ScopeParseError` in Rust (`MissingAccess`, `UnknownScope`, `InvalidAccess`), a plain
`Error` in TypeScript, `ValueError` in Python, and a plain `error` in Go. The message
echoes the input, because scopes are not secret.

## Decrypt

A threshold decrypt fails in one of four ways ([how decrypt works](secrets.md#how-decrypt-works)):

| Kind | Rust | Cause | What to do |
|---|---|---|---|
| `quorum` | `QuorumUnavailable { needed, active, faults }` | fewer than `t` healthy nodes answered | read `faults`; retry later, or check node health |
| `epoch` | `EpochRotated { served, provided }` | the committee rotated to a new epoch during the request | re-read the committee state and retry |
| `transport` | `Transport`, `BadResponse` | a malformed or oversized response | retry; report it if it persists |
| `crypto` | `Core(…)` | verification, aggregation or opening failed | see below |

Each `NodeFault` names the node's `index`, `endpoint` and the `stage` where it dropped
out: `health`, `inactive`, `partial-decrypt`, `epoch-mismatch`, or `protocol-version`
(Rust `FaultStage::{Health, Inactive, PartialDecrypt, EpochMismatch, ProtocolVersion}`).
A fault never carries request material.

In the core, `CoreError::Aggregate` means one subset's partials did not combine. It
surfaces as a `crypto` / `Core` error; decrypt again to draw a different random quorum. `CoreError::Aead` is terminal: the key, epoch or AAD
tag is wrong. In Rust, `AadMismatch` catches the most common cause first. It refuses
before any node is contacted when the secret on chain is sealed under a different tag
than the one you asked for.

## The C ABI

`matter_sdk.h` returns `MSDK_OK` (0), `MSDK_ERR_INVALID_ARG` (−1), `MSDK_ERR_CRYPTO`
(−2), `MSDK_ERR_KEY` (−3) or `MSDK_ERR_INTERNAL` (−4). Go maps these to `ErrInvalidArg`,
`ErrCrypto`, `ErrBadAPIKey` and `ErrInternal`.
