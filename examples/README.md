# Examples

Runnable programs for every language. Start with a `client-*` example. It is read-only
by default and covers the surface most integrations use.

| Example | Network | Costs gas | What it shows |
|---|---|---|---|
| [`client-rust`](client-rust) · [`client-typescript`](client-typescript) · [`client-python`](client-python) · [`client-go`](client-go) | testnet | **no**, unless `MATTER_SUBMIT=yes` | Connecting from an `apiKey` (or read-only), chain properties, `query` / `runtimeApi` / `constant`, lossless amounts, and a façade write (`staking.chill`) behind the submit gate |
| [`delegated-e2e`](delegated-e2e) (Rust) | testnet | **no**, unless `MATTER_SUBMIT=yes` | A member-tied scoped key: the resolved `Mode`, a local `NeverAdmitted` refusal, a local `NotPermitted` refusal, and a write wrapped as the member |
| [`rust`](rust) · [`typescript`](typescript) | none | no | Seal and recover against an in-process committee. The TypeScript demo replays `testvectors/open_secret.json` |
| [`rust-e2e`](rust-e2e) · [`e2e`](e2e) (TypeScript) · [`python-e2e`](python-e2e) · [`go-e2e`](go-e2e) | testnet | **yes** | A full Secrets round trip: seal → `Secrets.store_secret` → read back → threshold-decrypt → compare |

## Environment

**Keys come from the environment, never from argv.** Anything passed in argv ends up in
shell history and in `ps` output.

The SDK's own variables are documented in
[Connecting → Environment variables](../docs/connecting.md#environment-variables):
`MATTER_API_KEY`, `MATTER_SIGNER_SEED`, `MATTER_NETWORK`, `MATTER_RPC_URL`,
`MATTER_CONFIRM` and `MATTER_PRINCIPAL`. The examples add these:

| Variable | Used by | Default | Meaning |
|---|---|---|---|
| `MATTER_API_KEY` | `client-*` | — | The key to act as. It falls back to `MATTER_SIGNER_SEED`, then `TEST_KEY`. If none is set, the client connects read-only. |
| `MATTER_API_KEY` | `delegated-e2e` | — | **Required**, with no fallback. The scoped key exactly as the dashboard shows it. |
| `MATTER_SIGNER_SEED` | `*-e2e` | — | A **funded** sr25519 account (`0x` seed or BIP39 mnemonic). It pays gas and signs the decrypt requests. Falls back to `TEST_KEY`. |
| `TEST_KEY` | all but `delegated-e2e` | — | The last-resort key, the same as in CI. |
| `MATTER_SUBMIT` | `client-*`, `delegated-e2e` | — | Must be `yes` before the example submits anything. |
| `MATTER_SECRET` | `rust-e2e`, `e2e`, `python-e2e`, `go-e2e` | a sample env file | The plaintext to seal. |
| `MATTER_SECRET_ID` | `e2e`, `python-e2e`, `go-e2e` | — | Decrypt an existing secret instead of storing a new one. |
| `MATTER_AAD` | `e2e` | `env` | The AAD tag to seal under: `env`, `tls`, `storage`, `dek` or `dataset`. |

Two independent guards:

- **`MATTER_SUBMIT` means "spend gas at all". `MATTER_CONFIRM` means "spend gas on
  mainnet".** An accidental production submit takes two mistakes.
- **Network detection reads the endpoint, not the flag.** The SDK checks the chain's
  genesis hash and token symbol, so `MATTER_NETWORK=testnet` pointed at a mainnet URL
  still fails. Every `*-e2e` harness also requires `MATTER_CONFIRM=yes` whenever
  the network or the URL names mainnet.

## Running

Every command runs from the repository root. Building anything from source needs read
access to the private cryptographic core.

```bash
# Rust: read-only against testnet
MATTER_API_KEY=$TEST_KEY cargo run -p matter-sdk-client-example

# A member-tied scoped key: what it acts as, and what it is refused
MATTER_API_KEY=$MATTER_DELEGATED_KEY cargo run -p matter-delegated-e2e

# TypeScript: the examples use the packages in this repository, so build them first
npm --prefix packages/typescript-core ci && npm --prefix packages/typescript-core run build
npm --prefix packages/typescript ci && npm --prefix packages/typescript run build
(cd examples/client-typescript && npm install && MATTER_API_KEY=$TEST_KEY npm start)

# Python: needs the wheel built and installed (see bindings/python/README.md)
MATTER_API_KEY=$TEST_KEY python examples/client-python/run.py

# Go: links the core statically, which in this repository means building the archive first.
# examples/go.work points the examples at packages/go/mattersdk.
cargo build -p matter-sdk-ffi --release
(cd examples/client-go && MATTER_API_KEY=$TEST_KEY go run .)
```

The in-process demos need no network:

```bash
cargo run -p matter-sdk-example                          # Rust
(cd examples/typescript && npm install && npm run demo)  # TypeScript, after the core build above
```

The round trips spend gas, so they need a **funded** testnet account:

```bash
export MATTER_SIGNER_SEED='<funded 0x-seed or mnemonic>'
cargo run -p matter-sdk-e2e                          # Rust
(cd examples/e2e && npm install && npm start)        # TypeScript, see e2e/README.md
python examples/python-e2e/run.py                    # Python
(cd examples/go-e2e && go run .)                     # Go, after the FFI build above
```

Each round trip compares the recovered plaintext in process and prints only its size.
To prove the languages agree, re-decrypt one harness's secret from another: pass the
printed id as `MATTER_SECRET_ID` to the TypeScript, Python or Go harness.

## What the client examples prove

Run all four with the same key and they print the **same account id** and the same chain
facts. That is one key format, one set of chain properties, and one `tx` / `query` /
`runtimeApi` / `constant` surface across four languages. They also show:

- **Amounts are integer plancks, never floats.** An amount with too many decimal places
  is *rejected*, not rounded. The decimals come from the runtime
  (`Balances.ExistentialDeposit`), not from the node's chain spec.
- **An `ApiKey` never prints.** Logging the key object shows the account and
  `<redacted>`.

## Moving to production

- Keep the key out of the process: connect with a signer over your HSM, KMS or wallet.
  See [Secure signing](../docs/secure-signing.md).
- Use a scoped key that grants only what the workload needs. See
  [Keys and scopes](../docs/keys-and-scopes.md).
