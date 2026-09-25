# Examples

| Example | Network | Costs gas | What it shows |
|---|---|---|---|
| [`rust`](rust) · [`typescript/demo.ts`](typescript) | none | no | seal and recover against an in-process committee |
| [`client-rust`](client-rust) · [`client-typescript`](client-typescript) · [`client-python`](client-python) · [`client-go`](client-go) | testnet | **no**, unless `MATTER_SUBMIT=yes` | connect from an `apiKey`, read any pallet, preview a submission |
| [`delegated-e2e`](delegated-e2e) | testnet | **no**, unless `MATTER_SUBMIT=yes` | a member-tied scoped key: its resolved grant, a write wrapped as its member, and two local refusals |
| [`rust-e2e`](rust-e2e) · [`e2e`](e2e) (TypeScript) · [`python-e2e`](python-e2e) · [`go-e2e`](go-e2e) | testnet | **yes** | full round trip: seal → `secrets.storeSecret` → read back → threshold-decrypt |

Start with a `client-*` example: it is read-only by default and covers the surface most
integrations use.

## Environment

**Keys come from the environment, never from argv** — argv lands in shell history and
`ps` output.

| Variable | Default | Meaning |
|---|---|---|
| `MATTER_API_KEY` | — | `client-*`: a `0x` 32-byte mini-secret, a BIP39 mnemonic, or an sr25519 SURI; falls back to `MATTER_SIGNER_SEED`, then `TEST_KEY`; unset means a read-only client. `delegated-e2e`: required, the scoped key as the dashboard shows it (no fallback). |
| `MATTER_SIGNER_SEED` | — | `*-e2e`: the **funded** account that pays gas and decrypts. Falls back to `TEST_KEY`. |
| `MATTER_RPC_URL` | the network's default | endpoint override |
| `MATTER_NETWORK` | `testnet` | `testnet` or `mainnet` |
| `MATTER_CONFIRM` | — | must be `yes` before a **signing** client touches mainnet |
| `MATTER_SUBMIT` | — | must be `yes` before a `client-*` or `delegated-e2e` example submits anything |
| `MATTER_SECRET` | a sample env line | plaintext to seal (`*-e2e` only) |
| `MATTER_SECRET_ID` | — | act on an existing secret instead of storing a new one |
| `MATTER_PRINCIPAL` | — | force the member a key acts for when the chain's pointer is stale; disables the local scope check, leaving the runtime to decide |
| `MATTER_AAD` | `env` | AAD registry tag to seal under (TypeScript `e2e` only) |

Guards:

- **The `client-*` examples check what the endpoint serves, not the flag.** The SDK's
  guard reads the chain's genesis hash, so `MATTER_NETWORK=testnet` pointed at a
  mainnet URL still fails. The `*-e2e` harnesses require `MATTER_CONFIRM=yes` whenever
  the network or the URL names mainnet.
- **`MATTER_SUBMIT` ("spend gas at all") is separate from `MATTER_CONFIRM` ("spend gas
  on mainnet").** An accidental production submit takes two mistakes.

## Running

```bash
# Rust — read-only against testnet
MATTER_API_KEY=$TEST_KEY cargo run -p matter-sdk-client-example

# A member-tied scoped key: what it acts as, and what it is refused
MATTER_API_KEY=$MATTER_DELEGATED_KEY cargo run -p matter-delegated-e2e

# TypeScript — the examples use the packages in this repository, so build them first
npm --prefix packages/typescript-core ci && npm --prefix packages/typescript-core run build
npm --prefix packages/typescript ci && npm --prefix packages/typescript run build
cd examples/client-typescript && npm install && MATTER_API_KEY=$TEST_KEY npm start

# Python — needs the wheel built (see bindings/python/README.md)
MATTER_API_KEY=$TEST_KEY ./bindings/python/.venv/bin/python examples/client-python/run.py

# Go — links the core statically; in this repo that means building the archive first
cargo build -p matter-sdk-ffi --release
cd examples/client-go && MATTER_API_KEY=$TEST_KEY go run .
```

The in-process demos need no network:

```bash
cargo run -p matter-sdk-example                       # Rust
cd examples/typescript && npm install && npm run demo # TypeScript (after the build above)
```

The round trips spend gas, so they need a **funded** testnet account:

```bash
export MATTER_SIGNER_SEED='<funded 0x-seed or mnemonic>'
cargo run -p matter-sdk-e2e                                          # Rust
cd examples/e2e && npm install && npm start                           # TypeScript (see its README)
./bindings/python/.venv/bin/python examples/python-e2e/run.py         # Python
cd examples/go-e2e && go run .                                        # Go (after the FFI build above)
```

Each round trip compares the recovered plaintext in process and prints only its size.

## What the client examples prove

Run with the same key, all four print the **same account id** and chain facts: one key
format (`testvectors/api_keys.json`), one set of chain properties, and the same
`tx` / `query` / `runtimeApi` / `constant` surface in every language. They also show:

- **Amounts are integer plancks**, never floats; an over-precise amount is *rejected*,
  not rounded. Decimals come from the runtime (`Balances.ExistentialDeposit`), not the
  node's chain spec, because the two can disagree.
- **An `ApiKey` never prints.** Logging the key object shows the account and
  `<redacted>`.
