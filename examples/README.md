# Examples

Three kinds, in increasing order of what they touch.

| Example | Network | Costs gas | What it shows |
|---|---|---|---|
| [`rust`](rust) · [`typescript/demo.ts`](typescript) | none | no | seal and recover against an in-process committee |
| [`client-rust`](client-rust) · [`client-typescript`](client-typescript) · [`client-python`](client-python) · [`client-go`](client-go) | testnet | **no**, unless `MATTER_SUBMIT=yes` | connect from an `apiKey`, read any pallet, and see what submission would look like |
| [`delegated-e2e`](delegated-e2e) | testnet | **no**, unless `MATTER_SUBMIT=yes` | what a member-tied scoped key can and cannot do: the grant it resolves, a write wrapped as its member, and the two refusals that never reach the chain |
| [`rust-e2e`](rust-e2e) · [`e2e`](e2e) (TypeScript) · [`python-e2e`](python-e2e) · [`go-e2e`](go-e2e) | testnet | **yes** | the full round trip: seal → `secrets.storeSecret` → read back → threshold-decrypt |

Start with a `client-*` example. It is read-only by default, so it cannot cost
anything or change chain state, and it exercises the surface most integrations
actually use.

## Environment

Every example reads the same variables. **Keys come from the environment, never
from argv** — argv lands in shell history and `ps` output.

| Variable | Default | Meaning |
|---|---|---|
| `MATTER_API_KEY` | — | the key: a `0x` 32-byte mini-secret, a BIP39 mnemonic, or an sr25519 SURI. Falls back to `MATTER_SIGNER_SEED`, then `TEST_KEY`. Omit it entirely for a read-only client. |
| `MATTER_RPC_URL` | testnet | endpoint override |
| `MATTER_NETWORK` | `testnet` | `testnet` or `mainnet` |
| `MATTER_CONFIRM` | — | must be `yes` before a **signing** client will touch mainnet |
| `MATTER_SUBMIT` | — | must be `yes` before a `client-*` example submits anything |
| `MATTER_SECRET` | a sample env line | plaintext to seal (e2e only) |
| `MATTER_SECRET_ID` | — | act on an existing secret instead of storing a new one |
| `MATTER_PRINCIPAL` | — | force the member a key acts for, when the chain's pointer is stale. An escape hatch: it turns the local scope check off and lets the runtime decide alone |
| `MATTER_AAD` | `env` | which AAD registry tag to seal under (e2e only) |

Two guards are worth knowing about because they are what stop an expensive
mistake:

- **The mainnet check is on the endpoint, not the flag.** Pointing
  `MATTER_NETWORK=testnet` at a mainnet RPC URL still fails, which is exactly the
  hole a config-only check would leave open.
- **`MATTER_SUBMIT` is separate from `MATTER_CONFIRM`.** The first is "spend gas
  at all", the second is "spend gas on mainnet". An accidental production submit
  takes two mistakes, not one.

## Running

```bash
# Rust — read-only against testnet
MATTER_API_KEY=$TEST_KEY cargo run -p matter-client-example

# A member-tied scoped key: what it acts as, and what it is refused
MATTER_API_KEY=$MATTER_DELEGATED_KEY cargo run -p matter-delegated-e2e

# TypeScript
cd examples/client-typescript && npm install && MATTER_API_KEY=$TEST_KEY npm start

# Python — needs the wheel built (see bindings/python/README.md)
MATTER_API_KEY=$TEST_KEY ./bindings/python/.venv/bin/python examples/client-python/run.py

# Go — links the FFI cdylib, so it needs the library on its search path
cargo build -p matter-vault-ffi --release
cd examples/client-go && LD_LIBRARY_PATH=../../target/release MATTER_API_KEY=$TEST_KEY go run .
```

## What the client examples prove

Running all four against the same key should print the **same account id** and the
same chain facts. That is the cross-language contract made visible: one key
ingestion (`testvectors/api_keys.json`), one set of chain properties, and the same
generic surface — `tx` / `query` / `runtimeApi` / `constant` — in every language.

They also demonstrate two things that are easy to get wrong and expensive to get
wrong:

- **Amounts are integer plancks**, never floats, and an over-precise amount is
  *rejected* rather than rounded. This chain's decimal count already changed once
  (matter-node moved `UNIT` from `10^12` to `10^18` with no storage migration), so
  the examples read the effective value from the runtime's own
  `Balances.ExistentialDeposit` rather than trusting the node's chain spec.
- **An `ApiKey` never prints.** The examples deliberately log the key object; the
  output shows the account and `<redacted>`.
