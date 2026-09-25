# End-to-end test (live chain + committee)

Runs the full Secrets path against a live chain and the matter-kgc committee: fetch
context → encrypt → `secrets.storeSecret` → read back → threshold-decrypt → verify. It
proves what no offline test can: the committee **accepts the SDK's Substrate
signature** for a real authorized account.

The account must be **funded**: `storeSecret` pays a fee, and the same account signs the
partial-decrypt requests. The key stays in this process (a `@polkadot` keyring pair);
the SDK only receives a sign callback. Prefer a throwaway account.

## Run

```bash
# From the repository root. The harness imports the packages in this repository,
# so build them first:
npm --prefix packages/typescript-core ci && npm --prefix packages/typescript-core run build

cd examples/e2e
npm install

# Testnet (default endpoint baked in; override with MATTER_RPC_URL):
export MATTER_SIGNER_SEED='<mnemonic | 0x-seed>'   # a FUNDED account; TEST_KEY also accepted
npm start

# Mainnet (guarded — posts on-chain, spends real fees; dials the mainnet endpoint):
export MATTER_NETWORK=mainnet
export MATTER_CONFIRM=yes
npm start
```

`npx tsx preflight.ts` checks funding, DKG, and committee health without spending gas.

Environment variables are listed in the [examples README](../README.md). `MATTER_AAD`
selects the AAD tag: `env` (default), `tls`, `storage`, `dek`, or `dataset`. The
recovered plaintext is compared in process and never printed.
