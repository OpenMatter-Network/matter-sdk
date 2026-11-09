# End-to-end: TypeScript, live chain and committee

This harness runs the full Secrets path against a live chain and the matter-kgc
committee, through `MatterClient` with a custom `KeySigner`:

1. Read the committee context (`client.runtimeApi`).
2. `encrypt`.
3. `client.secrets.store` → the SDK encodes the call against live metadata, hashes the
   signing payload (far over 256 bytes) before the signer sees it, and waits for
   finality; `secretIdFromReceipt` reads the id from the receipt.
4. Read the secret back.
5. Threshold-decrypt with `keySigner(client.signer)`: the same signer authorizes the
   committee requests.
6. Compare the result.

It proves what no offline test can: the chain **accepts the SDK's extrinsic encoding and
signature**, and the committee **accepts the SDK's request signature**, both from a real,
authorized account, through the same seam an HSM or KMS would use.

The account must be **funded**, because `store_secret` pays a fee and the same account
signs the partial-decrypt requests. The key stays in this process as a `@polkadot`
keyring pair, and the SDK only receives a sign callback. Prefer a throwaway account.

## Run

```bash
# From the repository root. The harness imports both packages in this repository from
# source, so build the core and install the client's dependencies first:
npm --prefix packages/typescript-core ci && npm --prefix packages/typescript-core run build
npm --prefix packages/typescript ci

cd examples/e2e
npm install

# Testnet (the default endpoint is built in; override it with MATTER_RPC_URL):
export MATTER_SIGNER_SEED='<mnemonic | 0x-seed>'   # a FUNDED account; TEST_KEY also works
npm start

# Mainnet is guarded: this writes on-chain and spends real fees.
export MATTER_NETWORK=mainnet
export MATTER_CONFIRM=yes
npm start
```

`npx tsx preflight.ts` checks the account balance, DKG finalization, and each node's
`/health` without spending gas.

## Options

- **`MATTER_AAD`** selects the AAD tag: `env` (the default), `tls`, `storage`, `dek` or
  `dataset`.
- **`MATTER_SECRET_ID`** decrypts an existing secret instead of storing a new one.
- **`MATTER_SECRET`** sets the plaintext to seal.

The full list is in the [examples README](../README.md#environment). The recovered
plaintext is compared in process and never printed.
