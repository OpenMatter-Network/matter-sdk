# End-to-end test (live chain + committee)

Exercises the **full** MatterVault path against a real OpenMatter chain and the live
matter-kgc committee: fetch context → encrypt → `secrets.storeSecret` → read back →
threshold-decrypt → verify. This is the integration point that can't be tested
offline.

## You provide a funded key

The `storeSecret` extrinsic costs a transaction fee and the same account signs the
partial-decrypt requests, so the account must be **funded before you run this**. The
key stays in this process (a `@polkadot` keyring pair); the SDK only receives a sign
callback — it never sees the key.

## Run

```bash
cd examples/e2e
npm install

# Testnet (default):
export MATTER_RPC_URL=wss://<your-testnet-node>
export MATTER_SIGNER_SEED='<mnemonic | //Account | 0x-seed>'   # a FUNDED account
npm start

# Mainnet (guarded — posts on-chain, spends real fees):
export MATTER_NETWORK=mainnet
export MATTER_CONFIRM=yes
npm start
```

## Options (env vars)

| Var | Meaning |
|---|---|
| `MATTER_RPC_URL` | ws(s) endpoint of the chain node (**required**) |
| `MATTER_SIGNER_SEED` | sr25519 SURI of a **funded** account (**required**) |
| `MATTER_NETWORK` | `testnet` (default) or `mainnet` |
| `MATTER_CONFIRM` | must be `yes` to act against mainnet |
| `MATTER_SECRET` | plaintext to seal (default: a sample env line) |
| `MATTER_SECRET_ID` | decrypt this existing secret instead of storing a new one |
| `MATTER_AAD` | `env` (default) / `tls` / `storage` / `dek` |

Keys are read from the environment, never from argv, so they don't land in shell
history. Prefer a throwaway funded account for testing.

## What it proves

`storeSecret` lands and emits `secrets.SecretStored`; the persisted envelope reads
back from chain; a threshold quorum of committee nodes accepts the signed
`/partial-decrypt` requests; and the recovered plaintext matches what was sealed.
This validates the one integration point the unit tests can't: that the committee
**accepts the SDK's Substrate signature** for a real authorized account.
