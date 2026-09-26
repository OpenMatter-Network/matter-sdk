# matter-sdk (Python)

The Python client for OpenMatter. It reads any state on MatterChain, signs and submits any
call the runtime exposes, and runs threshold secrets on the matter-kgc committee.
Cryptography and API-key derivation come from the shared Rust core, compiled in as
`matter_sdk._native`. Everything else is pure Python.

## Install

```bash
pip install "matter-sdk[sdk]"
```

- **Python 3.9+.** Wheels are published for Linux (glibc and musl, x86-64 and arm64) and macOS (x86-64 and arm64).
- **The `[sdk]` extra** adds `substrate-interface` for the chain client.
- **Typing:** type information ships, including for the compiled core (`py.typed`, `_native.pyi`).

| Install | You get |
|---|---|
| `pip install matter-sdk` | `encrypt`, `open_secret`, `verify_plaintext_proof`, `signing_payload`, `lagrange_for`, `decrypt`, `UrllibTransport`, `Signer` / `substrate_signer`, `ApiKey` / `api_key_from_env`, `Aad`, the call builders, `wipe`, and `Scope` / `ScopeSet` / `required_scopes` |
| `pip install "matter-sdk[sdk]"` | Everything above, plus `MatterClient`, `ChainClient`, the façades, `TxReceipt`, `ApiKeySigner`, `parse_amount` and `format_amount` |

Without the extra, the chain names still import, but calling one raises an `ImportError`
that names the missing extra.

## Quick start

```python
from matter_sdk import MatterClient

# Reads MATTER_API_KEY / MATTER_NETWORK / MATTER_RPC_URL / MATTER_CONFIRM.
# With no key set it connects read-only, which is a valid result, not an error.
with MatterClient.from_env() as client:
    # Reads: any pallet, resolved by name from live metadata.
    print(client.properties.chain_name, client.properties.spec_version)
    print(client.query("Secrets", "NextSecretId"))
    print(client.runtime_api("KgcApi_dkg_epoch", return_type="u32"))

    # Amounts are integer plancks, never floats.
    print(client.parse_amount("1.5"))

    # Writes: any call, waiting for finalization.
    client.tx("Staking", "chill", {})
```

Connect explicitly with `MatterClient.connect(...)` (read-only),
`connect_with_api_key(ApiKey(...))`, or `connect_with_keypair(keypair)`. The last one takes
any `substrate-interface` `Keypair`-shaped object.

## Façades

`client.secrets`, `client.deployments`, `client.resources`, `client.staking`,
`client.orgs` and `client.keys`:

```python
from matter_sdk import Aad, grant_to_user

client.secrets.store(envelope, epoch, "prod", Aad.ENV_V1)
client.secrets.revoke(secret_id, grant_to_user(account))
client.staking.bond(client.parse_amount("10"), {"Staked": None})
client.deployments.set_secret_ref(deployment, secret_id)
client.orgs.authorize_secrets_agent(org, project, who)
```

Anything a façade doesn't cover is one `client.tx(pallet, call, params)` away.

## Secrets and keys

- `decrypt` returns a recovered secret as a `bytearray`. Never log it, and call
  `matter_sdk.wipe(plaintext)` when you're done.
- An `ApiKey` is redacted in `repr` and refuses to be pickled or copied, so it can't end
  up in a cache or a `multiprocessing` queue.
- Key derivation happens only in the shared core. `ApiKeySigner` adapts an `ApiKey` into
  the keypair shape `substrate-interface` signs with.
- Chain failures are typed. They all derive from `ChainError`: `ReadOnlyError`,
  `WrongNetworkError`, `MainnetNotConfirmedError`, `NotPermittedError`,
  `NeverAdmittedError`, `KeyRevokedError`, `UnsponsoredError`, `DispatchError`, and so on.

## Guides

- [Connecting](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/connecting.md): constructors, networks, the mainnet guard, and environment variables
- [Keys and scopes](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/keys-and-scopes.md)
- [The generic chain surface](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/chain-surface.md)
- Façades: [secrets](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/secrets.md) ·
  [deployments](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/deployments.md) ·
  [resources](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/resources.md) ·
  [staking](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/staking.md) ·
  [organizations](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/organizations.md)
- [Secure signing](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/secure-signing.md) ·
  [Errors](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/errors.md) ·
  [Language parity](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/parity.md)
- Runnable example:
  [`examples/client-python`](https://github.com/OpenMatter-Network/matter-sdk/blob/main/examples/client-python/run.py)

## Building from source (this repository)

Building from source needs read access to the private cryptographic core. The same
commands run in CI:

```bash
cd bindings/python
pip install maturin pytest 'substrate-interface>=1.7'
maturin build --release
pip install --force-reinstall --no-deps target/wheels/matter_sdk-*.whl
pytest -q
```

Build, then install. `maturin develop` shells out to `uv pip`, which some environments
disable. The layout is maturin's *mixed* one (`python/matter_sdk/` alongside the compiled
core), so changing only Python files still needs a rebuild.
