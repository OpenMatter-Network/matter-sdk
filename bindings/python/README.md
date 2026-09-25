# matter-sdk (Python)

The Python client for MatterSDK and the OpenMatter chain: a PyO3 binding over the shared
Rust cores (cryptography and API-key derivation) plus a pure-Python layer for the
committee transport, the threshold-decrypt quorum, signers, call builders, and a chain
client that reaches every pallet. See
[`docs/parity.md`](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/parity.md)
for differences from the other bindings.

## Install

```bash
pip install "matter-sdk[sdk]"
```

The cryptography and `ApiKey` need no extra dependencies; the `[sdk]` extra adds
`substrate-interface` for the chain client. Type information ships (`py.typed`),
including for the compiled core.

## Quick start

```python
from matter_sdk import MatterClient

# MATTER_API_KEY / MATTER_NETWORK / MATTER_RPC_URL / MATTER_CONFIRM.
# No key set connects read-only, which is a legitimate outcome rather than an error.
with MatterClient.from_env() as client:
    # Reads: any pallet, resolved by name from live metadata.
    print(client.query("Secrets", "NextSecretId"))
    print(client.runtime_api("KgcApi_dkg_epoch", return_type="u32"))

    # Amounts are integer plancks, never floats.
    print(client.parse_amount("1.5"))

    # Writes: any call. Waits for finalization, because the committee authorizes
    # against the finalized head. Guard failures are typed: ReadOnlyError,
    # WrongNetworkError, MainnetNotConfirmedError, NotPermittedError, ... all ChainError.
    client.tx("Staking", "chill", {})
```

`decrypt` returns a recovered secret as a `bytearray`: never log it, and call
`matter_sdk.wipe(plaintext)` when done.

An `ApiKey` is redacted through `repr` and refuses to be pickled or copied, so it cannot
reach a cache or a `multiprocessing` queue. See
[`docs/secure-signing.md`](https://github.com/OpenMatter-Network/matter-sdk/blob/main/docs/secure-signing.md).

Key derivation happens only in the shared core. `substrate-interface` needs its own
`Keypair` to sign extrinsics, so `ApiKeySigner` adapts an `ApiKey` into a keypair-shaped
object that delegates to the core.

## Façades

`secrets`, `deployments`, `resources`, `staking`, `orgs`, and `keys` are properties:

```python
client.secrets.store(envelope, epoch, "prod", Aad.ENV_V1)
client.secrets.revoke(secret_id, grant_to_user(account))
client.staking.bond(client.parse_amount("10"), {"Staked": None})
client.deployments.set_secret_ref(deployment, secret_id)
client.orgs.authorize_secrets_agent(org, project, who)
```

Anything not covered is one `client.tx(...)` away. `tests/test_facade.py` replays
`testvectors/facade_calls.json` both ways.

## Building from source (this repository)

Needs read access to the private cryptographic core.

```bash
pip install maturin
cd bindings/python
maturin build -i .venv/bin/python --release
pip install --force-reinstall --no-deps target/wheels/matter_sdk-*.whl
pytest -q
```

Use build-then-install: `maturin develop` shells out to `uv pip`, which some
environments disable. The layout is maturin's *mixed* one, so a Python-only edit still
needs a rebuild.
