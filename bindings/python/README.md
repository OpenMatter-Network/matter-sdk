# matter-vault (Python)

The Python client for MatterVault and the OpenMatter chain. See
[`docs/parity.md`](../../docs/parity.md) for what has landed here versus the other
bindings.

PyO3 binding over the shared Rust cores — cryptography (`matter-vault-core`) **and**
API-key derivation (`matter-vault-key`) — plus a pure-Python online layer: the
committee HTTP transport, the threshold-decrypt quorum loop, the signer abstraction,
call builders, and a chain client that reaches every pallet the runtime exposes.

Everything passes the same cross-language fixtures as the other bindings, including a
full `open_secret` round trip that recovers the exact plaintext the Rust core sealed.

## Install

The cryptography and `ApiKey` need no extra dependencies. The chain client needs
`substrate-interface`:

```bash
pip install matter-vault[sdk]
```

## Build & test

```bash
pip install maturin
cd bindings/python
maturin build -i .venv/bin/python --release
pip install --force-reinstall --no-deps target/wheels/matter_vault-*.whl
pytest -q
```

`maturin develop` shells out to `uv pip`, which is disabled in some environments;
the build-then-install pair above always works. The layout is maturin's *mixed* one,
so the pure-Python sources are bundled into the wheel — a Python-only edit still
needs a rebuild.

## Quick start

```python
from matter_vault import MatterClient

# MATTER_API_KEY / MATTER_NETWORK / MATTER_RPC_URL / MATTER_CONFIRM.
# No key set connects read-only, which is a legitimate outcome rather than an error.
with MatterClient.from_env() as client:
    # Reads: any pallet, resolved by name from live metadata.
    print(client.query("Secrets", "NextSecretId"))
    print(client.runtime_api("KgcApi_dkg_epoch", return_type="u32"))

    # Amounts are integer plancks, never floats.
    print(client.parse_amount("1.5"))

    # Writes: any call. Waits for finalization, because the committee authorizes
    # against the finalized head.
    client.tx("Staking", "chill", {})
```

An `ApiKey` is redacted through `repr`, and refuses to be pickled or copied —
`__reduce__` is how a credential reaches a cache or a `multiprocessing` queue without
anyone writing serialization code. See
[`docs/secure-signing.md`](../../docs/secure-signing.md).

## Why a Rust core via PyO3

The RLWE/BGV threshold cryptography is novel and must exist in exactly one audited
implementation. PyO3 lets Python call that core directly rather than re-implementing
lattice crypto.

The same argument applies to **key derivation**, and this binding is the reason it is
not a hypothetical: `ChainClient.keypair_from_seed` used to branch on the `0x` prefix
and route hex SURIs to `create_from_seed`, which ignores derivation junctions — so
`0x…//hard` silently derived the **root** account. `ApiKey` derives in the shared core,
so the class of bug cannot recur.

`substrate-interface` still needs its own `Keypair` to build a signed extrinsic, and
its `create_from_uri` cannot derive a hex phrase with junctions at all. `ApiKeySigner`
adapts an `ApiKey` into something keypair-shaped that delegates to the core, leaving
exactly one derivation path.

## Façades

The five curated façades, reachable as properties:

```python
client.secrets.store(envelope, epoch, "prod", Aad.ENV_V1)
client.secrets.revoke(secret_id, grant_to_user(account))
client.staking.bond(client.parse_amount("10"), {"Staked": None})
client.deployments.set_secret_ref(deployment, secret_id)
client.orgs.authorize_secrets_agent(org, project, who)
```

A façade is a convenience, not a gate: anything not covered is one `client.tx(...)`
away. The surface is pinned by `testvectors/facade_calls.json` and replayed by
`tests/test_facade.py` **both ways** — a fixture row without a method fails, and a
method without a row fails.
