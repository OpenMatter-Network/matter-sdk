"""Façade parity: this binding must expose exactly the surface
``testvectors/facade_calls.json`` pins, and each method must submit the named
``(pallet, call)``.

The façades are hand-written per language, so the risk is drift — Python growing a
method Rust does not have, or two languages disagreeing about which call a method
maps to. The fixture is emitted from Rust and replayed here, checked **both ways**:
a row without a method fails, and a method without a row fails.
"""

import inspect
import json
from pathlib import Path

import pytest

pytest.importorskip("substrateinterface")

from matter_vault.facade import (  # noqa: E402
    DeploymentsFacade,
    OrgsFacade,
    ResourcesFacade,
    SecretsFacade,
    StakingFacade,
)

VECTORS = Path(__file__).resolve().parents[3] / "testvectors" / "facade_calls.json"

FACADES = {
    "secrets": SecretsFacade,
    "deployments": DeploymentsFacade,
    "resources": ResourcesFacade,
    "staking": StakingFacade,
    "orgs": OrgsFacade,
}


def _calls():
    return json.loads(VECTORS.read_text())["calls"]


class _RecordingClient:
    """Records what a façade submits, so a method is checked without a chain."""

    def __init__(self) -> None:
        self.calls = []

    def tx(self, pallet, call, params):
        self.calls.append((pallet, call, params))
        return "receipt"


# Façade methods whose signature differs from the runtime call's argument list.
# `secrets.store` takes the (binding_id, capsule, proof, ct) tuple `encrypt`
# returns rather than four positional values, because re-splitting it at the
# boundary would invite a mismatched AAD.
ENVELOPE = (b"\x01", b"\x02", b"\x03", b"\x04")
METHOD_ARGS = {
    "secrets.store": (ENVELOPE, 1, "prod", "matter-deployment/env/v1"),
    "secrets.rotate": (1, ENVELOPE, 1, "matter-deployment/env/v1"),
}


def _placeholders(arg_names):
    """Arguments shaped by the fixture's arg names.

    Only the routing is under test, but a method that dereferences an argument
    needs something of the right shape. Keying off the pinned names keeps that
    knowledge in one place.
    """
    shapes = {
        "target": {"User": "0x" + "00" * 32},
        "targets": ["5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV"],
        "user_wg_pubkey": b"\x00" * 32,
        "is_private": True,
        "name": "demo",
        "secret_ref": 1,
        "env_vars": None,
    }
    return tuple(shapes.get(name, 1) for name in arg_names)


def test_the_fixture_is_not_empty():
    # A silently truncated fixture would make every assertion below vacuous.
    assert len(_calls()) > 20


@pytest.mark.parametrize(
    "row", _calls(), ids=[f"{c['facade']}.{c['method']}" for c in _calls()]
)
def test_each_method_routes_to_its_pinned_call(row):
    client = _RecordingClient()
    facade = FACADES[row["facade"]](client)

    method = getattr(facade, row["method"], None)
    assert callable(method), f"{row['facade']}.{row['method']} is missing"

    args = METHOD_ARGS.get(f"{row['facade']}.{row['method']}")
    method(*(args if args is not None else _placeholders(row["args"])))

    assert len(client.calls) == 1
    pallet, call, _params = client.calls[0]
    assert (pallet, call) == (row["pallet"], row["call"])


def test_no_facade_method_is_unpinned():
    # The other direction: an extra method here would be a surface Rust does not
    # have, which is drift even though every fixture row passes.
    expected = {}
    for row in _calls():
        expected.setdefault(row["facade"], set()).add(row["method"])

    for name, cls in FACADES.items():
        public = {
            member
            for member, _ in inspect.getmembers(cls, predicate=inspect.isfunction)
            if not member.startswith("_")
        }
        assert public == expected[name], f"{name} façade surface differs from the fixture"


def test_facades_reach_all_five_pallet_secrets_calls():
    # pallet-secrets has five extrinsics; the SDK previously built three, leaving
    # revoke_access — the call that contains a leaked signer — with no builder.
    client = _RecordingClient()
    secrets = SecretsFacade(client)
    target = {"User": "0x" + "00" * 32}

    secrets.store(ENVELOPE, 1, "prod", "matter-deployment/env/v1")
    secrets.rotate(1, ENVELOPE, 1, "matter-deployment/env/v1")
    secrets.grant(1, target)
    secrets.revoke(1, target)
    secrets.delete(1)

    assert [call for _pallet, call, _p in client.calls] == [
        "store_secret",
        "rotate_secret",
        "grant_access",
        "revoke_access",
        "delete_secret",
    ]


def test_grant_passes_a_named_variant_not_a_bare_account():
    # The defect this replaces: a raw 32-byte grantee is not decodable as
    # GrantTarget<AccountId>, so the call data was dead on arrival.
    client = _RecordingClient()
    target = {"User": "0x" + "07" * 32}
    SecretsFacade(client).grant(42, target)

    _pallet, _call, params = client.calls[0]
    assert params == {"secret_id": 42, "target": target}


def test_client_exposes_every_facade_as_a_property():
    # The accessors are the API; a missing one makes the façade unreachable even
    # though its class is fine.
    from matter_vault.client import MatterClient

    for name in FACADES:
        prop = getattr(MatterClient, name, None)
        assert isinstance(prop, property), f"MatterClient.{name} is not a property"
