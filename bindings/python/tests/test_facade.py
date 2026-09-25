"""Façade parity with ``testvectors/facade_calls.json``, checked both ways: a row
without a method fails, and so does a method without a row."""

import inspect
import json
from pathlib import Path

import pytest

pytest.importorskip("substrateinterface")

from matter_sdk.facade import (  # noqa: E402
    DeploymentsFacade,
    KeysFacade,
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
    "keys": KeysFacade,
}


def _fixture():
    return json.loads(VECTORS.read_text())


def _calls():
    return _fixture()["calls"]


def _runtime_api_calls():
    return _fixture()["runtime_api_calls"]


class _RecordingChain:
    """The read side a façade may reach for, recorded rather than performed."""

    def __init__(self) -> None:
        self.agent_key_calls = []

    def agent_key(self, key):
        self.agent_key_calls.append(bytes(key))
        return None


class _RecordingClient:
    """Records what a façade submits, so a method is checked without a chain."""

    def __init__(self) -> None:
        self.calls = []
        self.chain = _RecordingChain()

    def tx(self, pallet, call, params):
        self.calls.append((pallet, call, params))
        return "receipt"


# Façade methods whose signature differs from the runtime call's argument list.
ENVELOPE = (b"\x01", b"\x02", b"\x03", b"\x04")
METHOD_ARGS = {
    "secrets.store": (ENVELOPE, 1, "prod", "matter-deployment/env/v1"),
    "secrets.rotate": (1, ENVELOPE, 1, "matter-deployment/env/v1"),
}


def _placeholders(arg_names):
    """Placeholder arguments shaped by the fixture's arg names."""
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


@pytest.mark.parametrize("row", _runtime_api_calls(), ids=lambda r: f"{r['facade']}.{r['method']}")
def test_reads_route_through_the_named_state_call(row):
    client = _RecordingClient()
    facade = FACADES[row["facade"]](client)
    method = getattr(facade, row["method"], None)
    assert callable(method), f"{row['facade']}.{row['method']} is missing"

    assert method(b"\x00" * 32) is None
    assert client.chain.agent_key_calls == [b"\x00" * 32]
    assert client.calls == [], "a read must not submit an extrinsic"


def test_no_facade_method_is_unpinned():
    # A façade's surface is the union of both fixture tables.
    expected = {}
    for row in _calls() + _runtime_api_calls():
        expected.setdefault(row["facade"], set()).add(row["method"])

    for name, cls in FACADES.items():
        public = {
            member
            for member, _ in inspect.getmembers(cls, predicate=inspect.isfunction)
            if not member.startswith("_")
        }
        assert public == expected[name], f"{name} façade surface differs from the fixture"


def test_facades_reach_all_five_pallet_secrets_calls():
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
    client = _RecordingClient()
    target = {"User": "0x" + "07" * 32}
    SecretsFacade(client).grant(42, target)

    _pallet, _call, params = client.calls[0]
    assert params == {"secret_id": 42, "target": target}


def test_client_exposes_every_facade_as_a_property():
    from matter_sdk.client import MatterClient

    for name in FACADES:
        prop = getattr(MatterClient, name, None)
        assert isinstance(prop, property), f"MatterClient.{name} is not a property"
