"""The scope contract, replayed both ways from the Rust-emitted fixtures."""

import json
from pathlib import Path

from matter_sdk.scopes import Access, Scope, ScopeSet, required_scopes

VECTORS = Path(__file__).resolve().parents[3] / "testvectors"
BITS = json.loads((VECTORS / "scope_bits.json").read_text())
TABLE = json.loads((VECTORS / "required_scopes.json").read_text())


def test_places_every_scope_where_the_fixture_says():
    for row in BITS["scopes"]:
        scope = Scope(row["index"])
        assert ScopeSet.single(scope, Access.READ).bits == row["read_bit"]
        assert ScopeSet.single(scope, Access.WRITE).bits == row["write_bit"]
        assert str(ScopeSet.single(scope, Access.READ)) == f"{row['scope']}:r"
    assert ScopeSet.all().bits == BITS["all_bits"]


def test_knows_exactly_the_scopes_the_fixture_knows():
    assert len(list(Scope)) == len(BITS["scopes"])
    assert str(ScopeSet.all()).count(",") == len(BITS["scopes"]) - 1


def test_agrees_with_the_fixtures_superset_truth_table():
    for row in BITS["algebra"]:
        held = ScopeSet.from_bits(row["held"])
        required = ScopeSet.from_bits(row["required"])
        assert held.is_superset(required) is row["is_superset"]
        assert str(held) == row["held_text"]


def test_read_and_write_stay_independent():
    read_only = ScopeSet.single(Scope.SECRETS, Access.READ)
    assert not read_only.contains(Scope.SECRETS, Access.WRITE)
    write_only = ScopeSet.single(Scope.SECRETS, Access.WRITE)
    assert not write_only.contains(Scope.SECRETS, Access.READ)


def test_round_trips_through_str_and_parse():
    for held in (
        ScopeSet.empty(),
        ScopeSet.all(),
        ScopeSet.single(Scope.COMMUNITIES, Access.WRITE),
        ScopeSet.covering([Scope.DEPLOYMENTS, Scope.BILLING]),
    ):
        assert ScopeSet.parse(str(held)) == held
    assert ScopeSet.parse("") == ScopeSet.empty()
    assert str(ScopeSet.parse("Deployments:W  Secrets:R")) == "deployments:w, secrets:r"


def test_rejects_malformed_scope_text():
    import pytest

    for text, message in [
        ("deployments", "suffix"),
        ("deploy:r", "unknown scope"),
        ("secrets:x", "invalid access"),
        ("secrets:rr", "invalid access"),
    ]:
        with pytest.raises(ValueError, match=message):
            ScopeSet.parse(text)


def test_a_scope_set_is_immutable_and_hashable():
    import pytest

    held = ScopeSet.single(Scope.SECRETS, Access.READ)
    with pytest.raises(AttributeError):
        held.bits = 0
    assert held.with_(Scope.SECRETS, Access.WRITE) != held
    assert len({held, ScopeSet.single(Scope.SECRETS, Access.READ)}) == 1


def test_classifies_every_call_the_fixture_pins_identically():
    for row in TABLE["calls"]:
        got = required_scopes(row["pallet"], row["call"])
        target = f"{row['pallet']}.{row['call']}"
        if row["required"] is None:
            assert got is None, f"{target} must be admitted by no set"
        else:
            assert got is not None, f"{target} requires {row['required_text']}"
            assert got.bits == row["required"], target


def test_scopes_no_pallet_the_fixture_does_not_list():
    # Token movement, staking, governance, and sudo must never be admitted.
    scoped = {row["pallet"] for row in TABLE["calls"]}
    for pallet in ("Balances", "Staking", "Sudo", "Proxy", "Utility", "EthSigning"):
        assert pallet not in scoped
        for call in ("transfer_all", "bond", "sudo", "proxy", "batch_all", "anything"):
            assert required_scopes(pallet, call) is None, f"{pallet}.{call}"


def test_reads_the_two_argument_sensitive_rows_from_their_arguments():
    sensitive = [
        (row["pallet"], row["call"]) for row in TABLE["calls"] if row["arg_sensitive"]
    ]
    assert sensitive == [
        ("Jobs", "request_deployment"),
        ("Jobs", "set_deployment_secret_ref"),
    ]

    deploy_only = ScopeSet.single(Scope.DEPLOYMENTS, Access.WRITE)
    with_secret = deploy_only.with_(Scope.SECRETS, Access.READ)

    assert (
        required_scopes("Jobs", "set_deployment_secret_ref", {"deployment": 1, "secret_ref": None})
        == deploy_only
    )
    assert (
        required_scopes(
            "Jobs", "set_deployment_secret_ref", {"deployment": 1, "secret_ref": {"None": None}}
        )
        == deploy_only
    )
    assert (
        required_scopes("Jobs", "set_deployment_secret_ref", {"deployment": 1, "secret_ref": 9})
        == with_secret
    )

    assert (
        required_scopes(
            "Jobs", "request_deployment", {"request": {"secret_ref": None, "tls_secret_ref": None}}
        )
        == deploy_only
    )
    assert (
        required_scopes(
            "Jobs", "request_deployment", {"request": {"secret_ref": 7, "tls_secret_ref": None}}
        )
        == with_secret
    )


def test_demands_the_wider_set_when_the_argument_cannot_be_read():
    # An absent argument is unreadable, not None.
    with_secret = ScopeSet.single(Scope.DEPLOYMENTS, Access.WRITE).with_(
        Scope.SECRETS, Access.READ
    )
    for params in ({}, {"request": 42}, {"request": {"secret_ref": None}}, {"request": [1, 2]}):
        assert required_scopes("Jobs", "request_deployment", params) == with_secret, params
    assert required_scopes("Jobs", "set_deployment_secret_ref", {"deployment": 1}) == with_secret


def test_every_call_named_locally_has_a_fixture_row():
    # The other direction: a call this binding classifies by name but the fixture
    # does not list is drift, even if the pallet's catch-all would hide it.
    from matter_sdk import scopes as local

    pinned = {(row["pallet"], row["call"]) for row in TABLE["calls"]}
    named = {
        "Jobs": local._DEPLOYMENTS_WRITE
        | {"request_deployment", "set_deployment_secret_ref", "register_wg_peer", "remove_wg_peer"},
        "Collaborations": {"set_compute_node_image", "set_compute_node_sku_id"},
        "Resources": local._RESOURCES_WRITE,
        "Organizations": local._ORGANIZATION_WRITE,
        "Budgets": local._BILLING_WRITE,
    }
    for pallet, calls in named.items():
        for call in calls:
            assert (pallet, call) in pinned, f"{pallet}.{call} is classified locally but has no fixture row"


def test_every_pallet_scoped_locally_is_a_fixture_pallet():
    # A pallet whose catch-all admits an unknown call must be one the fixture pins.
    pinned_pallets = {row["pallet"] for row in TABLE["calls"]}
    candidates = pinned_pallets | {"Balances", "Staking", "Sudo", "Proxy", "Utility", "System"}
    locally_scoped = {p for p in candidates if required_scopes(p, "anything_else") is not None}
    assert locally_scoped <= pinned_pallets
