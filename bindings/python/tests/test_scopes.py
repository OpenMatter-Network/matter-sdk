"""The scope contract, replayed from the fixtures Rust emits.

Both ways, like ``test_facade.py``: a fixture row this binding cannot classify is
drift, and so is a classification the fixture does not know about.
"""

import json
from pathlib import Path

from matter_vault.scopes import Access, Scope, ScopeSet, required_scopes

VECTORS = Path(__file__).resolve().parents[3] / "testvectors"
BITS = json.loads((VECTORS / "scope_bits.json").read_text())
TABLE = json.loads((VECTORS / "required_scopes.json").read_text())


# --- bit layout -------------------------------------------------------------


def test_places_every_scope_where_the_fixture_says():
    for row in BITS["scopes"]:
        scope = Scope(row["index"])
        assert ScopeSet.single(scope, Access.READ).bits == row["read_bit"]
        assert ScopeSet.single(scope, Access.WRITE).bits == row["write_bit"]
        # The name is what str() must emit for that scope alone.
        assert str(ScopeSet.single(scope, Access.READ)) == f"{row['scope']}:r"
    assert ScopeSet.all().bits == BITS["all_bits"]


def test_knows_exactly_the_scopes_the_fixture_knows():
    # A scope added on either side without the other fails here.
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
        # A repeated letter is a confused generator, not a wider set.
        ("secrets:rr", "invalid access"),
    ]:
        with pytest.raises(ValueError, match=message):
            ScopeSet.parse(text)


def test_a_scope_set_is_immutable_and_hashable():
    import pytest

    held = ScopeSet.single(Scope.SECRETS, Access.READ)
    with pytest.raises(AttributeError):
        held.bits = 0
    # Widening returns a new set rather than mutating the one already handed out.
    assert held.with_(Scope.SECRETS, Access.WRITE) != held
    assert len({held, ScopeSet.single(Scope.SECRETS, Access.READ)}) == 1


# --- the call table ---------------------------------------------------------


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
    # The other direction. A pallet the fixture never mentions must admit
    # nothing, whatever the call — this is where token movement, staking,
    # governance and sudo live, and admitting any of them would be the one
    # mistake in this table that actually matters.
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

    # Clearing a reference needs no read; setting one does.
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

    # A readable request with both references cleared is the narrow case.
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
    # The fail-safe direction, and the fixture's value for these rows. An
    # argument that is simply absent is unreadable — not None.
    with_secret = ScopeSet.single(Scope.DEPLOYMENTS, Access.WRITE).with_(
        Scope.SECRETS, Access.READ
    )
    for params in ({}, {"request": 42}, {"request": {"secret_ref": None}}, {"request": [1, 2]}):
        assert required_scopes("Jobs", "request_deployment", params) == with_secret, params
    # Same for the other row: no `secret_ref` key at all means unreadable.
    assert required_scopes("Jobs", "set_deployment_secret_ref", {"deployment": 1}) == with_secret
