"""``MatterClient`` against a fake chain: network guards, amount arithmetic, the
read-only contract, and delegation."""

import pytest

pytest.importorskip("substrateinterface")

from matter_sdk import ApiKey  # noqa: E402
from matter_sdk import (  # noqa: E402
    ChainError,
    ConfigError,
    MainnetNotConfirmedError,
    ReadOnlyError,
    WrongNetworkError,
)
from matter_sdk.client import (  # noqa: E402
    MAINNET_TOKEN_SYMBOL,
    TESTNET_GENESIS,
    ChainProperties,
    KeyRevokedError,
    MatterClient,
    Network,
    NotPermittedError,
    _decimals_from_existential_deposit,
    format_amount,
    parse_amount,
)

SEED_HEX = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"


class _FakeChain:
    """Enough of ``ChainClient`` to build a client and record submissions."""

    def __init__(self, agent_key=None, agent_key_error=None) -> None:
        self.submitted = []
        self.submit_error = None
        self.closed = False
        # ``BudgetsApi_agent_key``'s answer; ``None`` means no scoped proxy.
        self._agent_key = agent_key
        # A failed lookup, distinct from "no delegation".
        self._agent_key_error = agent_key_error
        self.agent_key_calls = []
        self.finality_timeouts = []

    def agent_key(self, key):
        self.agent_key_calls.append(bytes(key))
        if self._agent_key_error is not None:
            raise self._agent_key_error
        return self._agent_key

    def query(self, pallet, entry, keys=None):
        return {"pallet": pallet, "entry": entry, "keys": keys}

    def runtime_api(self, method, args=b"", return_type="Bytes"):
        return {"method": method, "args": args, "return_type": return_type}

    def constant(self, pallet, name):
        return 10**15

    def set_agent_key(self, value):
        """Change what the chain would now answer, as a re-scope or a revoke."""
        self._agent_key = value

    def submit(self, keypair, pallet, call, params, principal=None, finality_timeout=None):
        self.submitted.append((keypair, pallet, call, params, principal))
        self.finality_timeouts.append(finality_timeout)
        if self.submit_error is not None:
            raise self.submit_error
        return "receipt"

    def close(self):
        self.closed = True


def _properties(symbol="MTR-Test", genesis=TESTNET_GENESIS, declared=18, effective=18):
    return ChainProperties(
        genesis_hash=genesis,
        chain_name="MatterChain Testnet" if symbol != MAINNET_TOKEN_SYMBOL else "MatterChain",
        spec_version=308,
        token_symbol=symbol,
        ss58_prefix=42,
        token_decimals_declared=declared,
        token_decimals_effective=effective,
        existential_deposit=10 ** (effective - 3),
    )


def _client(properties=None, key=SEED_HEX, chain=None, **kwargs):
    from matter_sdk.chain import api_key_signer

    api_key = ApiKey(key) if key else None
    return MatterClient(
        chain or _FakeChain(),
        properties or _properties(),
        api_key=api_key,
        keypair=api_key_signer(api_key) if api_key else None,
        **kwargs,
    )


def test_amounts_round_trip_losslessly():
    for decimals in (0, 3, 12, 18):
        for plancks in (0, 1, 999, 10**decimals, 2**64):
            text = format_amount(plancks, decimals)
            assert parse_amount(text, decimals) == plancks, (decimals, plancks, text)


def test_amounts_reject_excess_precision_rather_than_truncating():
    assert parse_amount("0.001", 3) == 1
    with pytest.raises(ValueError, match="fractional digits"):
        parse_amount("0.0001", 3)


def test_amounts_reject_malformed_and_negative():
    for bad in ("", "  ", "-1", "abc", "1.2.3", "1,5", "1e9"):
        with pytest.raises(ValueError):
            parse_amount(bad, 12)


def test_client_amount_helpers_use_the_effective_decimals():
    client = _client(_properties(declared=18, effective=12))
    assert client.one_token() == 10**12
    assert client.parse_amount("1") == 10**12
    assert client.format_amount(10**12) == "1"


def test_the_decimals_discrepancy_is_a_factor_of_a_million():
    assert format_amount(10**15, 18) == "0.001"
    assert format_amount(10**15, 12) == "1000"


def test_decimals_derive_from_the_existential_deposit():
    assert _decimals_from_existential_deposit(10**15) == 18
    assert _decimals_from_existential_deposit(10**9) == 12
    assert _decimals_from_existential_deposit(1500) is None
    assert _decimals_from_existential_deposit(0) is None


def test_properties_detect_a_decimals_disagreement():
    assert not _properties(declared=18, effective=18).decimals_disagree
    assert _properties(declared=18, effective=12).decimals_disagree


def test_the_pinned_testnet_genesis_wins_over_the_token_symbol():
    is_mainnet, via = _properties(symbol=MAINNET_TOKEN_SYMBOL).is_mainnet()
    assert not is_mainnet
    assert via == "genesis-hash"


def test_an_unknown_chain_falls_back_to_the_token_symbol():
    unknown = "0x" + "ab" * 32
    assert _properties(symbol="MTR", genesis=unknown).is_mainnet() == (True, "token-symbol")
    assert _properties(symbol="MTR-Test", genesis=unknown).is_mainnet() == (False, "token-symbol")


def test_a_testnet_config_pointed_at_mainnet_is_rejected():
    mainnet = _properties(symbol="MTR", genesis="0x" + "ab" * 32)
    with pytest.raises(WrongNetworkError, match="expected the testnet network"):
        _client(mainnet, network=Network.TESTNET)


def test_a_signing_client_needs_confirmation_for_mainnet():
    mainnet = _properties(symbol="MTR", genesis="0x" + "ab" * 32)
    with pytest.raises(MainnetNotConfirmedError, match="without explicit confirmation"):
        _client(mainnet, network=Network.MAINNET)

    client = _client(mainnet, network=Network.MAINNET, confirm_mainnet=True)
    assert client.address is not None


def test_a_read_only_client_may_reach_mainnet_without_confirmation():
    mainnet = _properties(symbol="MTR", genesis="0x" + "ab" * 32)
    client = _client(mainnet, key=None, network=Network.MAINNET)
    assert client.account_id is None


def test_a_read_only_client_refuses_to_submit():
    client = _client(key=None)
    assert client.account_id is None
    assert client.address is None
    with pytest.raises(ReadOnlyError, match="read-only"):
        client.tx("Staking", "chill", {})
    with pytest.raises(ReadOnlyError, match="read-only"):
        client.signer()


def test_a_signing_client_reports_a_consistent_identity():
    client = _client()
    key = ApiKey(SEED_HEX)
    assert client.account_id == key.account_id
    assert client.address.startswith("5")
    auth = client.signer().authorize(1, [1], 1, b"\x00" * 32)
    assert auth["requester"] == key.account_id_hex


def test_the_generic_surface_forwards_to_the_chain():
    client = _client()
    assert client.query("System", "Account", ["addr"])["entry"] == "Account"
    assert client.runtime_api("KgcApi_dkg_epoch")["method"] == "KgcApi_dkg_epoch"
    assert client.constant("Balances", "ExistentialDeposit") == 10**15

    client.tx("Jobs", "request_deployment", {"request": 1})
    _keypair, pallet, call, params, principal = client.chain.submitted[0]
    assert (pallet, call, params) == ("Jobs", "request_deployment", {"request": 1})
    assert principal is None, "a client acting as itself wraps nothing"


def test_the_client_is_a_context_manager():
    client = _client()
    with client:
        pass
    assert client.chain.closed


def test_default_endpoints_replay_the_fixture():
    import json
    from pathlib import Path

    fixture = json.loads(
        (Path(__file__).resolve().parents[3] / "testvectors" / "networks.json").read_text()
    )
    assert fixture["default_rpc"]
    for row in fixture["default_rpc"]:
        assert Network.default_rpc_url(row["network"]) == row["url"], row["network"]


def test_custom_network_requires_an_explicit_url():
    with pytest.raises(ConfigError, match="requires an explicit rpc_url"):
        MatterClient._resolve_url(Network.CUSTOM, None)
    assert MatterClient._resolve_url(Network.CUSTOM, "ws://x") == "ws://x"
    assert MatterClient._resolve_url(Network.TESTNET, None).startswith("wss://")


PRINCIPAL = bytes(32 * [9])


def _delegated(scopes=None):
    """A client whose key the chain says acts for PRINCIPAL."""
    from matter_sdk.scopes import Access, Scope, ScopeSet

    scopes = scopes if scopes is not None else ScopeSet.single(Scope.DEPLOYMENTS, Access.WRITE)
    chain = _FakeChain(agent_key=(PRINCIPAL, scopes.bits))
    return _client(chain=chain), chain, scopes


def test_a_delegated_client_reports_who_it_acts_for():
    client, _chain, scopes = _delegated()
    assert client.is_delegated
    assert client.principal == PRINCIPAL
    assert client.scopes == scopes
    assert str(client.scopes) == "deployments:w"


def test_a_delegated_client_wraps_its_writes():
    client, chain, _scopes = _delegated()
    client.tx("Jobs", "cancel_deployment", {"deployment": 1})
    _keypair, pallet, call, _params, principal = chain.submitted[0]
    assert (pallet, call) == ("Jobs", "cancel_deployment")
    # ChainClient.submit does the wrapping; the client must pass the principal.
    assert principal == PRINCIPAL


def test_a_delegated_client_refuses_an_out_of_scope_call_before_submitting():
    from matter_sdk import NotPermittedError

    client, chain, _scopes = _delegated()
    with pytest.raises(NotPermittedError, match="volumes:w"):
        client.tx("Volumes", "retire_volume", {"volume_id": 1})
    assert chain.submitted == []


def test_a_delegated_client_refuses_calls_no_key_may_make():
    from matter_sdk import NotPermittedError
    from matter_sdk.scopes import ScopeSet

    client, chain, _scopes = _delegated(ScopeSet.all())
    for pallet, call in [
        ("Balances", "transfer_all"),
        ("Staking", "bond"),
        ("Sudo", "sudo"),
        ("Utility", "batch_all"),
        ("Proxy", "proxy"),
    ]:
        with pytest.raises(NotPermittedError, match="never admitted"):
            client.tx(pallet, call, {})
    assert chain.submitted == []


def test_a_delegated_client_reads_the_secret_ref_argument():
    from matter_sdk import NotPermittedError

    client, chain, _scopes = _delegated()
    client.tx("Jobs", "set_deployment_secret_ref", {"deployment": 1, "secret_ref": None})
    assert len(chain.submitted) == 1

    with pytest.raises(NotPermittedError):
        client.tx("Jobs", "set_deployment_secret_ref", {"deployment": 1, "secret_ref": 9})

    # An absent argument is unreadable, so it takes the wider requirement.
    with pytest.raises(NotPermittedError):
        client.tx("Jobs", "set_deployment_secret_ref", {"deployment": 1})
    assert len(chain.submitted) == 1


def test_a_client_acting_as_itself_is_not_scope_checked():
    client = _client()
    assert not client.is_delegated
    assert client.scopes is None
    client.tx("Balances", "transfer_all", {})
    assert len(client.chain.submitted) == 1


def test_a_failing_agent_key_lookup_fails_the_connect_rather_than_going_direct():
    chain = _FakeChain(agent_key_error=ChainError("ws closed", pallet="Budgets", call="agent_key"))
    with pytest.raises(ChainError):
        _client(chain=chain)


def test_an_unregistered_key_asks_the_chain_once_and_resolves_direct():
    chain = _FakeChain(agent_key=None)
    client = _client(chain=chain)
    assert not client.is_delegated
    assert chain.agent_key_calls == [bytes(client.account_id)]


def test_connect_diagnostics_go_to_a_logger_not_to_stderr(caplog):
    import logging

    chain = _FakeChain(agent_key=(bytes(range(32)), 0b0100))
    with caplog.at_level(logging.INFO, logger="matter_sdk.client"):
        client = _client(chain=chain)

    assert client.is_delegated
    messages = [r.getMessage() for r in caplog.records]
    assert any("acting for" in m for m in messages), messages
    assert any(client.principal_address in m for m in messages), messages


def test_a_revoked_key_is_named_as_revoked_and_stays_delegated():
    from matter_sdk.chain import PoolRejectedError

    principal = bytes(range(32))
    # secrets:w, so the call clears the local check.
    chain = _FakeChain(agent_key=(principal, 0b100000))
    client = _client(chain=chain)
    assert client.is_delegated

    chain.submit_error = PoolRejectedError("Inability to pay some fees", pallet="Secrets", call="store_secret")
    chain.set_agent_key(None)  # the member revoked it in the dashboard

    with pytest.raises(KeyRevokedError):
        client.tx("Secrets", "store_secret", {})
    assert client.is_delegated, "a revoked key must not quietly become a direct signer"


def test_a_rescoped_key_reports_the_missing_scope_with_the_fresh_set():
    from matter_sdk.chain import PoolRejectedError

    principal = bytes(range(32))
    # secrets:w, so the call clears the local check.
    chain = _FakeChain(agent_key=(principal, 0b100000))
    client = _client(chain=chain)

    chain.submit_error = PoolRejectedError("Inability to pay some fees", pallet="Secrets", call="store_secret")
    chain.set_agent_key((principal, 0b010000))  # narrowed to Secrets:Read

    with pytest.raises(NotPermittedError) as excinfo:
        client.tx("Secrets", "store_secret", {})
    assert "secrets:w" in str(excinfo.value)


def test_a_call_no_key_may_make_is_told_apart_from_a_missing_scope():
    from matter_sdk.client import NeverAdmittedError

    client = _client(chain=_FakeChain(agent_key=(bytes(range(32)), 0b100000)))

    with pytest.raises(NeverAdmittedError):
        client.tx("Balances", "transfer_all", {})
    with pytest.raises(NotPermittedError) as excinfo:
        client.tx("Volumes", "retire_volume", {})
    assert not isinstance(excinfo.value, NeverAdmittedError)


def test_a_write_carries_the_clients_finality_budget():
    chain = _FakeChain()
    client = _client(chain=chain, finality_timeout=5)
    client.tx("System", "remark", {"remark": "0x00"})
    assert chain.finality_timeouts == [5]


def test_the_default_finality_budget_is_two_minutes():
    chain = _FakeChain()
    _client(chain=chain).tx("System", "remark", {"remark": "0x00"})
    assert chain.finality_timeouts == [120]


def test_connecting_with_an_api_key_uses_the_chains_address_format(monkeypatch):
    from substrateinterface.utils.ss58 import ss58_encode

    import matter_sdk.client as client_module

    props = _properties()
    props.ss58_prefix = 0
    monkeypatch.setattr(client_module, "ChainClient", lambda url: _FakeChain())
    monkeypatch.setattr(MatterClient, "_read_properties", staticmethod(lambda chain: props))
    client = MatterClient.connect_with_api_key(SEED_HEX)
    assert client.address == ss58_encode(ApiKey(SEED_HEX).account_id, 0)
