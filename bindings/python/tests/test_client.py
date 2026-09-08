"""``MatterClient`` behaviour that does not need a chain.

The seam is narrow: everything above the JSON-RPC boundary is a pure function of
(metadata, rpc responses). These tests drive the client with a fake chain so the
guards, the amount arithmetic, and the read-only contract are covered offline —
the parts that must never regress, because getting them wrong spends real money.
"""

import pytest

pytest.importorskip("substrateinterface")

from matter_vault import ApiKey  # noqa: E402
from matter_vault.chain import ChainError  # noqa: E402
from matter_vault.client import (  # noqa: E402
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
        # Raised by submit(), so a failure path can be driven without a chain.
        self.submit_error = None
        self.closed = False
        # What ``BudgetsApi_agent_key`` would answer for this client's own key:
        # ``None`` is a chain that grants it no scoped proxy, which is what a
        # human seed or a pre-scoped-key runtime looks like.
        self._agent_key = agent_key
        # A lookup that *failed*, which is a third thing entirely: the chain was
        # never asked, so "no delegation" is not a fact yet.
        self._agent_key_error = agent_key_error
        self.agent_key_calls = []

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

    def submit(self, keypair, pallet, call, params, principal=None):
        self.submitted.append((keypair, pallet, call, params, principal))
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
    from matter_vault.chain import api_key_signer

    api_key = ApiKey(key) if key else None
    return MatterClient(
        chain or _FakeChain(),
        properties or _properties(),
        api_key=api_key,
        keypair=api_key_signer(api_key) if api_key else None,
        **kwargs,
    )


# --- the amount arithmetic ------------------------------------------------


def test_amounts_round_trip_losslessly():
    # A UI that displays a balance and submits it back must not change it.
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
    # Not the declared ones: that is the whole point of tracking both.
    client = _client(_properties(declared=18, effective=12))
    assert client.one_token() == 10**12
    assert client.parse_amount("1") == 10**12
    assert client.format_amount(10**12) == "1"


def test_the_decimals_discrepancy_is_a_factor_of_a_million():
    # matter-node changed UNIT from 10^12 to 10^18 with no storage migration.
    assert format_amount(10**15, 18) == "0.001"
    assert format_amount(10**15, 12) == "1000"


# --- the decimals derivation ---------------------------------------------


def test_decimals_derive_from_the_existential_deposit():
    assert _decimals_from_existential_deposit(10**15) == 18
    assert _decimals_from_existential_deposit(10**9) == 12
    # A non-power-of-ten ED means the policy changed; fall back rather than
    # reporting a confidently wrong exponent.
    assert _decimals_from_existential_deposit(1500) is None
    assert _decimals_from_existential_deposit(0) is None


def test_properties_detect_a_decimals_disagreement():
    assert not _properties(declared=18, effective=18).decimals_disagree
    assert _properties(declared=18, effective=12).decimals_disagree


# --- the network guards --------------------------------------------------


def test_the_pinned_testnet_genesis_wins_over_the_token_symbol():
    # Even with mainnet's symbol, a matching genesis hash means testnet.
    is_mainnet, via = _properties(symbol=MAINNET_TOKEN_SYMBOL).is_mainnet()
    assert not is_mainnet
    assert via == "genesis-hash"


def test_an_unknown_chain_falls_back_to_the_token_symbol():
    unknown = "0x" + "ab" * 32
    assert _properties(symbol="MTR", genesis=unknown).is_mainnet() == (True, "token-symbol")
    assert _properties(symbol="MTR-Test", genesis=unknown).is_mainnet() == (False, "token-symbol")


def test_a_testnet_config_pointed_at_mainnet_is_rejected():
    # A typo'd RPC URL must fail before it costs anything.
    mainnet = _properties(symbol="MTR", genesis="0x" + "ab" * 32)
    with pytest.raises(ChainError, match="expected the testnet network"):
        _client(mainnet, network=Network.TESTNET)


def test_a_signing_client_needs_confirmation_for_mainnet():
    mainnet = _properties(symbol="MTR", genesis="0x" + "ab" * 32)
    with pytest.raises(ChainError, match="without explicit confirmation"):
        _client(mainnet, network=Network.MAINNET)

    # Explicit opt-in is accepted.
    client = _client(mainnet, network=Network.MAINNET, confirm_mainnet=True)
    assert client.address is not None


def test_a_read_only_client_may_reach_mainnet_without_confirmation():
    # Reading cannot spend anything, so the guard does not apply.
    mainnet = _properties(symbol="MTR", genesis="0x" + "ab" * 32)
    client = _client(mainnet, key=None, network=Network.MAINNET)
    assert client.account_id is None


# --- the read-only contract ---------------------------------------------


def test_a_read_only_client_refuses_to_submit():
    client = _client(key=None)
    assert client.account_id is None
    assert client.address is None
    with pytest.raises(ChainError, match="read-only"):
        client.tx("Staking", "chill", {})
    with pytest.raises(ChainError, match="read-only"):
        client.signer()


def test_a_signing_client_reports_a_consistent_identity():
    client = _client()
    key = ApiKey(SEED_HEX)
    assert client.account_id == key.account_id
    assert client.address.startswith("5")
    # The committee signer must advertise the same account it submits as.
    auth = client.signer().authorize(1, [1], 1, b"\x00" * 32)
    assert auth["requester"] == key.account_id_hex


# --- the generic surface -------------------------------------------------


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


def test_custom_network_requires_an_explicit_url():
    with pytest.raises(ValueError, match="requires an explicit rpc_url"):
        MatterClient._resolve_url(Network.CUSTOM, None)
    assert MatterClient._resolve_url(Network.CUSTOM, "ws://x") == "ws://x"
    assert MatterClient._resolve_url(Network.TESTNET, None).startswith("wss://")


# --- delegated keys --------------------------------------------------------

PRINCIPAL = bytes(32 * [9])


def _delegated(scopes=None):
    """A client whose key the chain says acts for PRINCIPAL."""
    from matter_vault.scopes import Access, Scope, ScopeSet

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
    # The wrapping itself happens in ChainClient.submit; what matters here is
    # that the client hands it the principal to wrap for.
    assert principal == PRINCIPAL


def test_a_delegated_client_refuses_an_out_of_scope_call_before_submitting():
    from matter_vault import NotPermittedError

    client, chain, _scopes = _delegated()
    # Naming the missing scope is the whole point: the chain's own answer to a
    # balance-less key is a complaint about fees.
    with pytest.raises(NotPermittedError, match="volumes:w"):
        client.tx("Volumes", "retire_volume", {"volume_id": 1})
    assert chain.submitted == []


def test_a_delegated_client_refuses_calls_no_key_may_make():
    from matter_vault import NotPermittedError
    from matter_vault.scopes import ScopeSet

    client, chain, _scopes = _delegated(ScopeSet.all())
    for pallet, call in [
        ("Balances", "transfer_all"),
        ("Staking", "bond"),
        ("Sudo", "sudo"),
        # Nesting one of these would let a key launder authority through a batch.
        ("Utility", "batch_all"),
        ("Proxy", "proxy"),
    ]:
        with pytest.raises(NotPermittedError, match="never admitted"):
            client.tx(pallet, call, {})
    assert chain.submitted == []


def test_a_delegated_client_reads_the_secret_ref_argument():
    from matter_vault import NotPermittedError

    client, chain, _scopes = _delegated()
    # Clearing a reference needs only deployments:w.
    client.tx("Jobs", "set_deployment_secret_ref", {"deployment": 1, "secret_ref": None})
    assert len(chain.submitted) == 1

    # Setting one also needs secrets:r, which this key lacks.
    with pytest.raises(NotPermittedError):
        client.tx("Jobs", "set_deployment_secret_ref", {"deployment": 1, "secret_ref": 9})

    # An argument that is simply absent is unreadable, so it takes the wider
    # requirement rather than the convenient one.
    with pytest.raises(NotPermittedError):
        client.tx("Jobs", "set_deployment_secret_ref", {"deployment": 1})
    assert len(chain.submitted) == 1


def test_a_client_acting_as_itself_is_not_scope_checked():
    client = _client()
    assert not client.is_delegated
    assert client.scopes is None
    # A direct client is bounded by what its account can do on chain, not by a
    # scope set, so the local table must not gate it.
    client.tx("Balances", "transfer_all", {})
    assert len(client.chain.submitted) == 1


def test_a_failing_agent_key_lookup_fails_the_connect_rather_than_going_direct():
    # The failure mode this guards: a transient RPC error at connect resolves the
    # client to Direct, after which every write is signed as the key's own
    # balance-less account and dies in the pool as "cannot pay fees" — a message
    # that says nothing about the real cause. Unknown is not the same as absent.
    from matter_vault.chain import ChainError

    chain = _FakeChain(agent_key_error=ChainError("ws closed", pallet="Budgets", call="agent_key"))
    with pytest.raises(ChainError):
        _client(chain=chain)


def test_an_unregistered_key_asks_the_chain_once_and_resolves_direct():
    chain = _FakeChain(agent_key=None)
    client = _client(chain=chain)
    assert not client.is_delegated
    assert chain.agent_key_calls == [bytes(client.account_id)]


def test_connect_diagnostics_go_to_a_logger_not_to_stderr(caplog):
    # A library that writes to stderr decides for its host where its output
    # goes. This one asks: the record exists, and only an application that
    # configured logging will see it.
    import logging

    chain = _FakeChain(agent_key=(bytes(range(32)), 0b0100))
    with caplog.at_level(logging.INFO, logger="matter_vault.client"):
        client = _client(chain=chain)

    assert client.is_delegated
    messages = [r.getMessage() for r in caplog.records]
    assert any("acting for" in m for m in messages), messages
    # SS58, because that is the form the dashboard showed whoever minted the key.
    assert any(client.principal_address in m for m in messages), messages


def test_a_revoked_key_is_named_as_revoked_and_stays_delegated():
    # The failure this guards: a revoked key that fell back to signing directly
    # would fail the next call for want of funds it never had, and the caller
    # would read "cannot pay fees" instead of "your key was revoked".
    from matter_vault.chain import PoolRejectedError

    principal = bytes(range(32))
    # Secrets:Write, so the call clears the local check and reaches the chain.
    chain = _FakeChain(agent_key=(principal, 0b100000))
    client = _client(chain=chain)
    assert client.is_delegated

    chain.submit_error = PoolRejectedError("Inability to pay some fees", pallet="Secrets", call="store_secret")
    chain.set_agent_key(None)  # the member revoked it in the dashboard

    with pytest.raises(KeyRevokedError):
        client.tx("Secrets", "store_secret", {})
    assert client.is_delegated, "a revoked key must not quietly become a direct signer"


def test_a_rescoped_key_reports_the_missing_scope_with_the_fresh_set():
    from matter_vault.chain import PoolRejectedError

    principal = bytes(range(32))
    # Secrets:Write initially, so the call passes the local check.
    chain = _FakeChain(agent_key=(principal, 0b100000))
    client = _client(chain=chain)

    chain.submit_error = PoolRejectedError("Inability to pay some fees", pallet="Secrets", call="store_secret")
    chain.set_agent_key((principal, 0b010000))  # narrowed to Secrets:Read

    with pytest.raises(NotPermittedError) as excinfo:
        client.tx("Secrets", "store_secret", {})
    assert "secrets:w" in str(excinfo.value)


def test_a_call_no_key_may_make_is_told_apart_from_a_missing_scope():
    # Widening a key fixes one and can never fix the other, so a caller that
    # retries on a permissions error needs to know which it got.
    from matter_vault.client import NeverAdmittedError

    client = _client(chain=_FakeChain(agent_key=(bytes(range(32)), 0b100000)))

    with pytest.raises(NeverAdmittedError):
        client.tx("Balances", "transfer_all", {})
    with pytest.raises(NotPermittedError) as excinfo:
        client.tx("Volumes", "retire_volume", {})
    assert not isinstance(excinfo.value, NeverAdmittedError)
