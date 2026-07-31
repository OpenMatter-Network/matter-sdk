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
    MatterClient,
    Network,
    _decimals_from_existential_deposit,
    format_amount,
    parse_amount,
)

SEED_HEX = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"


class _FakeChain:
    """Enough of ``ChainClient`` to build a client and record submissions."""

    def __init__(self) -> None:
        self.submitted = []
        self.closed = False

    def query(self, pallet, entry, keys=None):
        return {"pallet": pallet, "entry": entry, "keys": keys}

    def runtime_api(self, method, args=b"", return_type="Bytes"):
        return {"method": method, "args": args, "return_type": return_type}

    def constant(self, pallet, name):
        return 10**15

    def submit(self, keypair, pallet, call, params):
        self.submitted.append((keypair, pallet, call, params))
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


def _client(properties=None, key=SEED_HEX, **kwargs):
    from matter_vault.chain import api_key_signer

    api_key = ApiKey(key) if key else None
    return MatterClient(
        _FakeChain(),
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
    _keypair, pallet, call, params = client.chain.submitted[0]
    assert (pallet, call, params) == ("Jobs", "request_deployment", {"request": 1})


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
