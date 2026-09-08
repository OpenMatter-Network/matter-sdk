"""``ChainClient.agent_key``: how a runtime without scoped keys is told apart
from a runtime that has them and from a lookup that simply failed.

These sit a layer below ``test_client.py``'s ``_FakeChain``, which substitutes
``agent_key`` wholesale and so cannot exercise the method itself. The
distinction under test is the one that matters in production: "this chain has
no scoped keys" is a fact read from metadata, while "the node did not answer"
is not a fact at all and must not be mistaken for one.
"""

import pytest

pytest.importorskip("substrateinterface")

from scalecodec.base import RuntimeConfigurationObject  # noqa: E402
from scalecodec.type_registry import load_type_registry_preset  # noqa: E402
from substrateinterface.exceptions import SubstrateRequestException  # noqa: E402

from matter_vault.chain import ChainClient, ChainError  # noqa: E402

AGENT_KEY_PALLET = "Budgets"
AGENT_KEY_CALL = "authorize_agent_key"

PRINCIPAL = bytes(range(32))
KEY = bytes([9]) * 32


def _runtime_config():
    config = RuntimeConfigurationObject()
    config.update_type_registry(load_type_registry_preset("core"))
    return config


class _StubSubstrate:
    """Only what ``agent_key`` reads: the call table and one ``state_call``."""

    def __init__(self, *, has_call: bool, answer: bytes = b"", error: Exception = None):
        self._has_call = has_call
        self._answer = answer
        self._error = error
        self.runtime_config = _runtime_config()
        self.rpc_calls = []

    def get_metadata_call_function(self, pallet, call):
        # substrate-interface returns None for an absent call rather than raising.
        return object() if (self._has_call and (pallet, call) == (AGENT_KEY_PALLET, AGENT_KEY_CALL)) else None

    def rpc_request(self, method, params):
        self.rpc_calls.append((method, params))
        if self._error is not None:
            raise self._error
        return {"result": "0x" + self._answer.hex()}


def _chain(**kwargs):
    chain = ChainClient.__new__(ChainClient)
    chain.substrate = _StubSubstrate(**kwargs)
    return chain


def test_a_pre_322_runtime_is_detected_from_metadata_not_from_an_rpc_failure():
    # The call and the runtime API ship in the same runtime, so the call's
    # presence in metadata answers the question locally — no round trip, and no
    # inference from a failure that may have had nothing to do with the runtime.
    chain = _chain(has_call=False)
    assert chain.agent_key(KEY) is None
    assert chain.substrate.rpc_calls == [], "a pre-322 chain must not be asked"


def test_a_322_runtime_that_answers_none_resolves_to_no_delegation():
    chain = _chain(has_call=True, answer=bytes([0]))
    assert chain.agent_key(KEY) is None
    assert len(chain.substrate.rpc_calls) == 1


def test_a_registered_key_decodes_its_principal_and_scopes():
    # 37 bytes: the Option tag, the 32-byte principal, and the ScopeSet as a
    # bare little-endian u32. Pinned against the live testnet answer.
    scopes = 0x000FFFFF
    answer = bytes([1]) + PRINCIPAL + scopes.to_bytes(4, "little")
    assert chain_agent_key(answer) == (PRINCIPAL, scopes)


def chain_agent_key(answer):
    return _chain(has_call=True, answer=answer).agent_key(KEY)


def test_a_lookup_failure_on_a_322_runtime_is_an_error_not_a_silent_direct():
    chain = _chain(has_call=True, error=SubstrateRequestException("ws closed"))
    with pytest.raises(ChainError) as excinfo:
        chain.agent_key(KEY)
    assert excinfo.value.pallet == AGENT_KEY_PALLET


def test_a_malformed_answer_is_an_error_rather_than_no_delegation():
    # A truncated Some is a shape bug somewhere; reporting "not registered"
    # would turn it into a confusing fee rejection three calls later.
    with pytest.raises(Exception) as excinfo:
        chain_agent_key(bytes([1]) + PRINCIPAL[:16])
    assert not isinstance(excinfo.value, SystemExit)
