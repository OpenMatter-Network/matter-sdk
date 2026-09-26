"""``ChainClient`` reads against a stubbed substrate: absent storage, names the
runtime lacks, and the epoch-aware committee a decrypt needs."""

import pytest

pytest.importorskip("substrateinterface")

from scalecodec.base import RuntimeConfigurationObject  # noqa: E402
from scalecodec.type_registry import load_type_registry_preset  # noqa: E402
from substrateinterface.exceptions import (  # noqa: E402
    StorageFunctionNotFound,
    SubstrateRequestException,
)

from matter_sdk import ChainError, CommitteeNode, CommitteeState  # noqa: E402
from matter_sdk.chain import _CUSTOM_TYPES, ChainClient  # noqa: E402

FINALIZED = "0x" + "ab" * 32
EPOCH = 7


def _compact(n: int) -> bytes:
    if n < 1 << 6:
        return bytes([n << 2])
    if n < 1 << 14:
        return ((n << 2) | 1).to_bytes(2, "little")
    return ((n << 2) | 2).to_bytes(4, "little")


def _bytes(b: bytes) -> bytes:
    return _compact(len(b)) + b


def _u64(n: int) -> bytes:
    return n.to_bytes(8, "little")


def _vec(items) -> bytes:
    items = list(items)
    return _compact(len(items)) + b"".join(items)


def _some(b: bytes) -> bytes:
    return b"\x01" + b


NONE = b"\x00"


def _account(n: int) -> bytes:
    return bytes([n]) * 32


class _StorageResult:
    def __init__(self, value, found: bool) -> None:
        self.value = value
        self.meta_info = {"result_found": found}


class _StubSubstrate:
    """``state_call`` answers keyed by ``(method, args)``, plus the storage and
    metadata reads the generic surface makes."""

    def __init__(self, answers=None, storage=None, constants=None, calls=()):
        self.runtime_config = RuntimeConfigurationObject()
        self.runtime_config.update_type_registry(load_type_registry_preset("core"))
        self.runtime_config.update_type_registry_types(_CUSTOM_TYPES)
        self._answers = answers or {}
        self._storage = storage or {}
        self._constants = constants or {}
        self._calls = set(calls)
        self.composed = []

    def rpc_request(self, method, params):
        assert method == "state_call"
        name, args = params
        key = (name, bytes.fromhex(args[2:]))
        if key not in self._answers:
            raise SubstrateRequestException(f"Execution failed: {name} not found")
        return {"result": "0x" + self._answers[key].hex()}

    def query(self, pallet, entry, params):
        if (pallet, entry) not in self._storage:
            raise StorageFunctionNotFound(f'Storage function "{pallet}.{entry}" not found')
        return self._storage[(pallet, entry)]

    def get_constant(self, pallet, name):
        value = self._constants.get((pallet, name))
        return None if value is None else _StorageResult(value, True)

    def get_metadata_call_function(self, pallet, call):
        return object() if (pallet, call) in self._calls else None

    def compose_call(self, pallet, call, params):
        self.composed.append((pallet, call))
        raise AssertionError("an unknown call must be refused before composing")

    def get_chain_finalised_head(self):
        return FINALIZED


def _chain(**kwargs) -> ChainClient:
    chain = ChainClient.__new__(ChainClient)
    chain.substrate = _StubSubstrate(**kwargs)
    return chain


# --- storage reads -----------------------------------------------------------


def test_an_entry_that_is_not_stored_reads_as_none_not_its_default():
    # System.Account has a storage default; an unfunded account must still read
    # as absent, as it does in Rust and Go.
    default_account = {"nonce": 0, "data": {"free": 0}}
    chain = _chain(storage={("System", "Account"): _StorageResult(default_account, False)})
    assert chain.query("System", "Account", ["5Gr…"]) is None


def test_a_stored_zero_is_a_value_not_absence():
    chain = _chain(storage={("Secrets", "NextSecretId"): _StorageResult(0, True)})
    assert chain.query("Secrets", "NextSecretId") == 0


# --- names the runtime lacks -------------------------------------------------


def test_an_unknown_storage_entry_is_a_chain_error_naming_it():
    with pytest.raises(ChainError) as err:
        _chain().query("Secrets", "NextSecretIdd")
    assert (err.value.pallet, err.value.call) == ("Secrets", "NextSecretIdd")
    assert "Secrets.NextSecretIdd" in str(err.value)


def test_an_unknown_constant_is_a_chain_error_naming_it():
    with pytest.raises(ChainError) as err:
        _chain().constant("Balances", "ExistentialDepositt")
    assert (err.value.pallet, err.value.call) == ("Balances", "ExistentialDepositt")


def test_an_unknown_runtime_api_is_a_chain_error_naming_it():
    with pytest.raises(ChainError) as err:
        _chain().runtime_api("KgcApi_dkg_epochh", return_type="u32")
    assert err.value.call == "KgcApi_dkg_epochh"


def test_an_unknown_call_is_refused_before_anything_is_signed():
    chain = _chain()
    with pytest.raises(ChainError) as err:
        chain.submit(object(), "Jobs", "cancel_deploymnt", {"deployment": 1})
    assert (err.value.pallet, err.value.call) == ("Jobs", "cancel_deploymnt")
    assert chain.substrate.composed == []


# --- the committee at a secret's epoch ---------------------------------------


def _epoch_arg(epoch: int = EPOCH) -> bytes:
    return epoch.to_bytes(4, "little")


def _committee_answers(
    *,
    committee=((3, 30), (1, 10), (2, 20)),
    endpoints=None,
    commitments=None,
    threshold=2,
    output=_some(_bytes(b"joint-pk") + _bytes(b"shared-a-at-7")),
):
    endpoints = endpoints or {
        1: b"https://kgc1.example",
        2: b"https://kgc2.example/",
        3: b"https://kgc3.example",
    }
    commitments = commitments or {n: f"g{n}".encode() for n, _ in committee}
    answers = {
        ("KgcApi_dkg_output_at_epoch", _epoch_arg()): output,
        ("KgcApi_threshold_params_at_epoch", _epoch_arg()): _u64(len(committee)) + _u64(threshold),
        ("KgcApi_committee_at_epoch", _epoch_arg()): _vec(
            _account(n) + _u64(index) for n, index in committee
        ),
        ("KgcApi_kgc_nodes", b""): _vec(
            _account(n) + _bytes(endpoint) + _u64(0) for n, endpoint in endpoints.items()
        ),
    }
    for n, _ in committee:
        commitment = commitments.get(n)
        answers[("KgcApi_share_commitment", _epoch_arg() + _account(n))] = (
            NONE if commitment is None else _some(_bytes(commitment))
        )
    return answers


def test_committee_at_reads_that_epochs_state_not_the_current_one():
    state = _chain(answers=_committee_answers()).committee_at(EPOCH)
    assert isinstance(state, CommitteeState)
    assert state.epoch == EPOCH
    assert state.threshold == 2
    assert state.shared_a == b"shared-a-at-7"
    assert state.block_hash == bytes.fromhex(FINALIZED[2:])
    assert state.nodes == [
        CommitteeNode(index=10, endpoint="https://kgc1.example", share_commitment=b"g1"),
        CommitteeNode(index=20, endpoint="https://kgc2.example", share_commitment=b"g2"),
        CommitteeNode(index=30, endpoint="https://kgc3.example", share_commitment=b"g3"),
    ]


def test_committee_at_drops_a_member_without_an_absolute_http_endpoint():
    answers = _committee_answers(
        endpoints={1: b"https://kgc1.example", 2: b"kgc2.example", 3: b"https://kgc3.example"}
    )
    state = _chain(answers=answers).committee_at(EPOCH)
    assert [n.index for n in state.nodes] == [10, 30]


def test_committee_at_refuses_a_reachable_member_without_a_commitment():
    answers = _committee_answers(commitments={1: b"g1", 2: None, 3: b"g3"})
    with pytest.raises(ChainError, match="share commitment missing"):
        _chain(answers=answers).committee_at(EPOCH)


def test_committee_at_refuses_fewer_reachable_members_than_the_threshold():
    answers = _committee_answers(
        endpoints={1: b"https://kgc1.example", 2: b"", 3: b"ftp://kgc3.example"}
    )
    with pytest.raises(ChainError, match="need 2"):
        _chain(answers=answers).committee_at(EPOCH)


def test_committee_at_refuses_an_epoch_with_no_dkg_output():
    with pytest.raises(ChainError, match="no DKG output"):
        _chain(answers=_committee_answers(output=NONE)).committee_at(EPOCH)


def test_committee_at_refuses_an_epoch_with_no_seated_committee():
    with pytest.raises(ChainError, match="no committee"):
        _chain(answers=_committee_answers(committee=())).committee_at(EPOCH)
