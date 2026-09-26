"""Submission is bounded: a write that does not finalize in time fails with
``FinalityTimeoutError`` instead of blocking forever."""

import pytest

pytest.importorskip("substrateinterface")

from matter_sdk import FinalityTimeoutError  # noqa: E402
from matter_sdk.chain import DEFAULT_FINALITY_TIMEOUT, ChainClient  # noqa: E402

SUBMITTED = "0xdeadbeef"


class _Clock:
    """A fake monotonic clock that only moves when the client sleeps."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _Extrinsic:
    data = SUBMITTED
    extrinsic_hash = bytes(32)


class _Account:
    value = {"nonce": 0}


class _Chain:
    """Finalized blocks that appear one per poll, each holding ``extrinsics``."""

    def __init__(self, blocks, start=100):
        # blocks: list of extrinsic lists, finalized one per poll after `start`.
        self._blocks = blocks
        self._start = start
        self._polls = 0
        self.submitted = []

    # --- the reads the finality watch makes
    def get_chain_finalised_head(self):
        # The first read is the head at submission; each later read finalizes one more.
        head = self._start + min(self._polls, len(self._blocks))
        self._polls += 1
        return f"head-{head}"

    def get_block_number(self, block_hash):
        return int(block_hash.split("-")[1])

    def get_block_hash(self, number):
        return f"0x{number:064x}"

    def rpc_request(self, method, params):
        assert method == "chain_getBlock"
        number = int(params[0], 16)
        return {"result": {"block": {"extrinsics": self._blocks[number - self._start - 1]}}}

    # --- what submit() needs before watching
    def get_metadata_call_function(self, pallet, call):
        return object()

    def compose_call(self, pallet, call, params):
        return (pallet, call)

    def query(self, pallet, entry, params):
        return _Account()

    def create_signed_extrinsic(self, call, keypair, nonce):
        return _Extrinsic()

    def submit_extrinsic(self, extrinsic, wait_for_inclusion=False, wait_for_finalization=False):
        assert not wait_for_finalization, "an unbounded watch cannot honour a deadline"
        self.submitted.append(extrinsic.data)


class _Keypair:
    ss58_address = "5Gr…"


def _client(blocks, clock) -> ChainClient:
    chain = ChainClient.__new__(ChainClient)
    chain.substrate = _Chain(blocks)
    chain._clock = clock
    chain._sleep = clock.sleep
    return chain


def test_the_default_budget_matches_the_other_languages():
    assert DEFAULT_FINALITY_TIMEOUT == 120


def test_finds_the_extrinsic_by_its_exact_bytes_in_a_later_finalized_block():
    clock = _Clock()
    chain = _client([["0x01"], ["0x02", SUBMITTED.upper().replace("0X", "0x")]], clock)
    block_hash, index = chain._await_finalized(SUBMITTED, 100, "Jobs.cancel_deployment", 60)
    assert (block_hash, index) == (f"0x{102:064x}", 1)


def test_a_write_that_never_finalizes_times_out_and_says_it_may_still_land():
    clock = _Clock()
    chain = _client([["0x01"], ["0x02"], ["0x03"]], clock)
    with pytest.raises(FinalityTimeoutError) as err:
        chain.submit(_Keypair(), "Jobs", "cancel_deployment", {"deployment": 1}, finality_timeout=30)
    assert chain.substrate.submitted == [SUBMITTED]
    assert (err.value.pallet, err.value.call) == ("Jobs", "cancel_deployment")
    assert "may still land" in str(err.value)
    assert clock.now >= 30
