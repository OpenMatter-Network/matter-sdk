"""Façade reads against ``testvectors/facade_reads.json`` (emitted from Rust):
every case replayed through the real façade, plus the primitives the decoders
stand on. A binding that disagrees with a vector has a bug."""

import dataclasses
import json
import typing

import pytest

pytest.importorskip("substrateinterface")

import matter_sdk  # noqa: E402
from matter_sdk import ChainError, canonical_json, to_json  # noqa: E402
from matter_sdk.reads import accounts as accounts_reads  # noqa: E402
from matter_sdk.reads import fees as fees_reads  # noqa: E402
from matter_sdk.reads._leaf import (  # noqa: E402
    _KIND,
    _Kind,
    ss58_account,
    ss58_address,
    text_from_bytes,
)
from matter_sdk.reads._scale import ScaleReader, decode_strict  # noqa: E402
from matter_sdk.reads._source import account_id_of, block_hash  # noqa: E402

from read_fixture import (  # noqa: E402
    FIXTURE_HEAD,
    READ_FACADES,
    READ_FIXTURE,
    ReadingClient,
    args_of,
    fixture_chain,
    requests_of,
)

ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

_PRIMITIVES = {
    "u8": lambda r: str(r.u8()),
    "u16": lambda r: str(r.u16()),
    "u32": lambda r: str(r.u32()),
    "u64": lambda r: str(r.u64()),
    "u128": lambda r: str(r.u128()),
    "bool": lambda r: str(r.boolean()).lower(),
    "compact_u32": lambda r: str(r.compact_u32()),
    "compact_u64": lambda r: str(r.compact_u64()),
    "compact_u128": lambda r: str(r.compact_u128()),
    "bytes": lambda r: "0x" + r.byte_string().hex(),
}


# --- the SCALE reader --------------------------------------------------------


@pytest.mark.parametrize(
    "row", READ_FIXTURE["scale"]["valid"], ids=lambda r: f"{r['type']}:{r['hex']}"
)
def test_the_reader_reads_each_primitive(row):
    raw = bytes.fromhex(row["hex"])
    assert decode_strict("test", raw, _PRIMITIVES[row["type"]]) == row["value"]


@pytest.mark.parametrize(
    "row", READ_FIXTURE["scale"]["invalid"], ids=lambda r: f"{r['type']}:{r['hex']}"
)
def test_the_reader_refuses_a_value_that_does_not_fit(row):
    with pytest.raises(ChainError) as caught:
        decode_strict("Some.Source", bytes.fromhex(row["hex"]), _PRIMITIVES[row["type"]])
    assert (caught.value.pallet, caught.value.call) == ("Some", "Source")


def test_options_and_sequences_read_in_wire_order():
    raw = bytes([0x00, 0x01, 0x07, 0x08, 0x01, 0x02])

    def read(reader: ScaleReader):
        return (
            reader.option(lambda r: r.u8()),
            reader.option(lambda r: r.u8()),
            reader.vec(lambda r: r.u8()),
        )

    assert decode_strict("test", raw, read) == (None, 7, [1, 2])


def test_an_option_tag_that_is_neither_none_nor_some_is_refused():
    with pytest.raises(ChainError):
        decode_strict("test", bytes([2]), lambda r: r.option(lambda i: i.u8()))


# --- accounts in and out -----------------------------------------------------


@pytest.mark.parametrize("row", READ_FIXTURE["accounts"]["accepted"], ids=lambda r: repr(r["text"]))
def test_every_accepted_account_form_names_the_same_account(row):
    assert account_id_of(row["text"]).hex() == row["account_hex"]


@pytest.mark.parametrize("text", READ_FIXTURE["accounts"]["refused"], ids=repr)
def test_text_that_is_not_an_account_is_refused(text):
    with pytest.raises(ValueError):
        account_id_of(text)


@pytest.mark.parametrize("who", [32, None, 1.5, ["a"], bytes(31), bytearray(33)], ids=repr)
def test_only_32_bytes_are_an_account(who):
    # ``bytes(32)`` is 32 zero bytes: converting would read the wrong account.
    with pytest.raises(ValueError):
        account_id_of(who)


def test_bytes_like_values_of_32_bytes_are_accounts():
    account = bytes.fromhex(READ_FIXTURE["accounts"]["accepted"][0]["account_hex"])
    for who in (account, bytearray(account), memoryview(account)):
        assert account_id_of(who) == account


@pytest.mark.parametrize(
    "row", READ_FIXTURE["accounts"]["addresses"], ids=lambda r: f"prefix {r['prefix']}"
)
def test_an_address_is_ss58_under_its_prefix_and_parses_back(row):
    account = bytes.fromhex(row["account_hex"])
    assert ss58_address(account, row["prefix"]) == row["address"]
    assert ss58_account(row["address"]) == account


def test_a_block_hash_is_32_bytes_as_bytes_or_hex():
    assert "0x" + block_hash(FIXTURE_HEAD).hex() == FIXTURE_HEAD
    assert "0x" + block_hash(f" {FIXTURE_HEAD[2:]}\n").hex() == FIXTURE_HEAD
    for bad in ("0x1234", bytes(31), 32, None):
        with pytest.raises(ValueError):
            block_hash(bad)


# --- the enum tables decoders carry ------------------------------------------


def _as_fixture_table(source, table):
    return {
        "source": source,
        "groups": [
            {
                "index": index,
                "pallet": pallet,
                "reasons": [{"index": i, "name": name} for i, name in reasons.items()],
            }
            for index, (pallet, reasons) in table.items()
        ],
    }


def test_the_enum_tables_are_the_ones_rust_checked_against_the_runtime():
    tables = READ_FIXTURE["tables"]
    hold, freeze = tables["hold_reasons"], tables["freeze_reasons"]
    assert _as_fixture_table(hold["source"], accounts_reads._HOLD_REASONS) == hold
    assert _as_fixture_table(freeze["source"], accounts_reads._FREEZE_REASONS) == freeze
    assert [r.value for r in accounts_reads._LOCK_REASONS] == tables["lock_reasons"]
    assert [c.value for c in fees_reads.DISPATCH_CLASSES] == tables["dispatch_classes"]


# --- canonical JSON ----------------------------------------------------------


def test_text_is_a_string_when_utf8_and_hex_when_not():
    assert text_from_bytes(b"prod-db") == "prod-db"
    assert text_from_bytes(b"\xff\x00\xfe") == b"\xff\x00\xfe"


def test_results_are_immutable():
    balance = accounts_reads.decode_balance(ALICE, 1, [None, None, None, None])
    with pytest.raises(dataclasses.FrozenInstanceError):
        balance.free = 1


def _element(hint):
    """The dataclass a field holds, through ``Tuple[T, ...]`` or ``Optional[T]``."""
    inner = [arg for arg in typing.get_args(hint) if arg is not Ellipsis and arg is not type(None)]
    return inner[0] if inner else hint


def _kind_problems(cls, shape, path):
    """Where a result dataclass's fields disagree with its row's ``shape``: a
    missing or extra field, or a JSON form the field's marker does not give."""
    fields = {field.name: field for field in dataclasses.fields(cls)}
    if set(fields) != set(shape):
        return [f"{path}: fields {sorted(fields)} are not the shape's {sorted(shape)}"]
    hints = typing.get_type_hints(cls)
    problems = []
    for name, sub in shape.items():
        token = sub[0] if isinstance(sub, list) else sub
        if isinstance(token, dict) and set(token) == {"?"}:
            token = token["?"]  # an object that may be null
        kind = fields[name].metadata.get(_KIND)
        if isinstance(token, dict):
            problems += _kind_problems(_element(hints[name]), token, f"{path}.{name}")
            continue
        wanted = {"u64": _Kind.WIDE, "u128": _Kind.WIDE, "text": _Kind.TEXT}.get(token.rstrip("?"))
        if kind is not wanted:
            problems.append(f"{path}.{name}: shape says {token}, the field is marked {kind}")
    return problems


@pytest.mark.parametrize(
    "row", READ_FIXTURE["reads"], ids=lambda r: f"{r['facade']}.{r['method']}"
)
def test_every_result_field_is_marked_with_the_json_form_its_shape_declares(row):
    # Python cannot tell a u32 from a u128 by type, so the marker is the contract.
    result_type = getattr(matter_sdk, row["result"])
    assert _kind_problems(result_type, row["shape"], row["result"]) == []
    # Declared order is the canonical key order.
    declared = [field.name for field in dataclasses.fields(result_type)]
    assert sorted(declared) == sorted(row["shape"])


# --- the shared vectors, through the real façade -----------------------------


def _cases():
    return [
        pytest.param(row, case, id=f"{row['facade']}.{row['method']}: {case['name']}")
        for row in READ_FIXTURE["reads"]
        for case in row["cases"]
    ]


def _call(row, case, chain, *, pinned: bool):
    facade = READ_FACADES[row["facade"]](ReadingClient(chain, case.get("client")))
    view = getattr(facade, READ_FIXTURE["pin_method"])("0x" + case["at"]) if pinned else facade
    method = getattr(view, row["method"], None)
    assert callable(method), f"{row['facade']}.{row['method']} is missing"
    return method(*args_of(row, case["args"]))


def _target_of(error: ChainError) -> str:
    """The source an error names, as the fixture spells it: ``Pallet.Entry`` for
    storage and constants, the bare method for an RPC or runtime API (which
    ``ChainError`` files under the method's own prefix)."""
    return error.call if "_" in error.call else f"{error.pallet}.{error.call}"


def _assert_outcome(row, case, chain, *, pinned: bool):
    """The read must end as the transcript says: these bytes, or this error."""
    if "error" in case:
        with pytest.raises(ChainError) as caught:
            _call(row, case, chain, pinned=pinned)
        assert _target_of(caught.value) == case["error"]["target"]
        return
    result = _call(row, case, chain, pinned=pinned)
    assert to_json(result) == case["expected"]
    assert canonical_json(result) == case["expected_json"]
    assert json.loads(canonical_json(result)) == case["expected"]


def test_a_read_that_asks_the_chain_has_a_second_returning_case_and_a_failing_one():
    assert READ_FIXTURE["reads"]
    for row in READ_FIXTURE["reads"]:
        name = f"{row['facade']}.{row['method']}"
        failing = [case for case in row["cases"] if "error" in case]
        returning = len(row["cases"]) - len(failing)
        assert returning >= 1, name
        if any(case["exchanges"] for case in row["cases"]):
            assert returning >= 2 and failing, name


@pytest.mark.parametrize("row, case", [c for c in _cases() if c.values[0]["pinnable"]])
def test_a_pinned_read_makes_exactly_the_recorded_requests(row, case):
    chain = fixture_chain(case)

    _assert_outcome(row, case, chain, pinned=True)

    # Nothing more: no head to resolve, and no request hidden in a helper.
    assert chain.substrate.requests == requests_of(case)


@pytest.mark.parametrize("row, case", _cases())
def test_an_unpinned_read_resolves_the_finalized_head_once(row, case):
    chain = fixture_chain(case)

    _assert_outcome(row, case, chain, pinned=False)

    # A read about one block asks for the finalized head once, then makes the
    # same requests at it; any other read asks exactly what was recorded. So
    # does a read refused before it asks anything: it never needs a block.
    refused_before_asking = "error" in case and not case["exchanges"]
    asks_for_the_head = row["pinnable"] and not refused_before_asking
    head = [{"method": "chain_getFinalizedHead", "params": []}] if asks_for_the_head else []
    assert chain.substrate.requests == head + requests_of(case)


def test_a_call_made_for_a_member_wraps_the_member_given_as_raw_bytes():
    # `submit` and the fee estimate share this wrap, and a client holds its
    # member as bytes. As bytes it used to fail inside the codec.
    member = bytes.fromhex(READ_FIXTURE["accounts"]["accepted"][0]["account_hex"])
    chain = fixture_chain()
    inner = chain._call_data("Staking", "chill", {})
    wrapped = chain._call_data("Staking", "chill", {}, principal=member)
    assert member in wrapped and wrapped.endswith(inner)
    assert chain.substrate.requests == []


# --- reads fail loudly -------------------------------------------------------


def _accounts_over(answer):
    """An accounts façade whose chain answers every request with ``answer``."""
    chain = fixture_chain()
    chain.substrate.rpc_request = lambda method, params: {"result": answer(method, params)}
    return READ_FACADES["accounts"](ReadingClient(chain)).at(FIXTURE_HEAD)


def test_a_node_that_leaves_a_key_out_of_its_answer_is_an_error():
    accounts = _accounts_over(lambda _method, params: [{"block": params[1], "changes": []}])
    with pytest.raises(ChainError) as caught:
        accounts.balance(ALICE)
    assert (caught.value.pallet, caught.value.call) == ("System", "Account")


def test_a_node_that_answers_with_something_that_is_not_hex_is_an_error():
    def garbled(_method, params):
        return [{"block": params[1], "changes": [[key, "not hex"] for key in params[0]]}]

    with pytest.raises(ChainError) as caught:
        _accounts_over(garbled).balance(ALICE)
    assert (caught.value.pallet, caught.value.call) == ("System", "Account")


@pytest.mark.parametrize("answer", [None, 7, [7], [{"block": "0x"}], [{"changes": [["k"]]}]], ids=repr)
def test_an_answer_that_is_not_a_list_of_change_sets_is_a_chain_error(answer):
    with pytest.raises(ChainError) as caught:
        _accounts_over(lambda _method, _params: answer).balance(ALICE)
    assert caught.value.call == "state_queryStorageAt"


def test_a_refused_request_is_a_chain_error_naming_the_method():
    accounts = READ_FACADES["accounts"](ReadingClient(fixture_chain()))
    with pytest.raises(ChainError) as caught:
        accounts.at(FIXTURE_HEAD).balance(ALICE)
    assert caught.value.call == "state_queryStorageAt"


def test_an_entry_the_runtime_does_not_have_is_a_chain_error_naming_it():
    with pytest.raises(ChainError) as caught:
        fixture_chain()._storage_key("System", "Accountt", [bytes(32)])
    assert (caught.value.pallet, caught.value.call) == ("System", "Accountt")
