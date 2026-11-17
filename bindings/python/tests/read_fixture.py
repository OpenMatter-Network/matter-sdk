"""``testvectors/facade_reads.json`` (emitted from Rust) and a chain that replays
one of its cases: the read catalogue, run through the real façades.

Imported by the test modules; not a test module itself.
"""

import json
from pathlib import Path

from scalecodec.base import RuntimeConfigurationObject, ScaleBytes
from scalecodec.type_registry import load_type_registry_preset
from substrateinterface.exceptions import SubstrateRequestException

from matter_sdk.chain import ChainClient
from matter_sdk.client import ChainProperties
from matter_sdk.facade import AccountsFacade, FeesFacade, NetworkFacade

_VECTORS = Path(__file__).resolve().parents[3] / "testvectors"

READ_FIXTURE = json.loads((_VECTORS / "facade_reads.json").read_text())

#: The façades that have reads, by fixture name.
READ_FACADES = {"accounts": AccountsFacade, "network": NetworkFacade, "fees": FeesFacade}

#: The finalized head a chain with no transcript reports.
FIXTURE_HEAD = "0x" + "f1" * 32
_FINALIZED_HEAD = "chain_getFinalizedHead"


def _spec330():
    """The spec-330 runtime's metadata (V14, the version substrate-interface
    decodes), loaded without a node."""
    config = RuntimeConfigurationObject()
    config.update_type_registry(load_type_registry_preset("core"))
    blob = (_VECTORS / "spec330_metadata_v14.scale").read_bytes()
    metadata = config.create_scale_object("MetadataVersioned", data=ScaleBytes(blob))
    metadata.decode()
    config.add_portable_registry(metadata)
    return config, metadata


_CONFIG, _METADATA = _spec330()


class FixtureSubstrate:
    """A substrate that replays one case's transcript.

    It holds the real spec-330 metadata, as a connected substrate does, and offers
    only ``rpc_request``: anything else the chain client reaches for (a helper
    that quietly makes its own requests, say) fails the test. It answers a request
    only as the transcript recorded that exact request, reports the case's block
    as its finalized head unless the transcript says otherwise, and records every
    request.
    """

    def __init__(self, case=None) -> None:
        self.runtime_config = _CONFIG
        self.metadata = _METADATA
        self.requests = []
        self._exchanges = case["exchanges"] if case else []
        self._head = "0x" + case["at"] if case else FIXTURE_HEAD

    def rpc_request(self, method, params):
        self.requests.append({"method": method, "params": params})
        for exchange in self._exchanges:
            if exchange["method"] == method and exchange["params"] == params:
                if "error" in exchange:
                    raise SubstrateRequestException(exchange["error"])
                return {"result": exchange["result"]}
        if method == _FINALIZED_HEAD:
            return {"result": self._head}
        raise SubstrateRequestException(
            f"the transcript has no answer for {method}({json.dumps(params)})"
        )


def fixture_chain(case=None) -> ChainClient:
    """The real :class:`ChainClient` over a :class:`FixtureSubstrate`, so its own
    request and storage-key code is what the façade runs on."""
    chain = ChainClient.__new__(ChainClient)
    chain.substrate = FixtureSubstrate(case)
    return chain


def fixture_properties() -> ChainProperties:
    """The chain facts the fixture's cases were emitted under."""
    facts = READ_FIXTURE["chain"]
    return ChainProperties(
        genesis_hash="0x" + "00" * 32,
        chain_name="MatterChain Fake",
        spec_version=330,
        token_symbol="MTR-Test",
        ss58_prefix=facts["ss58_prefix"],
        token_decimals_declared=18,
        token_decimals_effective=18,
        existential_deposit=int(facts["existential_deposit"]),
    )


def _account(hex_or_none):
    return None if hex_or_none is None else bytes.fromhex(hex_or_none)


class ReadingClient:
    """What a reading façade needs of ``MatterClient``; it refuses to submit.

    ``identity`` is a case's ``client``: who would sign, and for which member.
    Without one the client is read-only.
    """

    def __init__(self, chain: ChainClient, identity=None) -> None:
        self.chain = chain
        self.properties = fixture_properties()
        identity = identity or {}
        self.account_id = _account(identity.get("signer"))
        self.principal = _account(identity.get("principal"))

    def tx(self, pallet, call, params):
        raise AssertionError("a read must not submit an extrinsic")


def requests_of(case):
    """The requests a case's transcript records, in order."""
    return [{"method": e["method"], "params": e["params"]} for e in case["exchanges"]]


def args_of(row, args):
    """A case's arguments as a caller passes them, in the row's order. Wide
    integers travel as decimal strings in the fixture: JSON numbers cannot carry
    64 bits."""
    convert = {
        "account": lambda value: value,
        "string": lambda value: value,
        "u64": int,
        "u128": int,
        "call_args": _call_params,
    }
    return [convert[arg["type"]](args[arg["name"]]) for arg in row["args"]]


#: A call argument's fixture type to the value this binding's ``tx`` takes.
_CALL_ARG = {"u128": int}


def _call_params(call_args):
    """A call's arguments as ``tx`` takes them here: a dict by field name."""
    return {arg["name"]: _CALL_ARG[arg["type"]](arg["value"]) for arg in call_args}
