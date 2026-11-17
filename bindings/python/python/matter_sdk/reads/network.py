"""Network reads: which chain this is, its blocks, its timing, and the health of
the node answering."""

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

from ..hexutil import to_hex
from ._leaf import read_error, wide
from ._scale import decode_strict
from ._source import StorageEntry, StorageRequest

GET_HEADER = "chain_getHeader"
GET_BLOCK_HASH = "chain_getBlockHash"
GET_RUNTIME_VERSION = "state_getRuntimeVersion"
SYSTEM_NAME = "system_name"
SYSTEM_VERSION = "system_version"
SYSTEM_HEALTH = "system_health"

_NOW = StorageEntry("Timestamp", "Now")

_BLOCK_TIME = ("Babe", "ExpectedBlockTime")
_SESSION_BLOCKS = ("Babe", "EpochDuration")
_SESSIONS_PER_ERA = ("Staking", "SessionsPerEra")
_BONDING_DURATION = ("Staking", "BondingDuration")

#: The constants a timing read needs, as ``(pallet, name)``, in the order
#: :func:`decode_timing` takes them.
TIMING_CONSTANTS: Tuple[Tuple[str, str], ...] = (
    _BLOCK_TIME,
    _SESSION_BLOCKS,
    _SESSIONS_PER_ERA,
    _BONDING_DURATION,
)

_HASH_BYTES = 32
_HASH_HEX = re.compile(r"(?:0x)?([0-9a-fA-F]{64})")
_HEX_NUMBER = re.compile(r"0x[0-9a-fA-F]+")
_U64_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class NetworkInfo:
    """Which chain this client is connected to, as read once at connect."""

    #: The chain's name, e.g. ``MatterChain Testnet``.
    chain_name: str
    #: Block 0's hash: what tells one chain from another.
    genesis_hash: str
    #: The runtime's version at connect.
    spec_version: int
    #: The token's symbol, e.g. ``MTR``.
    token_symbol: str
    #: Decimal places in one token: divide plancks by ten to this power.
    #: Consensus-backed, from the runtime rather than the node's chain spec.
    token_decimals: int
    #: The prefix addresses on this chain are rendered under.
    ss58_prefix: int
    #: The smallest balance an account may hold and stay alive, in plancks.
    existential_deposit: int = wide()


@dataclass(frozen=True)
class BlockHeader:
    """A block's place in the chain."""

    #: The block's height.
    number: int = wide()
    #: The block's hash: pass it to a façade's ``at`` to read at this block.
    hash: str
    #: The hash of the block before it.
    parent_hash: str


@dataclass(frozen=True)
class Block:
    """A block and what its state says about itself."""

    #: The block's height.
    number: int = wide()
    #: The block's hash: pass it to a façade's ``at`` to read at this block.
    hash: str
    #: The hash of the block before it.
    parent_hash: str
    #: When the block was authored, in milliseconds since the Unix epoch.
    #: ``None`` for a block that records no time (the genesis block).
    timestamp_ms: Optional[int] = wide()
    #: The runtime version that executed the block.
    spec_version: int


@dataclass(frozen=True)
class NodeStatus:
    """The node answering this client, and how far it has got."""

    #: The node software's name.
    name: str
    #: The node software's version.
    version: str
    #: How many peers the node is connected to.
    peers: int
    #: Whether the node is still catching up with the chain.
    is_syncing: bool
    #: Whether the node expects peers at all (a single dev node does not).
    should_have_peers: bool
    #: The newest block the node knows. It can still be reverted.
    best_number: int = wide()
    #: That block's hash.
    best_hash: str
    #: The newest block that can no longer be reverted.
    finalized_number: int = wide()
    #: That block's hash.
    finalized_hash: str


@dataclass(frozen=True)
class NetworkTiming:
    """How the chain measures time. Blocks and eras are the chain's own units;
    the SDK does not turn them into wall-clock estimates for you."""

    #: The target time between blocks, in milliseconds.
    block_time_ms: int = wide()
    #: Blocks in one session.
    session_blocks: int = wide()
    #: Sessions in one era.
    sessions_per_era: int
    #: Blocks in one era: ``session_blocks * sessions_per_era``.
    era_blocks: int = wide()
    #: Eras unbonded funds stay locked before they can be withdrawn.
    bonding_duration_eras: int


def _field(target: str, answer: Any, name: str, kind: type) -> Any:
    value = answer.get(name) if isinstance(answer, dict) else None
    # ``bool`` is an ``int`` in Python; a flag is not a count.
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise read_error(target, f"the node's answer has no {kind.__name__} {name}")
    return value


def hash_from_hex(target: str, text: Any) -> str:
    """A 32-byte hash from the hex a node answers with, as lowercase ``0x`` hex."""
    found = _HASH_HEX.fullmatch(text) if isinstance(text, str) else None
    if found is None:
        raise read_error(target, "the node did not answer with a block hash")
    return "0x" + found.group(1).lower()


def block_number_param(number: int) -> str:
    """A block number as ``chain_getBlockHash`` takes it: hex, so no width is
    lost."""
    return f"0x{number:x}"


def network_info(properties) -> NetworkInfo:
    """The chain's identity, from what the client read at connect."""
    return NetworkInfo(
        chain_name=properties.chain_name,
        genesis_hash=properties.genesis_hash,
        spec_version=properties.spec_version,
        token_symbol=properties.token_symbol,
        token_decimals=properties.token_decimals_effective,
        ss58_prefix=properties.ss58_prefix,
        existential_deposit=properties.existential_deposit,
    )


def decode_header(block_hash: bytes, header: Any) -> BlockHeader:
    """A header the node holds for ``block_hash``, or the error for one it does
    not."""
    if header is None:
        raise read_error(GET_HEADER, "the node does not have this block")
    number = _field(GET_HEADER, header, "number", str)
    if not _HEX_NUMBER.fullmatch(number):
        raise read_error(GET_HEADER, "the header's block number is not hex")
    return BlockHeader(
        number=int(number, 16),
        hash=to_hex(block_hash),
        parent_hash=hash_from_hex(GET_HEADER, _field(GET_HEADER, header, "parentHash", str)),
    )


def now_request() -> List[StorageRequest]:
    """The one storage value a block read needs."""
    return [StorageRequest(_NOW)]


def _narrow_ms(target: str, wide_ms: int) -> int:
    """``Timestamp.Now`` is declared 128 bits wide; milliseconds fit 64 with room
    for half a billion years, so anything wider is not a timestamp."""
    if wide_ms > _U64_MAX:
        raise read_error(target, f"{wide_ms} ms does not fit 64 bits")
    return wide_ms


def decode_block(header: BlockHeader, now: Optional[bytes], version: Any) -> Block:
    """Build a block from its header and what its state holds. Pure."""
    timestamp_ms = (
        None
        if now is None
        else _narrow_ms(_NOW.target, decode_strict(_NOW.target, now, lambda r: r.u128()))
    )
    return Block(
        number=header.number,
        hash=header.hash,
        parent_hash=header.parent_hash,
        timestamp_ms=timestamp_ms,
        spec_version=_field(GET_RUNTIME_VERSION, version, "specVersion", int),
    )


def node_status(
    name: Any, version: Any, health: Any, best: BlockHeader, finalized: BlockHeader
) -> NodeStatus:
    """Build the node's status from its own answers and the two headers. Pure."""
    if not isinstance(name, str):
        raise read_error(SYSTEM_NAME, "the node did not answer with text")
    if not isinstance(version, str):
        raise read_error(SYSTEM_VERSION, "the node did not answer with text")
    return NodeStatus(
        name=name,
        version=version,
        peers=_field(SYSTEM_HEALTH, health, "peers", int),
        is_syncing=_field(SYSTEM_HEALTH, health, "isSyncing", bool),
        should_have_peers=_field(SYSTEM_HEALTH, health, "shouldHavePeers", bool),
        best_number=best.number,
        best_hash=best.hash,
        finalized_number=finalized.number,
        finalized_hash=finalized.hash,
    )


def _target(constant: Tuple[str, str]) -> str:
    return f"{constant[0]}.{constant[1]}"


def decode_timing(constants: Sequence[bytes]) -> NetworkTiming:
    """Build the chain's timing from its constants' bytes, in
    :data:`TIMING_CONSTANTS` order. Pure."""
    block_time, session_blocks, sessions_per_era, bonding_duration = constants
    blocks = decode_strict(_target(_SESSION_BLOCKS), session_blocks, lambda r: r.u64())
    sessions = decode_strict(_target(_SESSIONS_PER_ERA), sessions_per_era, lambda r: r.u32())
    return NetworkTiming(
        block_time_ms=_narrow_ms(
            _target(_BLOCK_TIME),
            decode_strict(_target(_BLOCK_TIME), block_time, lambda r: r.u128()),
        ),
        session_blocks=blocks,
        sessions_per_era=sessions,
        era_blocks=min(blocks * sessions, _U64_MAX),
        bonding_duration_eras=decode_strict(
            _target(_BONDING_DURATION), bonding_duration, lambda r: r.u32()
        ),
    )
