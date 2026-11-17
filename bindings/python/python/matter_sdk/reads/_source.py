"""Where a read's bytes come from. A domain module names its sources and holds a
pure decoder; :class:`Snapshot` is the only fetch, and it reads every source at
one block, so a result never mixes two.

``chain`` below is anything with ``_rpc(method, params)`` (one JSON-RPC request,
answered with its raw result), ``_runtime_call(api, args, at)`` (one runtime API
call at a block), and ``_storage_key(pallet, entry, keys)``,
``_constant_bytes(pallet, name)`` and ``_call_data(pallet, call, params,
principal)`` (all three from metadata already in hand):
:class:`~matter_sdk.chain.ChainClient`.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from ..hexutil import to_hex
from ._leaf import TEXT_PADDING, read_error, ss58_account

_FINALIZED_HEAD = "chain_getFinalizedHead"
_QUERY_STORAGE_AT = "state_queryStorageAt"
_HASH_BYTES = 32
_ACCOUNT_BYTES = 32
_HEX_PREFIX = "0x"
_NOT_AN_ACCOUNT = "account must be 32 bytes, as bytes, hex or an SS58 address"
_NOT_A_BLOCK_HASH = "a block hash is 32 bytes, as bytes or hex"
_WHOLE_BYTES_OF_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")
#: The types read as raw bytes. ``bytes(32)`` is 32 zero bytes, so anything
#: else must be refused rather than converted.
_BYTES_LIKE = (bytes, bytearray, memoryview)


@dataclass(frozen=True)
class StorageEntry:
    """A storage entry, as the runtime metadata spells it."""

    pallet: str
    entry: str

    @property
    def target(self) -> str:
        """``Pallet.Entry``: how errors and the read catalogue name this source."""
        return f"{self.pallet}.{self.entry}"


@dataclass(frozen=True)
class StorageRequest:
    """One storage value to fetch: an entry and its map keys (none for a plain
    value)."""

    entry: StorageEntry
    keys: Tuple[Any, ...] = ()


def _bytes_from_hex(text: str) -> Optional[bytes]:
    """Bytes from hex, with or without ``0x``; ``None`` unless it is whole bytes
    of hex."""
    body = text[len(_HEX_PREFIX) :] if text.startswith(_HEX_PREFIX) else text
    return bytes.fromhex(body) if _WHOLE_BYTES_OF_HEX.fullmatch(body) else None


def _raw_bytes(value: Any, from_text) -> Optional[bytes]:
    """``value`` as bytes when it is bytes-like, via ``from_text`` when it is a
    string, and ``None`` for anything else."""
    if isinstance(value, str):
        return from_text(value.strip(TEXT_PADDING))
    return bytes(value) if isinstance(value, _BYTES_LIKE) else None


def block_hash(block: Union[bytes, str]) -> bytes:
    """A block hash from bytes or hex. ``ValueError`` unless it is 32 bytes."""
    raw = _raw_bytes(block, _bytes_from_hex)
    if raw is None or len(raw) != _HASH_BYTES:
        raise ValueError(_NOT_A_BLOCK_HASH)
    return raw


def _account_from_text(text: str) -> Optional[bytes]:
    from_hex = _bytes_from_hex(text)
    if from_hex is not None and len(from_hex) == _ACCOUNT_BYTES:
        return from_hex
    return ss58_account(text)


def account_id_of(who: Union[bytes, str]) -> bytes:
    """An account from bytes or text: ``0x``-prefixed or bare 64-character hex, or
    an SS58 address under any network prefix, ignoring surrounding spaces, tabs
    and line breaks. ``ValueError`` unless ``who`` names exactly 32 bytes."""
    account = _raw_bytes(who, _account_from_text)
    if account is None or len(account) != _ACCOUNT_BYTES:
        raise ValueError(_NOT_AN_ACCOUNT)
    return account


def _answers(sets: Any) -> Dict[str, Any]:
    """Every ``key -> value`` a ``state_queryStorageAt`` answer carries."""
    try:
        return {key: value for change_set in sets for key, value in change_set["changes"]}
    except (TypeError, KeyError, ValueError) as exc:
        raise read_error(
            _QUERY_STORAGE_AT, "the node's answer is not a list of change sets"
        ) from exc


class Snapshot:
    """One block's state. Every source of a read goes through the same snapshot."""

    __slots__ = ("_chain", "_at")

    def __init__(self, chain, at: bytes) -> None:
        self._chain = chain
        self._at = at

    @property
    def at(self) -> bytes:
        """The block this snapshot reads at."""
        return self._at

    def request_here(self, method: str) -> Any:
        """One JSON-RPC request whose only parameter is this snapshot's block."""
        return self._chain._rpc(method, [to_hex(self._at)])

    def call(self, api: str, args: bytes) -> bytes:
        """Call the runtime API ``api`` (``Trait_method``) with SCALE-encoded
        ``args`` at this snapshot's block, returning its SCALE-encoded answer. A
        failure names the API, not the transport: that is what the caller asked
        for."""
        answer = self._chain._runtime_call(api, args, self._at)
        raw = _bytes_from_hex(answer) if isinstance(answer, str) else None
        if raw is None:
            raise read_error(api, "the node answered with something that is not hex")
        return raw

    def storage(self, requests: Sequence[StorageRequest]) -> List[Optional[bytes]]:
        """Fetch several storage values in one request. The result is in request
        order; ``None`` is a value the chain does not store."""
        keys = [
            to_hex(self._chain._storage_key(r.entry.pallet, r.entry.entry, list(r.keys)))
            for r in requests
        ]
        answers = _answers(self._chain._rpc(_QUERY_STORAGE_AT, [keys, to_hex(self._at)]))
        return [self._value(request, key, answers) for request, key in zip(requests, keys)]

    @staticmethod
    def _value(request: StorageRequest, key: str, answers: Dict[str, Any]) -> Optional[bytes]:
        if key not in answers:
            raise read_error(
                request.entry.target, f"the node's {_QUERY_STORAGE_AT} answer left this key out"
            )
        value = answers[key]
        if value is None:
            return None
        raw = _bytes_from_hex(value) if isinstance(value, str) else None
        if raw is None:
            raise read_error(request.entry.target, "the node answered with something that is not hex")
        return raw


def snapshot(chain, pin: Optional[bytes]) -> Snapshot:
    """Resolve ``pin`` to a block, asking the node only when it is not given."""
    if pin is not None:
        return Snapshot(chain, pin)
    head = chain._rpc(_FINALIZED_HEAD, [])
    raw = _bytes_from_hex(head) if isinstance(head, str) else None
    if raw is None or len(raw) != _HASH_BYTES:
        raise read_error(_FINALIZED_HEAD, "the node did not answer with a block hash")
    return Snapshot(chain, raw)
